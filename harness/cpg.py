"""Static call-graph (mini-CPG) stage backed by tree-sitter.

Parses collected JavaScript sources into function nodes plus call edges so
the model reasons over program structure as well as text. Only calls inside
named functions are graphed; module-level statements are left out.

The ``cpg.json`` artifact is the interchange contract: a Joern exporter could
replace this tree-sitter backend without changing the controller, the prompt
shape, or the runners. The stage degrades gracefully when tree-sitter is not
installed (:func:`build_call_graph` returns ``None``).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

MAX_EDGES = 500

_FUNCTION_QUERY = """
(function_declaration
  name: (identifier) @name
  body: (_) @body)
(variable_declarator
  name: (identifier) @name
  value: [(arrow_function) (function_expression)] @body)
(pair
  key: (property_identifier) @name
  value: [(arrow_function) (function_expression)] @body)
"""

_CALL_QUERY = """
(call_expression
  function: (identifier) @callee)
(call_expression
  function: (member_expression
    object: (identifier) @object
    property: (property_identifier) @property))
"""


def available() -> bool:
    """True when the tree-sitter backend can be imported."""
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_javascript  # noqa: F401
    except ImportError:
        return False
    return True


def _node_text(node: Any, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _function_start_line(name_node: Any) -> int:
    node = name_node.parent
    if node is not None and node.parent is not None:
        if node.parent.type == "variable_declaration":
            node = node.parent
    if node is None:
        node = name_node
    return node.start_point[0] + 1


def _callees_in_body(call_query: Any, body_node: Any, source: bytes) -> list[str]:
    callees = []
    for _, captures in call_query.matches(body_node):
        if "callee" in captures:
            for callee_node in captures["callee"]:
                callees.append(_node_text(callee_node, source))
        else:
            objects = captures.get("object", [])
            properties = captures.get("property", [])
            for obj, prop in zip(objects, properties):
                callees.append(
                    f"{_node_text(obj, source)}.{_node_text(prop, source)}"
                )
    return callees


def build_call_graph(sources: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Parse collected ``.js`` sources into nodes plus call edges.

    Returns ``None`` when the tree-sitter backend is not installed.
    """
    if not available():
        logger.debug("tree-sitter backend missing; skipping call graph")
        return None

    from tree_sitter import Language, Parser
    import tree_sitter_javascript as ts_javascript

    language = Language(ts_javascript.language())
    parser = Parser(language)
    function_query = language.query(_FUNCTION_QUERY)
    call_query = language.query(_CALL_QUERY)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str]] = set()
    truncated = False

    for source in sources:
        path = source["path"]
        if not path.endswith(".js"):
            continue
        raw = source["text"].encode("utf-8")
        tree = parser.parse(raw)

        functions: list[tuple[str, str, Any]] = []
        for _, captures in function_query.matches(tree.root_node):
            names = captures.get("name", [])
            bodies = captures.get("body", [])
            for name_node, body_node in zip(names, bodies):
                name = _node_text(name_node, raw)
                node_id = f"{path}#{name}"
                functions.append((name, node_id, body_node))
                nodes.append(
                    {
                        "id": node_id,
                        "kind": "function",
                        "name": name,
                        "path": path,
                        "line_start": _function_start_line(name_node),
                        "line_end": body_node.end_point[0] + 1,
                    }
                )

        defined = {name for name, _, _ in functions}
        for name, node_id, body_node in functions:
            for callee in _callees_in_body(call_query, body_node, raw):
                key = (node_id, callee)
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                if len(edges) >= MAX_EDGES:
                    truncated = True
                    break
                resolved = callee in defined
                edges.append(
                    {
                        "src": node_id,
                        "dst": f"{path}#{callee}" if resolved else f"external:{callee}",
                        "dst_name": callee,
                        "kind": "calls",
                        "resolved": resolved,
                    }
                )
            if truncated:
                break

    return {
        "backend": "tree-sitter",
        "nodes": nodes,
        "edges": edges,
        "truncated": truncated,
    }


def render_call_graph_text(cpg: dict[str, Any]) -> str:
    """Render the graph compactly for the discovery prompt."""
    nodes = cpg.get("nodes", [])
    edges = cpg.get("edges", [])
    lines = [
        f"CALL GRAPH ({cpg.get('backend', 'unknown')}: "
        f"{len(nodes)} functions, {len(edges)} edges)"
    ]
    lines.append("Functions (name path:start-end):")
    for node in nodes:
        lines.append(
            f"- {node['name']} {node['path']}:{node['line_start']}-{node['line_end']}"
        )
    lines.append("Calls (caller -> callee):")
    for edge in edges:
        caller = edge["src"].split("#", 1)[1]
        marker = "" if edge.get("resolved") else " (external)"
        lines.append(f"- {caller} -> {edge['dst_name']}{marker}")
    if cpg.get("truncated"):
        lines.append(f"(edge list truncated at {MAX_EDGES})")
    return "\n".join(lines)


MIN_CLUSTER_FUNCTIONS = 3


def _cluster_record(
    name: str, members: set[str], graph: dict[str, Any], root: str
) -> dict[str, Any]:
    by_name = {node["name"]: node for node in graph.get("nodes", [])}
    edges = []
    for edge in graph.get("edges", []):
        caller = edge["src"].split("#", 1)[1]
        if caller not in members:
            continue
        if edge.get("resolved") and edge["dst_name"] not in members:
            record = dict(edge)
            record["cross_cluster"] = True
            edges.append(record)
        else:
            edges.append(edge)
    return {
        "name": name,
        "entry": name if name in members else root,
        "functions": sorted(members),
        "nodes": [by_name[item] for item in sorted(members)],
        "edges": edges,
    }


def cluster_call_graph(
    graph: dict[str, Any], *, root: str = "route"
) -> list[dict[str, Any]]:
    """Partition functions into one cluster per feature handler.

    Each cluster holds a direct callee of ``root`` plus its transitive
    resolved callees. Handlers with fewer than ``MIN_CLUSTER_FUNCTIONS``
    functions merge into the shared cluster alongside the dispatcher
    itself. Falls back to a single cluster when the root is absent.
    """
    nodes = {node["name"]: node for node in graph.get("nodes", [])}
    callees: dict[str, list[str]] = {}
    for edge in graph.get("edges", []):
        if not edge.get("resolved"):
            continue
        caller = edge["src"].split("#", 1)[1]
        callees.setdefault(caller, []).append(edge["dst_name"])

    if root not in nodes:
        return [_cluster_record("all", set(nodes), graph, root)]

    clusters = []
    covered: set[str] = set()
    for handler in sorted(set(callees.get(root, []))):
        members: set[str] = set()
        stack = [handler]
        while stack:
            name = stack.pop()
            if name in members or name not in nodes:
                continue
            members.add(name)
            stack.extend(callees.get(name, []))
        if len(members) < MIN_CLUSTER_FUNCTIONS:
            continue
        covered |= members
        clusters.append(_cluster_record(handler, members, graph, root))
    shared = set(nodes) - covered
    if shared:
        clusters.append(_cluster_record("shared", shared, graph, root))
    return clusters


def render_cluster_text(
    cluster: dict[str, Any], *, index: int, total: int
) -> str:
    """Render one cluster's subgraph for its focused reasoning call."""
    lines = [f"CLUSTER {cluster['name']} ({index} of {total}): functions in scope"]
    for node in cluster["nodes"]:
        lines.append(
            f"- {node['name']} {node['path']}:{node['line_start']}-{node['line_end']}"
        )
    lines.append("Calls in this cluster (caller -> callee):")
    for edge in cluster["edges"]:
        caller = edge["src"].split("#", 1)[1]
        if edge.get("cross_cluster"):
            marker = " (another cluster)"
        else:
            marker = "" if edge.get("resolved") else " (external)"
        lines.append(f"- {caller} -> {edge['dst_name']}{marker}")
    lines.append(
        "Focus your findings on this cluster; other clusters are analyzed "
        "separately. Evidence may cite any numbered source lines."
    )
    return "\n".join(lines)
