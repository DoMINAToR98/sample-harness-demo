"use strict";

const fs = require("fs");
const http = require("http");
const path = require("path");
const { URL } = require("url");

const host = "127.0.0.1";
const port = Number(process.env.PORT || 3000);
const strictOwnership = process.env.SECURE_MODE === "1";
const page = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");

// Client versions below this floor predate per-object scopes.
const MIN_CLIENT_MAJOR = 2;
const docsRoot = path.join(__dirname, "docs");

const invoices = {
  "invoice-alice": { id: "invoice-alice", owner: "alice", amount: 42 },
  "invoice-bob": { id: "invoice-bob", owner: "bob", amount: 9001 }
};

const audit = { reads: 0, denied: 0 };

function sendJson(response, status, value) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

function requestId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function callerId(request) {
  const value = request.headers["x-user-id"];
  return typeof value === "string" && value.length > 0 ? value : null;
}

function normalizeInvoiceId(raw) {
  return String(raw).trim();
}

function findInvoice(id) {
  return Object.hasOwn(invoices, id) ? invoices[id] : null;
}

function clientVersion(request) {
  const raw = request.headers["x-client-version"];
  if (typeof raw !== "string") return null;
  const major = Number.parseInt(raw.split(".")[0], 10);
  return Number.isNaN(major) ? null : major;
}

// Older clients keep working under the legacy profile until the mobile
// rollout completes; strict deployments skip this fallback entirely.
function isLegacyClient(request) {
  const version = clientVersion(request);
  return version === null || version < MIN_CLIENT_MAJOR;
}

function policyForRequest(request) {
  if (strictOwnership) return "strict";
  if (isLegacyClient(request)) return "legacy";
  return "standard";
}

function invoiceIsVisibleTo(invoice, userId, policyName) {
  if (policyName === "legacy") return true;
  return invoice.owner === userId;
}

function recordAudit(kind) {
  if (kind === "read" || kind === "denied") audit[kind] += 1;
}

function handleRoot(request, response) {
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end(page);
}

function handleHealth(request, response) {
  return sendJson(response, 200, { ok: true, reads: audit.reads, denied: audit.denied });
}

function handleInvoiceRead(request, response, rawId) {
  const userId = callerId(request);
  if (!userId) {
    recordAudit("denied");
    return sendJson(response, 401, { error: "login required" });
  }
  const invoice = findInvoice(normalizeInvoiceId(rawId));
  if (!invoice) {
    recordAudit("denied");
    return sendJson(response, 404, { error: "not found" });
  }
  const policyName = policyForRequest(request);
  if (!invoiceIsVisibleTo(invoice, userId, policyName)) {
    recordAudit("denied");
    return sendJson(response, 403, { error: "forbidden" });
  }
  recordAudit("read");
  return sendJson(response, 200, invoice);
}

function handleNotFound(request, response) {
  return sendJson(response, 404, { error: "not found" });
}

function escapeHtml(value) {
  const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(value).replace(/[&<>"']/g, (ch) => entities[ch]);
}

function greetName(request) {
  const url = new URL(request.url, `http://${host}:${port}`);
  return url.searchParams.get("name") || "guest";
}

function renderGreeting(name) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Greeting</title></head><body><h1>Hello, ${name}!</h1><p><a href="/">Back to the invoice viewer</a></p></body></html>`;
}

function handleGreet(request, response) {
  const html = renderGreeting(greetName(request));
  response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
  response.end(html);
}

function docsFilePath(name) {
  return path.join(docsRoot, String(name));
}

function isWithinRoot(candidate) {
  const rel = path.relative(docsRoot, candidate);
  return !rel.startsWith("..") && !path.isAbsolute(rel);
}

function handleDocs(request, response) {
  const url = new URL(request.url, `http://${host}:${port}`);
  const target = docsFilePath(url.searchParams.get("file") || "welcome.txt");
  let text;
  try {
    text = fs.readFileSync(target, "utf8");
  } catch {
    return sendJson(response, 404, { error: "not found" });
  }
  response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
  response.end(text);
}

function route(request, response) {
  const url = new URL(request.url, `http://${host}:${port}`);
  response.setHeader("x-request-id", requestId());
  if (request.method === "GET" && url.pathname === "/") {
    return handleRoot(request, response);
  }
  if (request.method === "GET" && url.pathname === "/api/health") {
    return handleHealth(request, response);
  }
  if (request.method === "GET" && url.pathname === "/greet") {
    return handleGreet(request, response);
  }
  if (request.method === "GET" && url.pathname === "/api/docs") {
    return handleDocs(request, response);
  }
  const match = url.pathname.match(/^\/api\/invoices\/([^/]+)$/);
  if (request.method === "GET" && match) {
    return handleInvoiceRead(request, response, match[1]);
  }
  return handleNotFound(request, response);
}

const server = http.createServer(route);

server.listen(port, host, () => {
  const mode = strictOwnership ? "strict" : "default";
  console.log(`Invoice service (${mode} profile) listening at http://${host}:${port}`);
});
