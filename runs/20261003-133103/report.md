# Demo Security Findings

These results come from an intentionally vulnerable localhost application.

Run status: **validated**

## Path traversal in /api/docs permits reading files outside docs root

- Verdict: **validated**
- Weakness: `CWE-22`
- Endpoint: `GET /api/docs`
- Claim: handleDocs joins the attacker-controlled `file` query parameter into a filesystem path with no sanitization and reads it without any containment check, allowing `../` traversal outside docsRoot to read arbitrary process-accessible files.

### Source evidence

- `server.js:128-130`: docsFilePath directly joins attacker-controlled name onto docsRoot with path.join and no normalization, filtering, or containment.
- `server.js:137-148`: handleDocs takes url.searchParams.get(file) into docsFilePath and fs.readFileSyncs the result, with no call to isWithinRoot and no traversal rejection; 404 only on read failure.
- `server.js:132-135`: isWithinRoot containment helper is defined but never invoked on the docs path, leaving the traversal check unenforced.

### Runtime evidence

2/2 fixed checks matched

## Reflected cross-site scripting in greeting via unescaped name parameter

- Verdict: **validated**
- Weakness: `CWE-79`
- Endpoint: `GET /greet`
- Claim: The `name` query parameter is taken directly from the URL and interpolated unescaped into an HTML response, allowing reflected JavaScript execution in the victim's browser.

### Source evidence

- `server.js:113-116`: greetName returns attacker-controlled URL query value `name` with no validation or escaping, defaulting only when missing
- `server.js:118-120`: renderGreeting interpolates `name` directly into HTML h1 element via template string with no escaping call
- `server.js:122-126`: handleGreet renders that value and returns it as text/html, completing reflected-XSS source-to-sink
- `server.js:108-111`: escapeHtml helper exists but is never called in this cluster, confirming missing output encoding

### Runtime evidence

2/2 fixed checks matched

## Broken Object Level Authorization via legacy client fallback allows cross-user invoice read

- Verdict: **validated**
- Weakness: `CWE-639`
- Endpoint: `GET /api/invoices/:id`
- Claim: Legacy policy bypasses per-object ownership check, allowing any authenticated user to read any other user's invoice

### Source evidence

- `server.js:17-20`: invoices have distinct owners: invoice-alice owned by alice and invoice-bob owned by bob
- `server.js:55-58`: isLegacyClient returns true when version header is missing (null) or major < 2
- `server.js:60-64`: policyForRequest selects legacy profile for legacy clients unless SECURE_MODE strict
- `server.js:66-69`: invoiceIsVisibleTo returns true for all invoices under legacy policy, skipping owner check
- `server.js:84-102`: handleInvoiceRead enforces visibility but permits read when legacy policy returns true
- `index.html:37-39`: UI confirms empty or below 2 selects legacy profile

### Runtime evidence

2/2 fixed checks matched

Every expected weakness was confirmed by its fixed checks.
