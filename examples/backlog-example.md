# Security Finding Backlog

This is a worked example of `security-reviews/backlog.md` after a team triaged a review. It corresponds to findings from `security-review-report-example.md` (abridged to representative rows — a real backlog has one row per finding).

How triage works: each review appends its findings with status `open`. Your team edits Status after reading the report. The next review reads this file and adapts — suppressed false-positives are counted in one line, risk-accepted items collapse to a one-line list unless their context changed.

Statuses: `open` | `confirmed` | `false-positive` | `risk-accepted` | `resolved`

| ID | Report | Location | Finding | Status | Notes |
|----|--------|----------|---------|--------|-------|
| SR-001 | security-review-2026-10-10-1041-vuln-app.md | src/server.js:33 | Unauthenticated command injection in /api/ping | resolved | Replaced exec with execFile + host allowlist (PR #412) |
| SR-002 | security-review-2026-10-10-1041-vuln-app.md | src/users.js:17 | SQL injection via sort parameter on /api/admin/users | resolved | Sort column allowlisted (PR #412) |
| SR-003 | security-review-2026-10-10-1041-vuln-app.md | src/auth.js:6 | Hardcoded JWT secret enables token forgery | resolved | Moved to env var; all tokens invalidated by rotation (PR #427) |
| SR-004 | security-review-2026-10-10-1041-vuln-app.md | src/graphql.js:14-21 | Unauthenticated GraphQL with BOLA exposes all orders | confirmed | Auth middleware + resolver ownership checks scheduled next sprint |
| SR-008 | security-review-2026-10-10-1041-vuln-app.md | src/users.js:10-13 | IDOR on /api/users/:id/orders | confirmed | Fix in review (PR #418) |
| SR-013 | security-review-2026-10-10-1041-vuln-app.md | src/payments.js:5-19 | Checkout accepts client-controlled total | confirmed | Server-side price computation spec'd (ticket SEC-44) |
| SR-015 | security-review-2026-10-10-1041-vuln-app.md | .env:1-4 | Committed .env with live secrets incl. Stripe live key | confirmed | Keys rotated; history purge + .gitignore pending (ticket SEC-31) |
| SR-023 | security-review-2026-10-10-1041-vuln-app.md | src/auth.js:43-47 | Account enumeration via differentiated login errors | risk-accepted | Internal beta only; revisit before public launch (ticket SEC-40) |
| SR-025 | security-review-2026-10-10-1041-vuln-app.md | src/server.js:22 | Open redirect on /login?next= | risk-accepted | Marketing page renders no user content in production |
| SR-027 | security-review-2026-10-10-1041-vuln-app.md | src/auth.js:32-34 | node-serialize deserialization RCE (dead code) | confirmed | Delete with node-serialize removal (pairs with SR-039) |
| SR-031 | (example) | src/legacy/report.js:88 | "XSS" in PDF export template | false-positive | Template renders server-generated labels only; no user input reaches the sink |
| SR-034 | security-review-2026-10-10-1041-vuln-app.md | src/server.js:16 | 50 MB JSON body limit enables memory DoS | false-positive | Behind platform rate limiting and internal-only today; revisit if exposure changes |

## What the next review does with this file

- **SR-001, SR-002, SR-003** — verified fixed in code → drop from the delta as Resolved (code actually changed).
- **SR-023, SR-025** — risk-accepted and unchanged → collapse into the one-line "Previously risk-accepted" list; re-escalate only if context changed (public launch, new exposure).
- **SR-031, SR-034** — false-positives at unchanged code → suppressed; stated as a count, not re-reported.
- **SR-004, SR-008, SR-013, SR-015, SR-027** — confirmed / open → normal reporting with fresh locations and a "Persisted" line each in Since Last Review.
