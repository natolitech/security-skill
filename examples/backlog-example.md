# Security Finding Backlog

This is a worked example of `security-reviews/backlog.md` after a team triaged a review. It corresponds to findings from `security-review-report-example.md` (abridged to representative rows — a real backlog has one row per finding).

How triage works: each review appends its findings with status `open`. Your team edits Status after reading the report. The next review reads this file and adapts — suppressed false-positives are counted in one line, risk-accepted items collapse to a one-line list unless their context changed.

Statuses: `open` | `confirmed` | `false-positive` | `risk-accepted` | `resolved`

| ID | Report | Location | Finding | Status | Notes |
|----|--------|----------|---------|--------|-------|
| SR-001 | security-review-2026-10-08-0942-vuln-app.md | src/server.js:33 | Unauthenticated command injection in /api/ping | resolved | Replaced exec with execFile + host allowlist (PR #412) |
| SR-002 | security-review-2026-10-08-0942-vuln-app.md | src/users.js:15-18 | Unauthenticated SQL injection via sort parameter | resolved | Sort column allowlisted (PR #412) |
| SR-003 | security-review-2026-10-08-0942-vuln-app.md | src/graphql.js:21 | GraphQL: no auth, BOLA, GraphiQL enabled | confirmed | Scheduled next sprint — auth middleware + resolver checks |
| SR-004 | security-review-2026-10-08-0942-vuln-app.md | .env, src/auth.js:6, src/ai.js:6 | Secrets committed to git and baked into image | confirmed | Keys rotated; history purge + .gitignore pending (ticket SEC-31) |
| SR-006 | security-review-2026-10-08-0942-vuln-app.md | src/users.js:10-13 | IDOR on /api/users/:id/orders | confirmed | Fix in review (PR #418) |
| SR-009 | security-review-2026-10-08-0942-vuln-app.md | public/app.js:11-13 | Stored XSS via profile bio innerHTML | confirmed | |
| SR-013 | security-review-2026-10-08-0942-vuln-app.md | src/payments.js:5-20 | Client-supplied order total trusted | confirmed | |
| SR-022 | security-review-2026-10-08-0942-vuln-app.md | src/auth.js:43-47 | Login enumeration + no rate limiting | risk-accepted | Internal beta only; revisit before public launch (ticket SEC-40) |
| SR-028 | security-review-2026-10-08-0942-vuln-app.md | src/server.js:40-42 | Reflected XSS in /welcome | risk-accepted | Marketing page renders no user content in production |
| SR-031 | (example) | src/legacy/report.js:88 | "XSS" in PDF export template | false-positive | Template renders server-generated labels only; no user input reaches the sink |

What the next review does with each status:

- **resolved** — dropped from the delta unless the same flaw reappears (then flagged as a regression with the original ID)
- **confirmed** — expected to persist; appears under "Persisted" in the Since Last Review section until fixed
- **risk-accepted** — collapsed to one line ("Previously risk-accepted: SR-022, SR-028") unless context changed — e.g., if `/welcome` started rendering user content, SR-028 would be re-reported and re-escalated with a note
- **false-positive** — suppressed entirely at unchanged code; the report states how many known false-positives were suppressed
