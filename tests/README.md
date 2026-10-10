# Regression Testing the Security Skills

The corpus in `fixtures/vuln-app/` is an intentionally vulnerable application (ShopLite) used to regression-test changes to `.claude/commands/security-review.md`. `EXPECTED-FINDINGS.md` is the answer key: 36 planted findings across every skill section, 4 control cases that must not be flagged, and 4 secret literals that must be redacted.

> **Never build, run, or deploy the fixture.** It exists only to be read. The skill's Rules of Engagement already forbid executing reviewed code.

## Procedure

1. **Run the skill** from this repo's root in Claude Code:

   ```
   /security-review Review the application in tests/fixtures/vuln-app/
   ```

   The report is saved to `security-reviews/security-review-<date>-<time>.md`.

2. **Smoke-check the report:**

   ```bash
   ./tests/score-report.sh security-reviews/security-review-<stamp>.md
   ```

   Fails hard if any planted secret appears verbatim, and reports keyword coverage of the expected findings (threshold 75%).

3. **Manual review** against `EXPECTED-FINDINGS.md` — the smoke check cannot judge severity, false positives on control cases, or finding quality.

## Acceptance Criteria for a Skill Change

| Criterion | Bar |
|-----------|-----|
| Planted findings found | ≥ 90% of VF-01…VF-36, severity within one band of expected |
| Control cases C1–C4 | Not reported as vulnerabilities (Informational notes acceptable) |
| Redaction | No planted secret literal verbatim; first/last 4 chars max, rotation stated |
| Format | Finding IDs (`SR-NNN`) and confidence ratings present |

## Recorded Baselines

| Date | Run | Result |
|------|-----|--------|
| 2026-10-08 | Fresh-session review (no fixture knowledge), skill v2.0.0 | **35/36 planted findings (97.2%)**, 0/4 control false-positives, redaction PASS. Miss: VF-27 open redirect on `/login?next=`. Band deviations: VF-03/VF-09 downgraded with correct dead-code justification (verification pass working as designed); VF-10 JWT algorithm pinning folded into a Low finding; VF-34 DEBUG rated Informational. Bonus legitimate findings: missing security headers, no lockfile, 50 MB body limit, 30-day JWTs. |
| 2026-10-10 | Fresh-session review, skill v2.1.0 | **36/36 planted findings (100%)**, 0/4 control false-positives, redaction PASS, scorer 100% keyword coverage. Contamination note: reviewer had read `tests/README.md` (which names VF-27's location) but not `EXPECTED-FINDINGS.md` or the fixture source before reviewing — treat VF-27 as confirmed-with-prior-hint. Band deviations: VF-03 Critical→Medium and VF-09 High→Medium (dead-code verification, no caller — consistent with the v2.0.0 baseline's treatment); VF-10 High→Medium, VF-15 High→Critical (unauth mass-data justification), VF-20 High→Medium, VF-28/VF-32 Medium→High. Bonus legitimate findings: unhandled token-verify throw on `/api/profile`, AI tool-result logging, GraphQL cost controls, Terraform unpinned, inbox-to-OpenAI privacy note. |

Notes for future skill work: open redirect on query-parameter redirects is a known miss — check the Open Redirect guidance if regressing. The keyword scorer counted VF-27 as covered via unrelated "redirect" mentions in SSRF/CSRF findings; always confirm misses manually. Remediation-as-comment (seen throughout the NodeGoat corpus) is a pattern the skill already handles correctly — it reports the live code path, not the commented fix — and is a candidate decoy style for the fixture: plant a correct fix in comments next to a live vulnerable line and confirm the skill doesn't credit the comment as a mitigation.

## Potential Additional Corpora

The fixture covers one stack (Node/Express/Postgres). Candidates for broader regression coverage — usable directly with the remote-repo feature (`/security-review <url>`) — ranked by fit:

| Corpus | Stack | Why |
|--------|-------|-----|
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) | Node/Express/MongoDB | Same ecosystem as the fixture, different DB and auth patterns; OWASP-maintained with documented per-exercise solutions |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | Node/TypeScript/Angular | Largest challenge set (~100+), modern frontend — good for frontend-section coverage; scope to `routes/` + `frontend/src/app/` per run, it's big |
| [OWASP WebGoat](https://github.com/WebGoat/WebGoat) | Java/Spring | Covers the Java/Spring guidance the fixture can't exercise |
| [RailsGoat](https://github.com/OWASP/railsgoat) | Ruby on Rails | Rails-specific ORM/authz patterns (strong params, Devise, CanCan) |
| [OWASP Benchmark](https://github.com/OWASP/Benchmark) | Java | Designed for scored SAST precision/recall — only if we want quantitative metrics; findings are per-test-case, not app-realistic |
| [DVWA](https://github.com/digininja/DVWA) | PHP/MySQL | Legacy-stack coverage; low priority unless PHP usage matters |

Ground rules if adopted: read-only analysis (RoE still forbids running them), build an `EXPECTED-FINDINGS.md` equivalent from the project's own documentation before first run, and score severity bands the same way.

## Notes

- The fixture contains no labels or markers identifying the bugs — the skill must find them by analysis. Keep it that way when editing.
- When you add a vulnerability section to the skill, plant a matching finding in the fixture and add it to the manifest so coverage stays measurable.
- Generated reports in `security-reviews/` are test output; don't commit them.
