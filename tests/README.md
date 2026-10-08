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

## Notes

- The fixture contains no labels or markers identifying the bugs — the skill must find them by analysis. Keep it that way when editing.
- When you add a vulnerability section to the skill, plant a matching finding in the fixture and add it to the manifest so coverage stays measurable.
- Generated reports in `security-reviews/` are test output; don't commit them.
