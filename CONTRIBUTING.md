# Contributing

The skills are MIT-licensed — you're free to use, copy, and modify them inside
your organization, including commercially, with no obligation to share your
changes.

**A request, not a requirement:** if your changes are generally useful — new
vulnerability coverage, better remediation patterns, fewer false positives,
improved report structure — please contribute them back upstream via a pull
request to [github.com/natolitech/security-skill](https://github.com/natolitech/security-skill)
so every user benefits.

## How to Contribute a Skill Change

1. **Edit the skill** — `.claude/commands/security-review.md` or
   `.claude/commands/threat-model.md`. Keep instructions concrete and
   analytical; avoid report boilerplate (see CLAUDE.md's "When Editing the
   Skills").

2. **Plant a matching finding if you added coverage** — when adding a
   vulnerability section to the skill, add a corresponding planted finding to
   `tests/fixtures/vuln-app/` and record it in `tests/EXPECTED-FINDINGS.md`
   so coverage stays measurable.

3. **Run the regression corpus** — from the repo root in Claude Code:

   ```
   /security-review Review the application in tests/fixtures/vuln-app/
   ```

   Then smoke-check the generated report:

   ```bash
   ./tests/score-report.sh security-reviews/security-review-<stamp>.md
   ```

   Acceptance criteria are in [tests/README.md](tests/README.md) — ≥ 90% of
   planted findings, no control-case false positives, secrets redacted.
   Don't commit the generated report.

4. **Bump the version** — update the `<!-- skill: ... | version: N.N.N -->`
   header and add a changelog entry at the bottom of the skill file.

5. **Open a pull request** describing what the change catches that the
   previous version didn't.

## Repo Hygiene

- Markdown must pass `markdownlint-cli2` and shell scripts must pass
  `shellcheck` (CI runs both — see `.github/workflows/lint.yml`).
- Generated reports in `security-reviews/` are test output; don't commit them.
- `tests/fixtures/vuln-app/` is intentionally vulnerable and must never be
  built, run, or deployed.
