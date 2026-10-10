# Security Policy

## Reporting a Vulnerability in This Project

If you find a security vulnerability in the **skills themselves** — for example, an instruction in `.claude/commands/*.md` that causes reviewed code to be executed, secrets to be exposed in reports, or prompt-injection defenses that can be bypassed — please report it privately:

- Open a **GitHub Security Advisory** on this repository (Report a vulnerability), or
- Use GitHub's private vulnerability reporting for [github.com/natolitech/security-skill](https://github.com/natolitech/security-skill).

Please do **not** open a public issue for skill vulnerabilities. Include the skill name and version header (the `<!-- skill: … | version: … -->` line) and, where possible, a minimal reproduction of the misbehavior.

## Scope Notes

- **Applications reviewed by the skills are out of scope here.** Vulnerabilities in code you analyzed *with* these skills belong to that code's own security process — not this repo.
- **The regression fixture is intentionally vulnerable.** `tests/fixtures/vuln-app/` contains planted, documented vulnerabilities (see `tests/EXPECTED-FINDINGS.md`). Reports against the fixture are not accepted. **Never build, run, or deploy it.**
- **Example outputs contain redacted secrets only.** If you find an unredacted planted secret in any example or report, treat it as a reportable issue in this project.

## What to Expect

- Acknowledgment within a few days.
- Fixes ship as skill version bumps (see the per-file changelogs) with credit in the changelog unless you prefer otherwise.
- Releases are tagged; direct-copy consumers (INSTALL.md Method 1) must re-copy to receive fixes — the advisory will state which skill versions are affected.
