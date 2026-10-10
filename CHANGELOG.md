# Changelog

All notable changes to this project are documented here. The two distributable skills (`.claude/commands/security-review.md` and `.claude/commands/threat-model.md`) carry their own per-file changelogs and version independently; this file tracks the repo as a whole. Dates are YYYY-MM-DD.

## [2.1.0] — 2026-10-10

### Added

- **Remote repository targets** for both skills: a git URL passed as the review/model target is shallow-cloned (`--depth 1`, `--branch <ref>` if named) into a temp directory outside the invoking project and analyzed in place. Reports are pinned to URL + commit hash and saved with a repo-name scope slug. Rules of Engagement gained narrow carve-outs (the clone is the single permitted network operation; clone writes never touch the project). Delta comparison is restricted to prior reports of the same target; the triage backlog is not applied or updated for remote targets. Shallow-clone history limits are stated in-report; clone failures stop the run.
- **MIT license** (`LICENSE`) with a non-binding contribution request (`CONTRIBUTING.md`). Skill headers now carry `license: MIT` so the grant travels with copied files.
- Regression baseline for skill v2.1.0 recorded in `tests/README.md`: 36/36 planted findings, 0/4 control false-positives, redaction PASS.
- Ranked list of candidate additional regression corpora in `tests/README.md`.
- `docs/DOCS-IMPROVEMENT-PLAN.md` (documentation review and plan).

### Changed

- Documentation updated throughout for the remote-review feature (README, INSTALL usage/scoping/troubleshooting, CLAUDE.md, examples).

## [2.0.0] — 2026-10-08

### Added

- Rules of Engagement for both skills: static, read-only analysis; reviewed code treated as untrusted data (planted prompt injection is a finding, not an instruction).
- Stable finding IDs (`SR-NNN`, `TM-NNN`) and confidence ratings (Confirmed / Likely / Suspected).
- Secret redaction in report evidence (first/last 4 characters, rotation reminder).
- Verification pass before reporting: hunt for mitigations, re-trace data flows, downgrade or refute accordingly.
- Seven vulnerability analysis sections: CSRF, GraphQL/API-specific, frontend, containers/IaC, file upload, business logic abuse, LLM-application security.
- Honest dependency and secret-scanning framing: flag staleness statically, recommend `osv-scanner`/`gitleaks` rather than implying CVE knowledge.
- Threat model upgrades: mermaid data-flow diagram with numbered boundary crossings (B1, B2, …), privacy & data-protection pass, attack paths (kill chains) for top risks, "verify before rating" rule.
- Delta reporting: "Since Last Review" (New / Resolved / Persisted) against prior reports.
- Cross-skill integration: security-review reads the latest threat model for prioritization; threat-model reads prior review findings as evidence.
- Triage backlog (`security-reviews/backlog.md`): human decisions persist across runs; known false-positives suppressed, risk-accepted items collapsed.
- Machine-readable `findings-*.json` index alongside each report.
- Timestamped report filenames with scope slugs (same-day reruns no longer overwrite).
- Regression corpus (`tests/fixtures/vuln-app/`), expected-findings manifest, and `score-report.sh`.
- Skill version headers and per-file changelogs; `install.sh`; markdownlint + shellcheck CI; real end-to-end examples with walkthroughs.

## [1.1.0] — 2026-03-05

### Added

- Skills save their reports to a `security-reviews/` directory in the invoking project.

## [1.0.0] — 2026-03-05

### Added

- Initial release: `security-review` and `threat-model` skills for Claude Code.
