# Documentation Improvement Plan

**Created:** 2026-10-10
**Status:** Complete — all phases delivered (2026-10-10); D3 deliberately skipped (docs/ index not warranted at current size)
**Owner:** Security engineering
**Input:** Full docs review of README, INSTALL, CLAUDE.md, examples/, tests/README, CONTRIBUTING, docs/IMPROVEMENT-PLAN.md, reference specs, and the two skill files

The skill content (v2.1.0) is well-covered by docs. The gaps are structural (missing standard repo docs), consistency (cross-references and staleness), and freshness (no v2.1.0-era examples). Four phases, ordered by value.

---

## Phase A — Fill structural gaps (new files)

- [x] **A1 Repo CHANGELOG.md** — Keep-a-Changelog format, seeded from the skill-file changelogs, `git log`, and the v2.1.0 release notes. The repo now has tagged releases; consumers copy files permanently (INSTALL Method 1) and need a single place to answer "what changed since my copy?"
- [x] **A2 SECURITY.md** — Reporting policy for vulnerabilities in the skill itself (GitHub private security advisories), the fixture's never-run warning, and a note that reports about reviewed *applications* are out of scope. A security project without a disclosure path undermines its own message.
- [x] **A3 Remote-review example** — Commit the genuine v2.1.0 NodeGoat report (currently uncommitted test output in `security-reviews/`) as `examples/security-review-remote-example.md`, with a walkthrough of the URL→clone→commit-pin→slug flow and the cross-target notes. Real output, not mocked; includes the shallow-clone caveat.
- [x] **A4 Versioning policy** — Define semver for prompt-file skills in CONTRIBUTING: **major** = behavior/output-contract change (report format, RoE), **minor** = new coverage or capability (remote targets), **patch** = fixes/wording. Also states that both skills version independently.

## Phase B — Consistency fixes (edits)

- [x] **B1 README "What's Included"** — add rows for `LICENSE` and `docs/IMPROVEMENT-PLAN.md`; add a documentation map (one table: which doc answers which question).
- [x] **B2 README "Limitations" section** — state plainly: not a SAST/SCA/secret-scanner replacement (recommend real scanners), LLM review can miss findings and produce false positives, shallow remote clones have no history, regression corpus is one stack. Trust comes from honest bounds; the skill already does this internally.
- [x] **B3 INSTALL.md** — add a short "License & Contributing" section (links LICENSE, CONTRIBUTING; restates the non-binding request); verify ToC anchors cover it.
- [x] **B4 Reference spec banners** — one-line status banner atop `AGENT.md`, `threat.md`, `compliance.md`, `code.md`: archived reference spec; live skills are `.claude/commands/*.md`. Prevents newcomers acting on the old multi-agent specs.
- [x] **B5 IMPROVEMENT-PLAN "Future work"** — consolidate the scattered post-plan ideas into one section: VF-27 open-redirect guidance hardening, remediation-as-comment fixture decoy, additional corpora adoption (tests/README table), SARIF export option, threat-model remote example.

## Phase C — Freshness

- [x] **C1 Refresh examples at next regression cycle** — when a v2.1.0+ corpus run happens anyway, regenerate the fixture examples and update examples/README version labels. Until then, add one line noting v2.1.0's remote flow is documented via the new remote example (A3).
- [x] **C2 Coverage-list audit habit** — when a vulnerability section is added to a skill, check README's "What the Security Review Covers" list in the same PR (add to CONTRIBUTING checklist in A4).

## Phase D — Polish (optional)

- [x] **D1 Badges** — CI lint status, MIT license, latest release tag on README.
- [x] **D2 GitHub metadata** — repo description + topics (security, claude, code-review, threat-modeling, owasp).
- [ ] **D3 docs/ index** — only if docs/ grows past a handful of files; not warranted yet.

---

## Sequencing

A3 and B5 are highest-value per effort (real v2.1.0 artifact + stops idea loss). A1/A2 are standard repo hygiene and cheap. B-phase is mechanical. C1 is deferred by design. D is optional.

## Constraint

Docs must stay truthful to behavior: every claim should be checkable against the skill files or a saved report. No aspirational sections.
