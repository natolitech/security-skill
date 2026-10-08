# Security Skill Improvement Plan

**Created:** 2026-10-08
**Status:** Complete — all phases delivered (2026-10-08)
**Owner:** Security engineering

This plan upgrades the distributable security skills (`.claude/commands/security-review.md` and `.claude/commands/threat-model.md`) across four phases: safety/correctness fixes, coverage expansion, workflow integration, and engineering rigor for the repo itself.

---

## Phase 1 — Safety & Correctness Fixes

Fixes an active operational risk and quality gaps introduced when the multi-agent specs were condensed into single skills.

- [x] **1.1 Secret redaction rule** — When finding evidence contains a secret (API key, password, token), the report must show only first/last 4 characters plus a rotation reminder. The current format instructs Claude to quote vulnerable code verbatim — which copies hardcoded secrets into a committed report file.
- [x] **1.2 Safe-execution constraints** — Add an explicit rules section: the review is static analysis only. Do not run the application, install or execute scanners, make outbound network requests, or modify code. Limits blast radius from prompt injection in reviewed code.
- [x] **1.3 Finding IDs + confidence ratings** — Stable IDs (`SR-001`, `TM-001`) and confidence levels (Confirmed / Likely / Suspected) on every finding. IDs were present in the original `code.md` spec (F1/F2) and dropped in translation; they make findings referenceable across runs and PRs, confidence aids triage.
- [x] **1.4 Report filename collisions** — `security-review-YYYY-MM-DD.md` silently overwrites on same-day reruns. Add time (`HHMM`) or scope slug to the filename.
- [x] **1.5 Verification pass** — Add a final step before reporting: for each finding, confirm the mitigation isn't implemented elsewhere (middleware, framework defaults, upstream validation) and downgrade or drop accordingly. Directly targets the false-positive problem anticipated in INSTALL.md.

## Phase 2 — Coverage Expansion

- [x] **2.1 Add missing vulnerability sections** to `/security-review`:
  - CSRF (token validation, SameSite-only reliance, state-changing GETs) — currently only referenced in the severity table with no analysis guidance
  - File upload handling (content-type validation vs. magic bytes, size limits, storage location, SVG-XSS, executable upload)
  - GraphQL/API-specific (field-level authorization, introspection in production, BOLA, batching/aliasing abuse)
  - Business logic abuse (negative quantities, price tampering, coupon/reward reuse)
  - Frontend-specific (postMessage handlers without origin checks, tokens in localStorage, production source maps)
  - Containers/IaC depth (privileged containers, host mounts, secrets in Terraform state, overly public security groups)
  - LLM-application security (indirect prompt injection, tool/agent authorization, SSRF via URL-fetching agents)
- [x] **2.2 Reframe dependency & secret scanning honestly** — An LLM reading a lockfile is not real SCA. Instruct the skill to flag outdated/EOL packages as informational and emit recommended scanner commands (`osv-scanner`, `gitleaks`) rather than implying CVE knowledge it doesn't reliably have.
- [x] **2.3 Threat model upgrades**:
  - Mermaid data-flow diagram (present in original `threat.md` spec, dropped in translation)
  - Privacy/retention threats (LINDDUN-lite: data minimization, retention, consent) — GDPR-relevant
  - Kill-chain / attack-path detail for the top 2–3 risks only (keeps the "prioritize" rule intact)

## Phase 3 — Workflow Integration

Repeat-use value for teams that adopt the skills as a process, not a one-off.

- [x] **3.1 Delta reporting** — When a prior report exists in `security-reviews/`, produce a "new / resolved / persisted since last review" section instead of a cold-start report.
- [x] **3.2 Cross-skill integration** — `/security-review` reads the latest threat model (if present) and prioritizes its high-risk components; `/threat-model` reads prior review findings.
- [x] **3.3 Triage state** — Lightweight `security-reviews/backlog.md` where findings get marked confirmed / false-positive / risk-accepted. The next review reads it and suppresses known-accepted items (avoiding alert fatigue).
- [x] **3.4 Machine-readable summary** — `findings.json` (or SARIF) alongside the markdown report, keyed on the stable finding IDs from 1.3.

## Phase 4 — Engineering Rigor (the repo itself)

- [x] **4.1 Vulnerable fixture corpus** — `tests/fixtures/vuln-app/` with planted, known findings + an expected-findings manifest. CLAUDE.md already calls for testing "against a project with known vulnerabilities" — this builds it. Highest-leverage investment: makes skill edits regression-testable.
- [x] **4.2 Version headers** — Each command gets a `<!-- skill-version: N.N -->` header plus changelog section, so copy-installed consumers (INSTALL.md Method 1 — permanently pinned files) can tell what they're running.
- [x] **4.3 Ship the installer** — INSTALL.md Method 4 shows an inline script; add the actual `install.sh` to the repo. Also sync README (doesn't mention the `security-reviews/` output directory) and add a markdown-lint CI check.

---

## Sequencing

1. Phase 1 (fixes active operational risk — ~small effort)
2. Phase 2.1–2.2 (the security substance)
3. Phase 4.1 (fixture corpus, so Phase 2 changes can be regression-tested)
4. Phase 2.3, then Phase 3, then remaining Phase 4

## Constraint

Per CLAUDE.md: keep instructions concrete and analytical; avoid adding report boilerplate; do not add compliance framework mapping to security-review (stays in threat-model's regulatory section); test changes by running `/security-review` against a real project with known vulnerabilities (see 4.1).
