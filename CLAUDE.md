# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a **distributable application security review skill** for Claude Code. Engineers copy the `.claude/commands/` directory into any project to get on-demand security analysis.

## Repository Structure

**Distributable skills** (what gets installed into projects):
- `.claude/commands/security-review.md` — Code-level vulnerability review. Covers OWASP Top 10, injection, auth, access control, SSRF, crypto, config, secrets, path traversal, race conditions, and more. Invoked via `/security-review`.
- `.claude/commands/threat-model.md` — Architecture-level STRIDE threat model derived from actual code analysis, with a mermaid data-flow diagram, a privacy/data-protection pass, and attack paths for top risks. Invoked via `/threat-model`.

**Reference material** (original multi-agent specs these skills were derived from):
- `AGENT.md` — Security coordinator agent spec
- `threat.md` — Threat modeling subagent (STRIDE methodology reference)
- `compliance.md` — Compliance mapping subagent (NIST 800-53, OWASP ASVS, HIPAA, FERPA, PCI-DSS, GDPR, SOC 2)
- `code.md` — Secure code review subagent (Python/FastAPI, TypeScript/React, PostgreSQL patterns)

## Key Design Decisions

- The skills are **self-contained** — they don't depend on the reference files or on each other. Each `.claude/commands/*.md` file works independently when copied into any project.
- The skills instruct Claude to **read actual code**, not fill generic templates. Every finding must reference real file paths and line numbers.
- Severity ratings consider **context** (exploitability, blast radius, data sensitivity), not just vulnerability category.
- The skills are **technology-agnostic** — they work on any language/framework but contain guidance on what to look for in specific ecosystems.

## When Editing the Skills

- Keep instructions concrete and analytical. "Check for SQL injection" is insufficient — describe what injection looks like across ORMs, raw queries, and template engines.
- Avoid adding template/report boilerplate. The output format sections should be minimal; the analysis instructions should be comprehensive.
- Test changes by running `/security-review` against the regression corpus: `/security-review Review the application in tests/fixtures/vuln-app/`, then score with `./tests/score-report.sh <report>` and compare against `tests/EXPECTED-FINDINGS.md` (see `tests/README.md` for acceptance criteria). When adding a vulnerability section to the skill, plant a matching finding in the fixture and add it to the manifest.
- Do not add compliance framework mapping to the security-review skill — that's organizational, not code-level. Keep it in the threat-model skill's regulatory considerations section.
