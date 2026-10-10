# Security Review Skill for Claude Code

A distributable application security review skill for Claude Code. Engineers add this to any project to get on-demand security analysis — at any point in development, not just at release gates.

## Installation

Copy the `.claude/commands/` directory into your project:

```bash
# From your project root
mkdir -p .claude/commands
cp /path/to/security-skill/.claude/commands/security-review.md .claude/commands/
cp /path/to/security-skill/.claude/commands/threat-model.md .claude/commands/
```

Or clone and symlink:

```bash
mkdir -p .claude/commands
ln -s /path/to/security-skill/.claude/commands/security-review.md .claude/commands/security-review.md
ln -s /path/to/security-skill/.claude/commands/threat-model.md .claude/commands/threat-model.md
```

## Usage

In Claude Code, invoke the skills with slash commands:

### Full Security Review

```
/security-review
```
Reviews the entire project for vulnerabilities. Covers OWASP Top 10, authentication/authorization, injection, cryptographic issues, SSRF, access control, configuration, secrets, and more.

You can scope it:
```
/security-review Review the authentication module in src/auth/
/security-review Focus on the API endpoints in src/routes/
/security-review Review only the changes in this PR
```

You can also point it at a remote repository:
```
/security-review https://github.com/org/target-repo
```
The skill shallow-clones the repo (`git clone --depth 1`) into a temporary directory outside your project, analyzes the clone there, and saves the report to your project's `security-reviews/` directory with the repo name as the scope slug. Findings are pinned to the URL plus the exact commit hash reviewed. A shallow clone has no git history, so history-dependent checks (secrets committed in the past) are flagged as out of scope. If the clone fails — a private repo you don't have credentials for, for example — the skill says so and stops rather than guessing.

### Threat Model

```
/threat-model
```
Produces a STRIDE-based threat model by analyzing the actual codebase — not a generic template. Identifies data classifications, trust boundaries, attack surface, privacy and retention risks, and prioritized threats with attack paths for the top risks.

Accepts a remote repository URL the same way:
```
/threat-model https://github.com/org/target-repo
```
The repo is shallow-cloned into a temp directory and modeled there; the report header records the URL and the exact commit reviewed.

### Saved Output

Both commands write to a `security-reviews/` directory in your project: timestamped markdown reports, a machine-readable `findings-*.json` index from `/security-review` (for CI diffs and trend tracking), and a triage `backlog.md` that suppresses known false-positives and risk-accepted items on repeat runs. Repeat reviews include a "Since Last Review" delta section, and each skill reads the other's prior output to focus its analysis. See [INSTALL.md](INSTALL.md) for details.

See [INSTALL.md](INSTALL.md) for full usage details, and [examples/](examples/) for complete, real example outputs from both commands.

## What's Included

| File | Purpose |
|------|---------|
| `.claude/commands/security-review.md` | Code-level vulnerability review skill |
| `.claude/commands/threat-model.md` | Architecture-level threat modeling skill |
| `install.sh` | One-command installer for the two skills (see INSTALL.md Method 4) |
| `examples/` | Real end-to-end outputs from both skills, with walkthroughs |
| `CONTRIBUTING.md` | How to contribute improvements back upstream |

### Regression Corpus (this repo only)

| File | Purpose |
|------|---------|
| `tests/fixtures/vuln-app/` | Intentionally vulnerable app used to regression-test skill changes (never run it) |
| `tests/EXPECTED-FINDINGS.md` | Answer key: 36 planted findings, 4 control cases, redaction checks |
| `tests/score-report.sh` | Smoke-checks a generated report against the manifest |

### Reference Material (this repo only)

| File | Purpose |
|------|---------|
| `AGENT.md` | Original coordinator agent spec (reference) |
| `threat.md` | Original threat modeling subagent spec (reference) |
| `compliance.md` | Original compliance mapping subagent spec (reference) |
| `code.md` | Original secure code review subagent spec (reference) |

The reference files document the original multi-agent security system these skills were derived from. They are not needed for the skills to function — only the two files in `.claude/commands/` need to be distributed.

## What the Security Review Covers

- Injection (SQL, NoSQL, command, template, LDAP)
- Broken authentication and session management
- Broken access control (IDOR, privilege escalation, mass assignment)
- Cross-site request forgery (CSRF)
- GraphQL and API-specific issues (BOLA, field-level authorization, batching abuse)
- Cryptographic failures
- Server-side request forgery (SSRF)
- Cross-site scripting (XSS)
- Frontend-specific issues (postMessage origins, token storage, source maps)
- Insecure deserialization and prototype pollution
- Security misconfiguration (CORS, CSP, debug mode, headers)
- Containers and infrastructure as code (Docker, Kubernetes, Terraform, CI/CD)
- Vulnerable dependencies
- Path traversal
- File upload handling
- Race conditions
- Business logic abuse
- Open redirect
- Logging/secrets hygiene
- LLM-application security (prompt injection, agent authorization)

## Design Principles

These skills were built to address common failures in AI-assisted security reviews:

1. **Read the code, don't fill templates.** Every finding must reference actual file paths and line numbers. No generic checklists.
2. **Assess in context.** Severity considers exploitability, blast radius, and data sensitivity — not just vulnerability category.
3. **Stack-agnostic, stack-aware.** Works on any language/framework but knows what to look for in each.
4. **Actionable output.** Every finding includes the vulnerable code and a concrete remediation pattern.
5. **Acknowledge limits.** The skill instructs Claude to flag what it can't determine rather than fabricate findings.

## License

MIT — see [LICENSE](LICENSE). Any organization is free to use, copy, and modify the skills, including commercially, with no obligation to share changes back.

**A request, not a requirement:** if you improve the skills — new vulnerability coverage, better remediation patterns, fewer false positives — please contribute the changes back via a pull request to [github.com/natolitech/security-skill](https://github.com/natolitech/security-skill) so every user benefits. The regression corpus in `tests/` makes it safe to verify that changes don't lose coverage. See [CONTRIBUTING.md](CONTRIBUTING.md).
