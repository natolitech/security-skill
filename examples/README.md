# Examples

Real, end-to-end examples of using the two skills. The fixture examples were produced by executing the skills (v2.1.0) against `tests/fixtures/vuln-app/` — an intentionally vulnerable demo store ("ShopLite") — with no foreknowledge of the planted issues. The remote example was produced by executing `/security-review` (v2.1.0) against a live public repository. Nothing here is mocked or hand-written.

## The Commands

```text
/security-review                                                    # whole project
/security-review Review the authentication module in src/auth/      # scoped to a directory
/security-review Review the changes on this branch for security issues   # scoped to a diff/PR
/security-review https://github.com/org/target-repo                 # remote repository (shallow-cloned)
/threat-model                                                       # whole system
/threat-model Focus on the payment processing subsystem             # scoped to a feature
/threat-model https://github.com/org/target-repo                    # remote repository (shallow-cloned)
```

Full invocation reference: [../README.md](../README.md) and [../INSTALL.md](../INSTALL.md).

## Example Files

| File | What it shows |
|------|---------------|
| [`security-review-report-example.md`](security-review-report-example.md) | Complete `/security-review` output: 42 findings, executive summary, "Since Last Review" slot, severity/confidence-rated findings with evidence and remediation, positive observations, recommendations |
| [`findings-example.json`](findings-example.json) | The machine-readable index written alongside every review — finding IDs, severities, locations, triage statuses — for CI diffs and trend tracking |
| [`threat-model-example.md`](threat-model-example.md) | Complete `/threat-model` output: data classification, attack surface table, mermaid data-flow diagram with numbered boundary crossings, STRIDE + privacy threats (TM-NNN), attack paths for top risks |
| [`backlog-example.md`](backlog-example.md) | A triaged `security-reviews/backlog.md` showing all five statuses and what the next review does with each |
| [`security-review-remote-example.md`](security-review-remote-example.md) | Remote repository review (OWASP NodeGoat @ `c5cb68a`): URL → shallow clone → commit-pinned report with repo-name slug, cross-target notes, shallow-clone history caveat |

## Walkthrough 1 — First Security Review

You've just installed the skills into a project (see [../INSTALL.md](../INSTALL.md#installation-methods)). In Claude Code:

```text
/security-review
```

Claude reads your code — routes, auth flows, queries, config, containers — then writes two files:

```text
security-reviews/
  security-review-2026-10-10-1041-vuln-app.md   ← the report (see the example file)
  findings-2026-10-10-1041.json                 ← the index (see the example JSON)
```

Reading the report, top to bottom:

1. **Executive Summary + Finding Counts** — overall posture and the shape of the problem in 15 seconds
2. **Critical and High Findings** — each one names the exact `file:line`, quotes the vulnerable code (with secrets redacted to first/last 4 characters), rates confidence (`Confirmed` / `Likely` / `Suspected`), and shows corrected code in the remediation — see SR-001 in the example for the pattern
3. **Medium/Low and Informational** — same rigor, lower urgency
4. **Positive Observations** — what's already done right; this keeps severity honest and tells you which patterns to spread
5. **Recommendations Summary** — fixes grouped as immediate / this sprint / longer-term

The example report found 4 criticals in a ~600-line app, including an unauthenticated command injection (SR-001) — with the exact diff-shaped fix.

## Walkthrough 2 — Triaging into the Backlog

After reading the report, triage each finding in `security-reviews/backlog.md` (template is created automatically; the full worked example is [`backlog-example.md`](backlog-example.md)):

- **confirmed** — it's real, schedule the fix
- **false-positive** — code is actually safe; include why in Notes
- **risk-accepted** — real, but you're accepting it for now; record the condition ("internal beta only")
- **resolved** — fixed

This is a human decision — the skill appends `open` rows but never edits your statuses.

## Walkthrough 3 — Repeat Review with Deltas

Next week (or on the next PR):

```text
/security-review Review the changes on this branch for security issues
```

The skill reads the prior report and your backlog, then adds a **Since Last Review** section: *New* / *Resolved* / *Persisted*. Known false-positives at unchanged code are suppressed (counted, not re-reported) and risk-accepted items collapse to one line — unless context changed, in which case they're re-escalated with an explanation. You see what changed, not a fresh wall of the same findings.

## Walkthrough 4 — Threat Model Before a New Feature

Designing something new or heading toward a release:

```text
/threat-model
```

The output ([example](threat-model-example.md)) gives you the architectural view the code review can't: a data classification table, an attack-surface inventory, a mermaid data-flow diagram with numbered trust-boundary crossings (B1, B2, …), STRIDE + privacy threats with `TM-NNN` IDs, and **attack paths** — chained kill chains for the top risks, each step referencing real components and boundary IDs. If a prior security review exists, it's read as evidence for the Existing Security Controls section.

Use the two together: threat model finds *where* the architecture is weak; security review finds *the code* that makes it weak.

## Walkthrough 5 — Reviewing a Remote Repository

Evaluating a dependency, a fork, or code you don't have checked out locally:

```text
/security-review https://github.com/OWASP/NodeGoat
```

The skill shallow-clones the repo into a temp directory outside your project, analyzes it there, and writes the report with the repo name as the scope slug. The [example](security-review-remote-example.md) shows the remote-specific behaviors: the report header pins the exact commit reviewed (`c5cb68a…`), states it's a baseline for this target (deltas and the backlog apply per-repository, never across targets), and notes that the shallow clone has no git history — so history-dependent checks are called out as out of scope rather than skipped silently. If the clone fails (private repo, no credentials), the run stops and says so; the fallback is cloning manually and reviewing by local path.

## What Good Output Looks Like

The examples demonstrate the quality bar the skills enforce:

- Every finding cites real `file:line` — never "you might have injection somewhere"
- Confidence ratings distinguish traced-and-unmitigated (Confirmed) from dangerous-but-unverifiable (Suspected) — watch for honest downgrades, like the example's SR-027, where a dangerous deserialization helper was downgraded because no route actually calls it
- Secrets are always redacted in evidence, with a rotation reminder
- Controls that exist are acknowledged, not flagged
