# Installation and Usage Guide

Detailed guide for installing and using the Security Review skills with Claude Code.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
  - [Method 1: Direct Copy (Per-Project)](#method-1-direct-copy-per-project)
  - [Method 2: Symlink (Shared, Single Source of Truth)](#method-2-symlink-shared-single-source-of-truth)
  - [Method 3: Git Submodule (Team Distribution)](#method-3-git-submodule-team-distribution)
  - [Method 4: Shell Script Installer](#method-4-shell-script-installer)
- [Verifying Installation](#verifying-installation)
- [Usage](#usage)
  - [Running a Security Review](#running-a-security-review)
  - [Running a Threat Model](#running-a-threat-model)
  - [Scoping Your Review](#scoping-your-review)
- [Understanding the Output](#understanding-the-output)
  - [Security Review Output](#security-review-output)
  - [Threat Model Output](#threat-model-output)
  - [Severity Ratings Explained](#severity-ratings-explained)
- [Workflow Integration](#workflow-integration)
  - [During Feature Development](#during-feature-development)
  - [During Code Review / PR](#during-code-review--pr)
  - [Pre-Release Audit](#pre-release-audit)
  - [After a Security Incident](#after-a-security-incident)
- [Team Rollout](#team-rollout)
- [Customization](#customization)
- [Troubleshooting](#troubleshooting)
- [Updating](#updating)

---

## Prerequisites

- **Claude Code** installed and configured ([claude.ai/code](https://claude.ai/code))
- A project repository to install into
- No other dependencies — the skills are plain markdown files

---

## Installation Methods

### Method 1: Direct Copy (Per-Project)

Best for: trying it out on a single project.

```bash
# Navigate to your project root
cd /path/to/your-project

# Create the commands directory
mkdir -p .claude/commands

# Copy the skill files
cp /path/to/security-skill/.claude/commands/security-review.md .claude/commands/
cp /path/to/security-skill/.claude/commands/threat-model.md .claude/commands/
```

Then commit them to your project:

```bash
git add .claude/commands/security-review.md .claude/commands/threat-model.md
git commit -m "Add security review skills for Claude Code"
```

### Method 2: Symlink (Shared, Single Source of Truth)

Best for: using across multiple local projects while keeping one updatable copy.

```bash
# Clone the security-skill repo to a shared location
git clone <this-repo-url> ~/tools/security-skill

# In each project:
cd /path/to/your-project
mkdir -p .claude/commands
ln -s ~/tools/security-skill/.claude/commands/security-review.md .claude/commands/security-review.md
ln -s ~/tools/security-skill/.claude/commands/threat-model.md .claude/commands/threat-model.md
```

**Note:** Symlinks won't follow into other developers' environments. This method is for personal use across your own projects. For team distribution, use Method 3 or 4.

Add symlinks to `.gitignore` if you don't want them tracked:

```bash
echo ".claude/commands/security-review.md" >> .gitignore
echo ".claude/commands/threat-model.md" >> .gitignore
```

### Method 3: Git Submodule (Team Distribution)

Best for: teams who want the skills version-controlled and updatable across all projects.

```bash
cd /path/to/your-project

# Add as a submodule in a tools directory
git submodule add <this-repo-url> tools/security-skill

# Create the commands directory and symlink (or copy)
mkdir -p .claude/commands
cp tools/security-skill/.claude/commands/security-review.md .claude/commands/
cp tools/security-skill/.claude/commands/threat-model.md .claude/commands/

git add .claude/commands/ .gitmodules tools/security-skill
git commit -m "Add security review skills for Claude Code via submodule"
```

To update later:

```bash
cd tools/security-skill
git pull origin main
cd ../..
cp tools/security-skill/.claude/commands/security-review.md .claude/commands/
cp tools/security-skill/.claude/commands/threat-model.md .claude/commands/
git add .
git commit -m "Update security review skills"
```

### Method 4: Shell Script Installer

Best for: scripted setup across many projects or CI environments.

Create this script or run it directly:

```bash
#!/bin/bash
# install-security-skills.sh
# Usage: ./install-security-skills.sh [project-dir] [security-skill-dir]

PROJECT_DIR="${1:-.}"
SKILL_DIR="${2:-$HOME/tools/security-skill}"

if [ ! -d "$SKILL_DIR/.claude/commands" ]; then
  echo "Error: Security skill not found at $SKILL_DIR"
  echo "Clone it first: git clone <repo-url> $SKILL_DIR"
  exit 1
fi

mkdir -p "$PROJECT_DIR/.claude/commands"
cp "$SKILL_DIR/.claude/commands/security-review.md" "$PROJECT_DIR/.claude/commands/"
cp "$SKILL_DIR/.claude/commands/threat-model.md" "$PROJECT_DIR/.claude/commands/"

echo "Security skills installed to $PROJECT_DIR/.claude/commands/"
echo "Available commands: /security-review, /threat-model"
```

---

## Verifying Installation

After installation, verify the files are in place:

```bash
ls -la .claude/commands/
```

Expected output:

```
security-review.md
threat-model.md
```

Then open Claude Code in your project. The skills should appear as available slash commands. Type `/` and you should see `security-review` and `threat-model` in the autocomplete list.

---

## Usage

### Running a Security Review

The `/security-review` command performs a code-level vulnerability analysis. It reads your actual source code, traces data flows, and reports specific findings with file paths and line numbers.

**Full project review:**

```
/security-review
```

Claude will:
1. Identify your tech stack from manifest files
2. Map all entry points (routes, APIs, webhooks, etc.)
3. Identify sensitive operations (auth, data access, crypto, etc.)
4. Check configuration (CORS, CSP, headers, IaC)
5. Systematically analyze each entry point for vulnerability classes
6. Assess severity in context
7. Produce a structured report with findings and remediation

**Scoped review — specific directory:**

```
/security-review Review the authentication system in src/auth/
```

**Scoped review — specific concern:**

```
/security-review Focus on injection vulnerabilities in the API layer
```

**Scoped review — PR or recent changes:**

```
/security-review Review the changes in the current branch for security issues
```

**Scoped review — specific files:**

```
/security-review Review src/controllers/payment.ts and src/services/stripe.ts
```

### Running a Threat Model

The `/threat-model` command produces an architecture-level STRIDE analysis by reading your codebase.

**Full threat model:**

```
/threat-model
```

Claude will:
1. Determine system purpose, stack, and data types from code
2. Classify data by sensitivity (restricted, confidential, internal, public)
3. Map all entry points and trust boundaries
4. Perform STRIDE analysis on each trust boundary crossing
5. Assess risk with real-world context
6. Note regulatory implications if applicable
7. Produce a prioritized threat model with mitigations

**Scoped threat model:**

```
/threat-model Focus on the payment processing subsystem
```

```
/threat-model Model threats for the new webhook integration
```

### Scoping Your Review

| You Want | Command |
|----------|---------|
| Full project audit | `/security-review` |
| Review one module | `/security-review Review src/auth/` |
| Review a specific vulnerability class | `/security-review Check for injection vulnerabilities` |
| Review recent changes | `/security-review Review changes on this branch` |
| Review before merging a PR | `/security-review Review the diff against main` |
| Architecture threat model | `/threat-model` |
| Threat model a specific feature | `/threat-model Focus on the file upload feature` |
| Quick check on a single file | `/security-review Review src/routes/admin.ts` |

---

## Understanding the Output

### Security Review Output

The review produces a structured markdown report:

```
# Security Review: [Project Name]

Date, scope, and detected stack

## Executive Summary
Brief overall assessment and finding counts

## Critical and High Findings
Each finding includes:
  - Severity and title
  - Exact file path and line number
  - OWASP/CWE category
  - Exploitability assessment
  - Description referencing actual code
  - The vulnerable code quoted
  - Concrete remediation with corrected code
  - Reference links

## Medium and Low Findings
Same format, lower severity

## Informational Notes
Defense-in-depth observations

## Positive Observations
What's already done well (important for overall context)

## Recommendations Summary
Prioritized actions grouped by effort
```

**Key properties of findings:**

- Every finding references a **specific file and line number** — not a generic "you might have SQL injection"
- Every finding includes the **actual vulnerable code** quoted from your codebase
- Every remediation shows **corrected code**, not just "fix this"
- Severity is **contextual** — the same vulnerability type can be Critical or Low depending on exposure and data sensitivity

### Threat Model Output

```
# Threat Model: [System Name]

Date, scope, data sensitivity level

## System Overview
What the system does, based on code analysis

## Data Classification
Table of actual data types found, their classification, storage, and encryption status

## Attack Surface
Every entry point found in the code with auth requirements and trust boundaries

## Trust Boundaries
Actual boundaries in the architecture

## Threats
Grouped by risk level (Critical/High, Medium, Low)
Each references specific code components

## Existing Security Controls
What's already implemented

## Recommended Mitigations
Ordered by risk reduction value

## Regulatory Considerations
Only if data types trigger specific requirements
```

### Severity Ratings Explained

| Rating | What It Means | Example | Typical Action |
|--------|---------------|---------|----------------|
| **CRITICAL** | Direct path to RCE, full DB access, auth bypass, mass data exfiltration. No special conditions. | Unsanitized user input in SQL query on public endpoint returning PII | Fix immediately. Stop other work. |
| **HIGH** | Individual account takeover, significant data exposure, privilege escalation. May require authentication. | IDOR allowing any authenticated user to access other users' records | Fix before next release. Prioritize this sprint. |
| **MEDIUM** | Limited data exposure, CSRF, info disclosure aiding further attacks, missing expected controls. | Missing rate limiting on login endpoint; reflected XSS requiring user interaction | Fix within current development cycle. |
| **LOW** | Verbose errors, missing best-practice headers, minor info leakage, unlikely exploitation conditions. | Server version exposed in HTTP headers; missing X-Content-Type-Options header | Address when convenient. Track in backlog. |
| **INFORMATIONAL** | Defense-in-depth gaps, best practice deviations, proactive improvements. | No CSP header (but no XSS found); using SHA-256 for non-security hashing | Consider for hardening. No urgency. |

---

## Workflow Integration

### During Feature Development

Run a scoped review as you build:

```
/security-review Review the new user registration flow I just added in src/auth/register.ts
```

This catches issues early when they're cheapest to fix. Particularly valuable when implementing:
- Authentication or authorization logic
- Payment or financial transactions
- File upload handling
- API endpoints accepting user input
- Third-party integrations
- Admin or privileged operations

### During Code Review / PR

Before approving or requesting review on a PR:

```
/security-review Review the changes on this branch compared to main
```

This focuses on new or modified code and checks that changes don't break existing security properties. Use this to catch security issues before they reach the main branch.

### Pre-Release Audit

Before releasing a version, run the full suite:

```
/security-review
/threat-model
```

The security review catches code-level issues. The threat model provides the architectural view. Together they cover both tactical vulnerabilities and strategic security gaps.

Both skills automatically save their output to a `security-reviews/` directory in your project root:

```
security-reviews/
  security-review-2026-03-05.md
  threat-model-2026-03-05.md
```

You can commit these alongside your release notes or keep them for audit records.

### After a Security Incident

When investigating or remediating a security incident:

```
/security-review Focus on [affected component]. We had an incident involving [brief description].
```

This helps identify whether the root cause has related issues elsewhere in the codebase.

---

## Team Rollout

### Step 1: Install in a Pilot Project

Pick one active project and install using Method 1 (direct copy). Run `/security-review` and evaluate the output quality against your team's expectations.

### Step 2: Establish Team Convention

Decide when reviews should run:

| Trigger | Skill | Who |
|---------|-------|-----|
| New feature touching auth/authz | `/security-review` scoped to feature | Feature developer |
| PR with security-sensitive changes | `/security-review` scoped to diff | PR reviewer |
| Sprint boundary | `/security-review` on sprint's changes | Team lead or security champion |
| Before major release | `/security-review` + `/threat-model` | Security champion |
| New integration or API endpoint | `/threat-model` scoped to feature | Feature developer |

### Step 3: Distribute

Use Method 3 (submodule) or Method 4 (script) to install across all team projects. Add a note to your team's onboarding docs:

```markdown
## Security Reviews with Claude Code

We use automated security review skills in Claude Code. They're already installed
in `.claude/commands/`. Two commands are available:

- `/security-review` — Run anytime to check code for vulnerabilities
- `/threat-model` — Run when designing new features or before releases

See INSTALL.md in the security-skill repo for full usage details.
```

### Step 4: Track and Improve

Keep a lightweight log of findings that the skill catches (or misses). Use this to:
- Calibrate team expectations
- Identify patterns in your codebase that deserve custom rules
- Provide feedback for improving the skill prompts

---

## Customization

The skill files are plain markdown — you can customize them for your team's needs.

### Adding Project-Specific Concerns

Edit `.claude/commands/security-review.md` to add project-specific checks. For example, if your project uses Supabase RLS:

```markdown
#### Supabase Row-Level Security

What to look for:
- Tables without RLS enabled: check all migration files for `ENABLE ROW LEVEL SECURITY`
- Policies that use `true` as the expression (allows all access)
- Missing policies for INSERT, UPDATE, or DELETE (only SELECT is covered)
- Service role key used in client-side code (bypasses RLS)
```

### Adjusting Severity Criteria

If your project handles healthcare data, you might want to escalate all data exposure findings:

Edit the severity table in `security-review.md` to add:

```markdown
| **CRITICAL** | ...existing criteria... Also: any unauthorized access path to PHI, regardless of exploitability. |
```

### Adding Compliance Requirements

If your team needs compliance checks, add a section to `threat-model.md`:

```markdown
### Step 6: Compliance Verification

For this project, verify the following [HIPAA/PCI-DSS/etc.] requirements:
- [Specific controls relevant to your project]
```

### Removing Sections

If certain vulnerability classes aren't relevant (e.g., SSRF in a purely client-side project), you can remove those sections to reduce noise. However, keep them if there's any server-side component — they're there because they're commonly overlooked.

---

## Troubleshooting

### Skills don't appear as slash commands

**Check file location.** The files must be at exactly:
```
your-project/
  .claude/
    commands/
      security-review.md
      threat-model.md
```

Not nested deeper, not in a different directory name.

**Check file permissions.** Claude Code needs read access:
```bash
ls -la .claude/commands/
# Files should be readable (-rw-r--r-- or similar)
```

**Check for symlink issues.** If using symlinks, verify they resolve:
```bash
readlink -f .claude/commands/security-review.md
# Should print the actual file path
```

### Review takes too long

Large projects can take time for a full review. Scope it down:

```
/security-review Review only src/api/ and src/auth/
```

Or focus on what matters most:

```
/security-review Focus on authentication, authorization, and injection vulnerabilities only
```

### Findings seem generic or not specific to my code

This should not happen — the skill explicitly instructs Claude to read actual code and reference specific files/lines. If you see generic output:

1. Make sure you're using the skill files from this repo, not a different security prompt
2. Check that Claude Code has access to read the project files
3. Try scoping to a specific directory to confirm it's reading code

### False positives

Security reviews will sometimes flag code that's actually safe. This is expected and preferable to missing real issues. If a finding is a false positive:

- Check whether the mitigation is elsewhere (e.g., validation happens in middleware, not in the flagged function)
- The finding may still be worth noting as defense-in-depth — if the upstream control is removed later, the code becomes vulnerable
- Use the finding to add a code comment explaining why the pattern is safe in this context

---

## Updating

### If installed via direct copy (Method 1)

Re-copy the files from the updated security-skill repo:

```bash
cp /path/to/security-skill/.claude/commands/security-review.md .claude/commands/
cp /path/to/security-skill/.claude/commands/threat-model.md .claude/commands/
```

### If installed via symlinks (Method 2)

Update the source repo:

```bash
cd ~/tools/security-skill
git pull
```

Symlinked projects pick up changes automatically.

### If installed via submodule (Method 3)

```bash
cd tools/security-skill
git pull origin main
cd ../..
cp tools/security-skill/.claude/commands/security-review.md .claude/commands/
cp tools/security-skill/.claude/commands/threat-model.md .claude/commands/
git add .
git commit -m "Update security review skills"
```

### If installed via script (Method 4)

Re-run the installer script after pulling updates to the source repo.
