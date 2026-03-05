# Threat Model

You are performing a threat model of this system. You are an expert application security engineer analyzing architecture and code to identify threats — not filling in a generic template.

## How to Execute

### Step 1: Understand the System

Read the codebase to determine:

1. **What does it do?** — Business purpose, data it handles, users it serves
2. **What's the stack?** — Languages, frameworks, databases, message queues, caches, cloud services
3. **What data does it process?** — Classify by sensitivity:
   - **Restricted:** Credentials, encryption keys, session tokens, API secrets
   - **Confidential:** PII (names, emails, addresses, phone numbers), PHI, financial data, educational records
   - **Internal:** Business logic data, non-public configuration, internal metrics
   - **Public:** Intentionally public content
4. **Where does data flow?** — Trace from user input through processing to storage and output. Identify every trust boundary crossing (browser→API, API→database, service→service, service→external API).

### Step 2: Map Attack Surface

Identify concrete entry points by reading route definitions, API schemas, and integration code:

| Entry Point | Auth Required | Data Accepted | Trust Boundary Crossed |
|-------------|---------------|---------------|------------------------|
| [Actual endpoint from code] | [What auth mechanism] | [What input types] | [Which boundary] |

### Step 3: STRIDE Analysis on Real Components

For each component that crosses a trust boundary, ask the six STRIDE questions. Only document threats that are plausible given the actual implementation — do not list every theoretical threat for every component.

**Spoofing** — Can an attacker impersonate a legitimate user or component?
- How is identity established? What's the token/session mechanism?
- Can tokens be forged, stolen, or replayed?
- Are service-to-service calls authenticated?

**Tampering** — Can an attacker modify data in transit or at rest?
- Is input validated at the trust boundary?
- Can database records be modified through injection or mass assignment?
- Are file uploads verified for content, not just extension?
- Can API responses be tampered with (MITM if no TLS)?

**Repudiation** — Can an attacker deny performing an action?
- Are security-relevant events logged (login, data access, privilege changes)?
- Are logs tamper-evident?
- Can log entries be forged via injection?

**Information Disclosure** — Can an attacker access data they shouldn't?
- Can they reach other users' data (IDOR)?
- Do error messages reveal internal details?
- Is sensitive data exposed in logs, URLs, or client-side code?
- Can SSRF reach internal services or cloud metadata?

**Denial of Service** — Can an attacker degrade or halt the service?
- Are there rate limits on expensive operations?
- Can unbounded input cause resource exhaustion (regex DoS, large file uploads, expensive queries)?
- Are there circuit breakers for external dependencies?

**Elevation of Privilege** — Can an attacker gain unauthorized access?
- Can a regular user reach admin functionality?
- Can authorization checks be bypassed by manipulating request parameters?
- Can a compromised low-privilege component access high-privilege resources?

### Step 4: Risk Assessment

Rate each identified threat:

| Factor | Scale | Meaning |
|--------|-------|---------|
| **Likelihood** | Low / Medium / High | How easy is exploitation given current controls? |
| **Impact** | Low / Medium / High / Critical | What's the worst-case outcome if exploited? |

Combine into risk: use the higher value, weighted toward impact for data-sensitive systems.

Consider real-world factors:
- Is the application internet-facing or internal?
- What authentication is required to reach the attack surface?
- What data is at stake? (PII/PHI/financial = higher impact)
- Are there existing mitigations that reduce likelihood?

### Step 5: Produce the Threat Model

```markdown
# Threat Model: [System Name]

**Date:** [Date]
**Scope:** [What was analyzed]
**Data Sensitivity:** [Highest classification of data handled]

## System Overview
[Brief description based on actual code analysis, not assumptions]

## Data Classification
| Data Type | Classification | Storage | Encryption |
|-----------|---------------|---------|------------|
| [Actual data from code] | [Level] | [Where stored] | [At rest / in transit status] |

## Attack Surface
[Entry point table from Step 2]

## Trust Boundaries
[Describe actual boundaries identified in the architecture]

## Threats

### Critical/High Risk
[Only threats rated critical or high — with specific references to code]

### Medium Risk
[Medium-rated threats]

### Low Risk
[Low-rated threats — brief descriptions sufficient]

## Existing Security Controls
[What's already in place — this matters for accurate risk assessment]

## Recommended Mitigations
[Ordered by risk reduction value, with implementation guidance]

## Regulatory Considerations
[Only if applicable — note if the data types trigger HIPAA, GDPR, PCI-DSS, FERPA, or SOC 2 requirements, and which specific requirements are relevant to the identified threats]
```

## Key Rules

- **Read the code.** Do not produce a generic threat model. Every threat must reference actual components, endpoints, or data flows found in the codebase.
- **Skip what doesn't apply.** If the system doesn't handle file uploads, don't list file upload threats. If there's no admin interface, don't model admin privilege escalation.
- **Prioritize.** A threat model with 50 items is useless. Focus on the threats that matter most given this system's specific architecture and data sensitivity.
- **Acknowledge unknowns.** If you can't determine something from the code (e.g., infrastructure configuration, WAF rules, network segmentation), say so rather than assuming.

## Saving the Report

After completing the threat model, save the report to disk:

1. Create the output directory if it doesn't exist: `security-reviews/`
2. Write the full threat model report to `security-reviews/threat-model-YYYY-MM-DD.md` using today's date.
3. Confirm the file path to the user after saving.
