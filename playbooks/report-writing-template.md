# Playbook: Report writing template

Roshan's established finding format (from the PINERP audit onward) — use this
structure whenever c0mr4de writes up a finding, whether for a live report or a
workspace note.

## Per-finding structure

```
### Finding N: <short title>

**Severity:** Critical | High | Medium | Low | Info  (mark "(conditional)" if
    severity depends on an unverified assumption, e.g. "critical if the secret
    is never rotated")
**Vulnerability Category:** <name + CWE id>. Use an SL-level rating if asked for
    one; skip CVSS unless explicitly requested.

**Description:** One or two sentences, plain language, what the bug is.

**Technical Details:** The mechanism - what code/config/logic causes it, with
    file/line or endpoint references where available.

**Steps to Reproduce:** Numbered, concrete, reproducible by someone who wasn't
    there. This and PoC are the two mandatory parts - don't skip either.

**Proof of Concept:** The actual request/payload/script that demonstrates it.
    Prefer a real captured request/response over a description.

**Impact:** What an attacker actually gets - concrete capability, not "this is
    insecure." E.g. "any registered user can bypass the payment gate and access
    paid features without paying," not "the token can be tampered with."

**Remediation:** Concrete fix, not just "validate input properly."

**References:** CWE link, relevant OWASP category, etc.
```

## Overall report structure

1. Executive summary - infra/stack overview, overall posture assessment, findings
   count by severity.
2. Findings, most severe first, each in the format above.
3. Positives - call out what's actually well-implemented (this was consistently
   done across pixstech, M1rage, and PINERP reports - e.g. "Entra SSO, encrypted+
   locked S3 bucket, WAF, SPF hardfail" for pixstech). Builds credibility and gives
   the client/owner a accurate picture, not just a list of bad news.
4. If this is a re-test/verification round, include a diff against the previous
   report - what's fixed, what's still open, what's newly introduced.

## Tone

Direct, technical, no hedging on confirmed findings. Mark unconfirmed/suspected
issues explicitly as such (e.g. "possible exposed key - flagged but not
independently verified") rather than blending confidence levels together.
