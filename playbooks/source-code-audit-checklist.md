# Playbook: Source-code security audit checklist

Distilled from the PINERP (GOAL-DIGGERS-PINERP) source audit — what to check when
you have repo access instead of (or in addition to) black-box access.

## Pass order

1. **Injection surfaces first** — grep for raw SQL construction (`$queryRaw` and
   equivalents), confirm parameterization; check for XSS sinks in the frontend
   (`dangerouslySetInnerHTML` in React and equivalents elsewhere).
2. **Session/auth implementation:**
   - Cookie flags (HttpOnly, Secure, SameSite).
   - CSRF protection — is there an origin/header check (e.g., `X-Requested-With`),
     and is CORS actually origin-locked or wildcard?
   - Password handling — bcrypt/argon2 (not plain/weak hash), login lockout present?
3. **JWT/session-secret hygiene — check this even if the app "looks" secure:**
   - Is the JWT secret validated for strength, or does env-var validation only
     check `min(1)` (i.e., accepts anything non-empty)? PINERP's `.env.example`
     shipped a `change-me-*` placeholder that would work if never rotated —
     CWE-798, conditional critical.
   - Are there default seeded credentials anywhere in seed scripts/fixtures
     (PINERP: `admin`/`Demo@1234` shared across all seed users)?
4. **The most valuable single check: is the JWT/session ever revalidated against
   the database after issuance?** This is the headline-severity pattern across
   multiple audits so far. Grep the auth middleware for where it reads role/active
   status: if `isAdmin` or similar comes straight from the token and `isActive` is
   only checked at login time (not per-request against the DB), then:
   - Disabling/demoting a user doesn't revoke their existing session.
   - Password reset doesn't invalidate old tokens.
   - Any "force logout" admin panel button is cosmetic unless it actually writes
     to a session table the middleware checks.
   Proof of concept: capture a valid session, have an admin disable that account,
   replay the original session — if it still returns 200, this is confirmed
   (PINERP: CWE-613/285, rated High, called out as the best live PoC of the audit).
5. **Money/quantity mutation logic** — look for unbounded deltas. PINERP's
   `deliverSalesOrder` computed `delta = new - current` with no lower bound, so
   sending a smaller "delivered" quantity than current silently inflated stock
   (CWE-840). Any endpoint that adjusts a balance/quantity/credit based on a
   client-supplied new-vs-old comparison deserves this check.
6. **User enumeration** — do login/reset endpoints return distinguishable
   responses (401 vs 403 vs 423, or "N attempts remaining" text) for
   valid-vs-invalid usernames? Low severity alone, but free to check and often
   present (CWE-204).
7. **Server-side price/total computation** — confirm totals are recomputed
   server-side from trusted data, not trusted from client-submitted values
   (defends against Burp-crafted totals).

## Reporting

Every finding needs both a **Steps to Reproduce** and a **Proof of Concept** —
these are the two non-negotiable parts. Format: Finding # / Severity / Vulnerability
Category (use an SL-level rating here, skip CVSS unless asked) / Description /
Technical Details / Steps to Reproduce / Proof of Concept / Impact / Remediation /
References. See `report-writing-template.md`.
