# Playbook: Web target recon methodology

Distilled from the pixstech.com VA and M1rage platform pentest — the recon pattern
that consistently surfaced the real attack surface before any active testing.

## Order of operations

1. **Map the infra first, don't just scan the one hostname you were given.**
   - Enumerate subdomains and look for non-prod/staging/dev distributions — pixstech
     had 7 separate CloudFront distributions (www, dev, test, fire, dev.fire, behind,
     mirror.behind) and the non-prod ones were a finding by themselves (F-05).
   - Identify the actual backend (API Gateway, direct origin, etc.) separately from
     the CDN/WAF-fronted parts — WAF often only covers the main web tier, not the API
     or storage layer. M1rage's origin had **no WAF at all** in front of it despite
     the marketing site being Cloudflare-fronted; pixstech's S3+API Gateway were
     reachable even though CloudFront was WAF-protected.
   - Identify auth/identity provider (Entra/M365, Auth0, custom) and mail setup
     (SPF/DMARC) — cheap to check, catches real findings (pixstech: missing DMARC).

2. **Fingerprint the stack** (`whatweb`, response headers, `/api/health` or similar
   endpoints) before guessing. M1rage's `/api/health` leaked `{database:ok, redis:ok}`
   — free infra info from an unauthenticated endpoint.

3. **Check security headers as a baseline, not the goal.** CSP, X-Frame-Options,
   HSTS, source-map exposure. A tight header posture (like M1rage's) is a signal to
   stop looking for XSS/clickjacking and focus effort on **server-side authorization
   logic** instead — that's where the real bugs were.

4. **Map the actual mutation surface.** Don't assume REST — check for framework-
   specific patterns (M1rage used Next.js Server Actions via the `Next-Action` header,
   with no REST route for login/register at all). Look at:
   - Which endpoints allow which HTTP methods (`OPTIONS` on an API route often
     leaks the full allowed-methods list unauthenticated).
   - Whether IDs are sequential/enumerable or opaque (CUIDs, UUIDs) — this changes
     whether IDOR is even worth testing.

5. **List priority targets before touching anything active:**
   - Any separate admin panel/login (`/admin`, `/admin/login`) — test default creds,
     whether client-trusted role/permission data is actually server-enforced.
   - Endpoints allowing write methods (PATCH/POST) without a corresponding GET —
     often under-tested, good IDOR candidates.
   - Rate limits on sensitive actions (flag submission, login) — confirm they're
     server-side (Redis/DB-backed), not just client-side cooldown UI.
   - Any object fetchable by ID before it should be visible (hidden/unpublished
     content, other users' data).

6. **If you re-test a target later, diff against your last report.** M1rage's
   09-01 re-check found they'd patched the `/api/health` leak, hidden `/admin` from
   anon (404 instead of redirect-to-login), and closed the OPTIONS method-enumeration
   leak — tracking that diff is what shows real remediation vs. cosmetic changes.

## Constraints to respect

- Never create accounts or enter credentials as the agent itself — authenticated
  testing needs the operator's own session/cookie, provided explicitly.
- Only operate within the scope the operator names for this session.
