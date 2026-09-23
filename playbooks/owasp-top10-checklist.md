# Playbook: OWASP Top 10 (2021) working checklist

General-purpose checklist for any web target, cross-referenced against tools
already wired into c0mr4de. Use `web-recon-methodology.md` first to map the
target, then work this list. Every category below maps to real findings from
past engagements where applicable — see the specific playbook for the deep dive.

## A01: Broken Access Control

- IDOR: enumerate object IDs (user, order, document, team) and test access as
  a different/lower-privileged account. Check both read AND write/update
  endpoints (PATCH/PUT/DELETE) — write-path IDOR is under-tested more often.
- Missing function-level access control: can a non-admin reach admin routes
  directly by URL, even if the UI hides the link?
- Client-trusted authorization: does the frontend receive `role`/`isAdmin`/
  `permissions` data and enforce it in JS, or does the server re-check on
  every request? See `jwt-client-side-bypass.md` — this exact pattern is how
  the Haveloc payment gate and M1rage's client-trusted-role concern both
  trace back to this category.
- CORS misconfiguration: reflected `Access-Control-Allow-Origin` with
  `Access-Control-Allow-Credentials: true`.
- Tools: `http_request` for manual IDOR probing, `ffuf`/`gobuster_dir` for
  discovering hidden admin routes.

## A02: Cryptographic Failures

- Sensitive data in localStorage/sessionStorage/cookies without protection
  (missing `Secure`/`HttpOnly` flags).
- Weak/predictable encryption: hardcoded IVs, keys embedded in the same
  bundle or token as the ciphertext, ECB mode, custom "encryption" that's
  really just encoding. See `jwt-client-side-bypass.md` for the exact chain
  that found this at Haveloc.
- Missing HSTS, mixed content, weak TLS config.
- Tools: `decode_jwt` for token inspection, `whatweb`/`http_request` for
  header checks.

## A03: Injection

- SQLi: any parameter that reaches a query — test with `sqlmap` after manual
  confirmation (single quote / boolean-based probe first to avoid noisy scans
  on obviously-safe endpoints).
- NoSQL injection: operator injection (`$gt`, `$ne`) in JSON bodies.
- Command injection: any feature that shells out (file conversion, ping/
  traceroute utilities, image processing).
- XSS: reflected/stored — check any user input that's rendered back, and
  confirm output encoding is actually applied.
- Tools: `sqlmap`, `http_request` for manual payload testing.

## A04: Insecure Design

- Missing rate limits on sensitive actions (login, password reset, flag
  submission, payment attempts) — and critically, confirm the limit is
  server-side (Redis/DB-backed), not just client-side UI cooldown.
- Business logic flaws: negative quantities, race conditions on
  balance/inventory changes (see `source-code-audit-checklist.md`, PINERP's
  `deliverSalesOrder` unbounded-delta bug).
- Race conditions: concurrent requests against balance-changing endpoints
  (double-spend/overdraw patterns).

## A05: Security Misconfiguration

- Verbose error messages leaking stack traces/internal paths.
- Default credentials still active (check seed/fixture data if source is
  available — PINERP shipped `admin`/`Demo@1234` across all seed users).
- Unnecessary exposed endpoints: `/api/health` leaking internal component
  status, debug endpoints left enabled, non-prod environments internet-
  reachable (pixstech: 7 CloudFront distributions, several non-prod).
- Missing security headers: CSP, X-Frame-Options, X-Content-Type-Options.
- Tools: `nikto` for a broad misconfiguration sweep, `whatweb` for stack ID.

## A06: Vulnerable and Outdated Components

- Fingerprint versions of frameworks/libraries/CMS and cross-check against
  known CVEs for that version.
- Tools: `whatweb`, `nmap -sV` for service version detection.

## A07: Identification and Authentication Failures

- User enumeration via distinguishable responses (401 vs 403 vs 423, or
  "N attempts remaining" text) — PINERP finding, low severity but cheap to
  check and often present.
- Missing/weak lockout on brute force.
- Session fixation, tokens not invalidated on logout/password change — see
  the "stateless JWT never revalidated" pattern in
  `source-code-audit-checklist.md`, the headline finding across multiple
  audits so far.
- Weak JWT secret validation (env checks that only require non-empty, not
  actual strength).

## A08: Software and Data Integrity Failures

- Unsigned/unverified auto-updates or deserialization of untrusted data.
- CI/CD pipeline integrity if in scope.

## A09: Security Logging and Monitoring Failures

- Test whether suspicious activity (repeated failed logins, tampered tokens)
  generates any alert/log the target owner would actually see. Hard to
  verify fully as an external tester; note as a gap if untestable.

## A10: Server-Side Request Forgery (SSRF)

- Any feature that fetches a URL server-side on the user's behalf (webhooks,
  "import from URL", PDF/screenshot generators, image proxies) — test with
  internal IPs (169.254.169.254 for cloud metadata, localhost, internal
  hostnames).

## Workflow

1. Recon first (`web-recon-methodology.md`) to know what's actually there.
2. Work this list top to bottom — A01 and A02 have found real critical bugs
   most often in past engagements, prioritize them when time is limited.
3. Every confirmed finding goes through `report-writing-template.md` before
   moving to the next category, not batched at the end — reduces the chance
   of losing detail on exactly how something was reproduced.
