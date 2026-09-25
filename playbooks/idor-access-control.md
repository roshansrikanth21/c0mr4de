# Playbook: IDOR & Broken Access Control

The most common high-impact web bug and the easiest to under-test. Two flavors:
- **IDOR (object level):** you can read/modify another user's object by changing
  an identifier (`/api/orders/1041` -> `1042`, `?user_id=`, a filename, a UUID).
- **Function/endpoint level:** a low-priv user reaches an admin action because the
  UI hides it but the server doesn't check the role.

This is exactly the class the Haveloc payment-gate audit lived in — the server
trusted a client-controlled value it should have verified server-side.

## Method (needs at least one authenticated session; two is ideal)

1. **Map objects and their IDs.** Crawl authenticated (katana with the session
   cookie via `auth.set_auth`), log every endpoint that takes an id/param into
   the worklog. Note the ID type: sequential int (trivial), UUID (needs a leak),
   hash, or composite.
2. **Two-account test (gold standard):** as user A, note an object id. As user B
   (different session), request A's object. Read = leak; write/delete = worse.
   With one account: create two objects, try to cross-access.
3. **Force-browse function-level:** take an admin/privileged request (from Burp
   import or observed traffic) and replay it with a low-priv session. If it works,
   that's a vertical access-control break.
4. **Parameter angles:** flip `?admin=false`->`true`, add `?user_id=` where the
   server might trust it, tamper JWT/role claims (`tamper_jwt`) and see if the
   server re-verifies, try mass-assignment (`"role":"admin"` in a JSON body the
   API doesn't expect you to control).

## What raises severity
- Sequential IDs (enumerable at scale) > unguessable ones.
- Write/delete > read. PII/financial/payment objects > cosmetic.
- No rate limit on enumeration = full-table exfiltration PoC.

## Report
Show the exact two requests (yours vs. the victim object) and the differing
response. Quantify: "IDs are sequential 1..N, so all M records are enumerable."
Remediation: enforce object ownership server-side on every request; deny-by-default
on privileged functions; don't rely on unguessable IDs as the only control.
