# Playbook: JWT / client-side authorization bypass

Distilled from the Haveloc payment-gate audit (placements.haveloc.com, 2026-09-18) —
the exact chain that found a critical payment bypass.

## When to use this

Any time you see a JWT, encoded token, or auth state stored in `localStorage`,
`sessionStorage`, or a cookie — especially when the app gates a *feature or payment
status* (not just login) behind that token.

## The chain, step by step

1. **Find the token.** Check `localStorage`/`sessionStorage` keys and cookies for
   anything JWT-shaped (`xxx.yyy.zzz`) or that looks encoded/encrypted.
2. **Decode it — don't assume it's opaque.** Use `decode_jwt`. Look at every field
   in the payload, not just the obvious ones. In Haveloc, the payload had `acs`
   ("Un Paid"/"Active"), `ut`, `pm`, `paymentEligible` — plain-text status flags
   sitting right there.
3. **Check if "encryption" is real.** If the token isn't a standard JWT but looks
   encrypted (e.g., AES), look for:
   - A hardcoded/fixed IV (grep the JS bundle for suspicious 16-byte constants).
   - The decryption key shipped in the same JS bundle, or worse, embedded in the
     token itself at a fixed offset. Haveloc had both — hardcoded IV `1234567812345678`
     and the AES key sliced out of the token at a fixed position.
4. **Test whether the server actually verifies it.** This is the step that turns
   "interesting" into "critical": use the `tamper_jwt` tool to flip a field
   (e.g., `field="acs", value="Active"`) — it keeps the original signature so you're
   directly testing whether the server verifies it — then replay the returned token
   with `http_request` (send it as `Authorization: Bearer <tampered>`). Do NOT
   hand-write JWT crypto in a code block; call `tamper_jwt`. If the server accepts the
   modified token, there is no server-side signature/authorization check — CWE-345
   (no verification) and usually CWE-602 (client-side enforcement of a security
   decision).
5. **Check cookie flags while you're in there.** Missing `Secure` on an auth cookie,
   missing `HttpOnly` on anything readable by JS — both showed up in Haveloc as
   secondary findings, cheap to check once you're already looking at the token.
6. **State the concrete impact.** Not "the token can be modified" — say what an
   attacker gets: e.g. "any registered user can flip their own payment status to
   Active without paying, bypassing the entire payment gate."

## Common variants to also check

- Permission/role bit-flags in the same token (Haveloc had a `ps` field for feature
  permissions, same client-side-only enforcement pattern).
- Whether the server checks auth *and* authorization, or just auth — Haveloc's API
  validated the user was logged in but not whether they'd actually paid.

## What this does NOT tell you

Decoding a token proves nothing by itself — the finding only exists once you've
replayed a *modified* token and confirmed the server accepted it. Don't report
"the JWT is not encrypted properly" as the finding; report the access you actually
gained.
