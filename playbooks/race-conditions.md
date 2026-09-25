# Playbook: Race Conditions (TOCTOU)

A check and the action it guards are not atomic, so N requests fired together all
pass the check before any of them commits. Classic money/logic bugs:
- Redeem one coupon/gift card N times.
- Withdraw/transfer more than the balance.
- Use a one-time OTP/token more than once.
- Exceed a "one per user" limit (votes, signups, claims, rate limits).
- Over-book / over-sell limited inventory.

## Detect
1. Find a **limited action** that reads state, decides, then writes: balance
   checks, "used" flags, quotas, stock counts.
2. Fire many identical requests **concurrently** (not sequentially — concurrency
   is the whole point). Minimal harness:
   ```python
   import asyncio, httpx
   async def hit(c): return (await c.post(URL, json=BODY, headers=H)).status_code
   async def main():
       async with httpx.AsyncClient() as c:
           print(await asyncio.gather(*[hit(c) for _ in range(30)]))
   asyncio.run(main())
   ```
   (c0mr4de's write_script tool can generate and run exactly this.) For HTTP/2
   targets, a single-packet burst is even tighter, but concurrent asyncio is
   enough to prove most web races.
3. **Confirm the overshoot in state, not the responses:** did the balance go
   negative? coupon apply twice? counter exceed the cap? The proof is the
   inconsistent end state, e.g. 5 "success" responses for a one-time action.

## Notes
- Send in-flight before the first commit; local concurrency to a remote host is
  usually sufficient — you don't need special tooling for the common cases.
- Keep the burst modest on live targets — enough to prove it, not to disrupt.
  Confirm the action is refundable/reversible before firing.

## Report
Show N concurrent requests all succeeding + the impossible resulting state (e.g.
balance -₹400, coupon counted twice). Remediation: atomic DB operations /
`SELECT ... FOR UPDATE` / unique constraints / idempotency keys, not a
read-then-write check.
