# CTF Playbooks

Category methodology for capture-the-flag, distinct from the client-pentest
playbooks in the parent directory. CTF differs from real engagements in ways that
change the approach:

- **A flag exists and is findable.** Every challenge is solvable by design, so
  "I found nothing" almost always means wrong angle, not hardened target. Keep
  pivoting. (Real pentest: clean is a valid result — don't fabricate.)
- **Format is a signal.** Flags match a known regex (`FLAG{...}`, `HTB{...}`,
  `picoCTF{...}`, and for Roshan's own CTFs `MIRAGE{...}`). Grep for the format
  everywhere — memory, files, network, decoded blobs.
- **Scope is the challenge box only.** No rules-of-engagement doc; the target is
  whatever the challenge hands you. Don't touch platform infra.
- **Intended path.** Point values and category hint at difficulty and technique.
  A 500-pt crypto is not solved by the same move as a 50-pt one.

## Categories
- [`web.md`](web.md) — web exploitation (overlaps parent playbooks, CTF-flavored)
- [`crypto.md`](crypto.md) — classical + modern crypto, common CTF weaknesses
- [`forensics.md`](forensics.md) — files, memory, network, stego, disk
- [`reversing.md`](reversing.md) — static + dynamic RE, unpacking, keygens
- [`pwn.md`](pwn.md) — binary exploitation / memory corruption
- [`misc-osint.md`](misc-osint.md) — misc, jail escapes, and CTF OSINT

## General loop
1. Read the prompt + point value; download and `file`/`strings`/`binwalk` every
   artifact before theorizing.
2. Identify category (may be mislabeled on purpose) and the likely intended bug.
3. Pull the matching category playbook via `consult_knowledge`.
4. Work the checklist; grep for the flag format after every transform.
5. Save what worked to the worklog — CTF techniques recur across events.

> Roshan authors CTFs too (MIRAGE, the OSINT/CTF seminar kit). These playbooks
> double as a design reference: if a category's checklist solves your challenge in
> one obvious step, it's probably too easy.
