# CTF: Misc, Jails & OSINT

The catch-all. Misc challenges reward reading the prompt precisely and noticing
the one constraint that matters.

## Jails / sandbox escapes
Given a restricted shell or a language sandbox; escape it or read the flag.
- **Python jail** (`eval`/`exec` with a blocklist): reach `os.system` without the
  banned words — `().__class__.__bases__[0].__subclasses__()` to find a useful
  class, `getattr`/`__builtins__` reconstruction, `breakpoint()`, f-string tricks,
  chr()-built strings to dodge keyword filters.
- **Bash/rbash jail:** `$IFS` for spaces, brace expansion, `${PATH:0:1}` to build
  chars, wildcards, `$'\x2f'`; env/`declare`/`compgen` to enumerate.
- **pyjail with no builtins:** rebuild from `__class__` traversal; audit exactly
  what's blocked and route around it.

## Scripting / logic / "guess the trick"
- A server that asks 1000 math questions in 5s -> automate with pwntools/httpx.
- Encoding chains, esolangs (Brainfuck/Whitespace/Piet), custom VMs -> write an
  interpreter or trace it.
- QR/data-matrix mosaics, "assemble the pieces," timing/side-channel oracles.

## CTF OSINT (find the real-world answer)
Same discipline as the parent OSINT playbooks, but the target is a puzzle:
- **Photo geolocation:** signage/language, road markings, plants, sun angle,
  license plates, architecture; reverse image search (Yandex is best for places),
  Google Lens; match landmarks in Google Earth/Street View.
- **Metadata:** exiftool for GPS coords, device, timestamps (challenge authors
  sometimes forget to strip them).
- **Person/handle pivot:** username_search across platforms (c0mr4de's osint
  tool), correlate a handle -> profiles -> posts -> the answer. Wayback Machine
  for deleted pages. This mirrors Roshan's own workflow: start from one selector
  (email/handle/image), enrich, correlate across sources.
- **Time/place from a post:** shadow direction + EXIF time, weather archives,
  flight/vessel trackers, geospatial guesswork confirmed on the map.

Verify against a primary source before committing — CTF OSINT rewards precision
(exact coords, exact name), and grep the flag format around whatever you find.
