# Playbook: nmap usage reference

## Standard workflow

1. **Fast first pass**: `-sV -T4 --top-ports 100` (the default `nmap` tool call
   in c0mr4de) — quick service/version fingerprint without a full 65535-port
   scan. Good enough to decide where to focus.
2. **Full port sweep if the fast pass looks incomplete**: `-p- -T4` (all ports,
   no version detection — faster, use when you suspect something's hiding on
   an unusual port).
3. **Targeted version + script scan on ports found interesting**:
   `-sV -sC -p <ports>` — `-sC` runs nmap's default script set (banner grabs,
   common misconfig checks) against just the ports that matter.
4. **UDP is easy to forget**: `-sU --top-ports 20` if the target might run
   DNS/SNMP/NTP services that a TCP-only scan will miss entirely.

## Reading the output

- **Open + versioned service** (`80/tcp open http Apache/2.4.41`) — cross-
  reference the version against known CVEs (see `owasp-top10-checklist.md`
  A06). Old Apache/nginx/PHP versions are a fast win if unpatched.
- **filtered vs closed**: `filtered` usually means a firewall is dropping
  packets (worth noting for the report — active filtering in place); `closed`
  means the port is reachable but nothing's listening there.
- **Unexpected open ports** (management interfaces, databases directly
  exposed like 3306/5432/6379/27017) are almost always worth a closer look —
  check if they're actually reachable without auth before reporting as a
  finding, don't just report "port open" as a vulnerability by itself.

## Common flags cheat-sheet

| Flag | Use |
|---|---|
| `-sV` | version detection |
| `-sC` | default script scan |
| `-T4` | faster timing (safe for most targets, avoid `-T5` on production) |
| `-Pn` | skip host discovery (use if ping is blocked but you know it's up) |
| `-p-` | all 65535 ports |
| `--top-ports N` | scan the N most common ports only |
| `-A` | aggressive (OS detection + version + scripts + traceroute) - noisy, use sparingly |

## Caution

Full `-p- -A` scans are slow and noisy — prefer the staged approach above
(fast pass -> targeted deep scan) both for speed on a 4GB-VRAM-constrained
local setup and to avoid unnecessary load on the target.
