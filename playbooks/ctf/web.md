# CTF: Web

Same bug classes as the parent web playbooks (SQLi, IDOR, SSRF, XXE, SSTI,
deserialization, JWT) but compressed: the vuln is deliberately reachable and the
flag is the goal, not a report. Start here, then pull the specific parent playbook
once you've identified the class.

## First moves
1. **Source first.** View source, JS bundles, `/robots.txt`, `/sitemap.xml`,
   `.git/` (dump with git-dumper), `/.env`, source-map files (`.js.map` rebuild
   the original source), comments. Many web challenges leak the whole logic here.
2. **Recon the routes.** Crawl (katana) + directory brute (ffuf/gobuster) for
   `/admin`, `/debug`, `/api`, backup files (`index.php.bak`, `~`, `.swp`).
3. **Cookies/JWT/session.** decode_jwt every token; check `alg:none`, weak HMAC
   secret (crack with the wordlist), tamper claims (tamper_jwt). Client-side
   trust bugs are a CTF staple.

## Common CTF web bug menu (map the challenge to one)
- **SQLi** -> auth bypass `' OR 1=1 -- `, UNION to dump, blind boolean/time; flag
  usually in a `users`/`flag`/`secret` table. sqlmap for grind, hand-craft for WAF.
- **SSTI** -> `{{7*7}}`, escalate to file read / RCE (see parent `deserialization-ssti`).
- **NoSQLi** -> `{"$ne":null}`, `{"$gt":""}` for Mongo auth bypass.
- **LFI/RCE** -> `php://filter/convert.base64-encode/resource=index.php` to read
  source, log poisoning / `data://` / wrappers to execute; `/proc/self/environ`.
- **SSRF** -> reach an internal `/flag` service or metadata (parent `ssrf`).
- **Command injection** -> `;id`, `$(cat /flag)`, blind via OOB (parent tools).
- **Prototype pollution / Node** -> `__proto__` in JSON to flip an auth check.
- **Race** -> concurrent requests for a one-time buy/redeem (parent `race-conditions`).
- **XSS** -> only matters if there's a bot/admin visiting your input; steal the
  admin cookie/flag via your listener. Otherwise it's a rabbit hole.

## After every step
Grep the response, decoded blobs, and any file you pull for the flag format.
The flag is often sitting in `/flag`, `/flag.txt`, an env var, or a DB column
called `flag`.
