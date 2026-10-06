# Playbook: File Inclusion (LFI / RFI) and Path Traversal

App builds a file path from input: `?page=`, `?file=`, `?template=`, `?lang=`,
`?download=`. LFI includes a local file (often -> RCE), RFI includes a remote URL
(needs `allow_url_include`), path traversal reads arbitrary files.

## Detection

1. Traversal probe: `?file=../../../../etc/passwd` (Linux),
   `..\..\..\windows\win.ini` (Windows). `root:x:0:0` in the body = confirmed read.
2. Defeat a `.php` suffix append: `php://filter`, path truncation, legacy `%00`.
3. Status-aware; confirm with the actual file contents as PoC.

## Exploitation

- Read source/creds: `?page=php://filter/convert.base64-encode/resource=config`
  (decode the base64), plus `/etc/passwd`, app `.env`, `/proc/self/environ`, SSH keys.
- **LFI -> RCE:** log poisoning (inject PHP via User-Agent into a log, then include
  it), PHP wrappers (`data://`, `php://input`, `expect://`), session files, or
  upload+include a webshell.

## Bypass

`../` stripped once -> `....//`; double-URL-encode `%252e%252e%252f`; overlong UTF-8;
absolute paths; `php://filter` past extension allow-lists.

## Report

PoC = contents of a file that should be unreadable (`/etc/passwd`, `.env`). Read =
High, LFI->RCE = Critical. Escalate to RCE only against an authorized target.

## Remediation

Map requests to an allow-list of IDs -> server-side filenames; never pass input to
file APIs. Canonicalize and verify the resolved path stays under an allowed base
dir. Disable `allow_url_include`/`allow_url_fopen`.
