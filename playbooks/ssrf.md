# Playbook: SSRF (Server-Side Request Forgery)

Any feature where the server fetches a URL you influence: webhooks, "import
from URL", PDF/screenshot/thumbnail generators, image proxies, URL preview,
avatar-by-URL, XML/SVG parsers, or an `?url=`/`?next=`/`?dest=` parameter.

## Detection

1. **Find the sink.** Grep the app / crawl (katana) for params that take a
   URL or hostname. Any request the server makes on your behalf is a candidate.
2. **Confirm out-of-band first** (this is what interactsh is for, and it catches
   BLIND SSRF that returns nothing):
   - `oob_start()` -> get a callback domain.
   - Put `http://<callback-domain>/x` in the URL param, send with http_request.
   - `oob_poll()` -> a DNS/HTTP callback = confirmed SSRF, even if the response
     body shows nothing. This is the strongest, most reliable proof.
3. **In-band signals:** different response time/size/error for internal vs
   external hosts; the fetched content reflected back.

## Escalation (once confirmed)

- **Cloud metadata** (highest impact): `http://169.254.169.254/latest/meta-data/`
  (AWS), `http://metadata.google.internal/computeMetadata/v1/` (GCP, needs
  `Metadata-Flavor: Google`), `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
  (Azure). Leaking IAM creds here is usually critical.
- **Internal services:** `http://localhost:PORT`, `http://127.0.0.1`, internal
  hostnames, `http://[::1]`, admin panels bound to localhost.
- **Protocol smuggling:** `file:///etc/passwd`, `gopher://` (can forge internal
  HTTP/Redis/SMTP), `dict://`.

## Filter bypasses (when localhost/metadata is blocked)

- Alternate IP encodings: `http://2130706433/` (decimal 127.0.0.1),
  `http://0177.0.0.1/`, `http://127.1/`, `http://0.0.0.0/`.
- DNS rebinding, `http://localhost.attacker.com` resolving to 127.0.0.1.
- Redirect: point the param at your server which 302-redirects to the internal
  target (many validators check the first URL only).
- `@` tricks: `http://expected.com@169.254.169.254/`.

## Report
Impact = what you reached (metadata creds > internal admin > port scan). PoC =
the exact URL + the OOB callback or the leaked internal response. Remediation:
allowlist destinations, resolve+validate the final IP (block RFC1918/link-local),
disable unused URL schemes, no raw redirects.
