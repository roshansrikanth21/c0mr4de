# Playbook: Cross-Site Scripting (XSS)

Reflected (payload echoed in the response), stored (saved then served to others),
DOM (client JS writes input into a sink). Look at every reflected param, saved
field (comments, profile, filename), and client-side sinks (`innerHTML`,
`document.write`, `eval`, `location`).

## Detection (execution-confirmed, not reflection)

1. Inject a unique marker into each field; find where it reflects and in what
   context (HTML body / attribute / JS string / URL).
2. **Content-Type gate:** a payload reflected in a `application/json` or
   `text/plain` response is NOT XSS - the browser won't parse it as HTML. Skip it.
3. **Confirm execution in a real browser, not a string match:** load the payload
   with `confirm_xss_exec` (headless browser) and count it only when injected JS
   actually runs (sets `window.<flag>`). Reflection alone is a lead, not a finding.

## Context -> payload

- HTML body: `"><img src=x onerror=window.__c0mr4de_xss_exec7=1>`
- Attribute: break out `">` then a tag, or use an event handler in-place.
- JS string: close the quote/string, inject, rebalance.
- DOM: trace source->sink; payload depends on the sink (fragment, postMessage).

## Escalation

Cookie exfil (non-HttpOnly), session-riding an internal admin endpoint, BXSS into
fields an admin later views (tickets, UA logs, filenames) with a callback payload.

## Bypass

Case, no-paren (`onerror=alert\`1\``), HTML/URL/unicode encoding, auto-fixed broken
tags, alternate events (`onfocus autofocus`, `onanimationend`), SVG/MathML.

## Report

PoC = execution proof (controlled callback / `window` flag), not reflection.
Stored/BXSS High-Critical, reflected Medium-High. `verified: true` only when
`confirm_xss_exec` fired.

## Remediation

Context-aware output encoding; CSP without `unsafe-inline`; HttpOnly+Secure cookies;
DOMPurify for rich text; `textContent` over `innerHTML`.
