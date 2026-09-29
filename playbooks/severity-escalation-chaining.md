# Playbook: Severity Escalation & Chaining

The single most valuable bug-bounty habit: **never accept a low/no-impact finding
as the endpoint.** A P5/informational bug is a starting point. The money and the
real risk are in the *impact you can demonstrate*, alone or chained. Before
reporting anything low, ask: "what does this actually let an attacker DO, and what
does it become when combined with one more step?"

Worked example (Daher, P5→P5→P2, $1000+): a race condition on email-verification
alone = P5 (no impact). Same primitive with an XSS payload in the email field =
Self-XSS = still P5 (only the victim sees it). Same primitive with a **blind XSS**
payload, planted where an **admin** would view it (a profile field the admin panel
renders), caught out-of-band → stole the admin session → internal panel = **P2**.
Nothing changed but the *impact chain*.

## The escalation ladder (low finding → what to try next)

- **Self-XSS → Stored/Blind XSS → ATO.** Get the payload into a context a *staff/
  admin* renders (support ticket, contact form, username/profile, filename,
  User-Agent/Referer in logs). Confirm out-of-band; steal the session cookie.
- **Reflected XSS → ATO / CSP bypass.** Steal session, or pivot to actions in the
  victim's context.
- **Open redirect → OAuth token theft / SSRF / credible phishing.** Chase the
  `redirect_uri`/token leak, not just the redirect.
- **IDOR (read) → IDOR (write) → privilege escalation.** Read is Medium; write /
  role change / mass-assignment is High–Critical.
- **Info leak (verbose error, exposed `.git`, JS source map, `.env`) → creds/keys →
  auth bypass / RCE.** The leak is the key to the next door.
- **SSRF → cloud metadata → IAM creds → account compromise.** (see `ssrf`)
- **LFI → RCE** via log poisoning / PHP wrappers / `/proc`.
- **CSRF → state change → ATO** (change email/password on a no-CSRF-token endpoint).
- **Race condition → financial / account access** (double-spend, coupon reuse,
  verify-bypass; see `race-conditions`).
- **Unverified-email trust → admin features.** If you can register/verify as
  `email@company.com`, some apps grant internal/employee features on domain trust.

## Blind vulns: prove impact you can't see (OOB)

Self-XSS, blind XSS, blind SSRF/RCE/XXE look like nothing until you prove they fire
in someone else's context. The move: plant the payload where a privileged user or
backend processes it, and detect it **out-of-band**.
- c0mr4de: `oob_start` → get a callback domain → embed it in the payload (XSS
  `"><script src=//<oob>></script>`, or an SSRF/RCE probe) → `oob_poll` for the
  hit. A callback = confirmed blind vuln + evidence, even with no visible response.
- Plant spots for blind XSS: support/contact forms, ticket subjects, profile
  fields staff view, filenames, and any header logged into an admin dashboard.
- Then bait a privileged viewer (a report/thread that an admin must triage) so the
  payload executes in their session.

## Reporting the escalation

- Report the **maximum demonstrated impact**, not the primitive. "Race condition"
  earns P5; "admin account takeover via blind XSS chained from a verification race"
  earns P2. Same work, 10× reward.
- Show the full chain in the PoC: each step, the OOB callback / stolen cookie /
  privileged action, and what the attacker ultimately controls.
- Map the CVSS to the *chain's* end state (no-auth, confidentiality/integrity
  impact, scope change), not the first step. Tie to `exploit-validation` — a chain
  is only worth the top severity if you actually landed every link.
