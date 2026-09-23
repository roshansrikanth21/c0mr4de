# Playbook: OSINT - people & targets (public-source only)

For authorized investigations, CTF OSINT, and the operator's own workflow.
Public data only - do not target/harass/de-anonymize private individuals.

## From a single input (username / email / name / domain)

1. **Pivot on the username.** `username_search(handle)` enumerates ~20 platforms
   (GitHub, X, Reddit, HTB, TryHackMe, Keybase, ...). Every hit is a lead and a
   graph node.
2. **Cross-reference handles.** People reuse handles. A confirmed GitHub handle ->
   check the same on other platforms; a bio/README often links a second handle,
   a personal site, an email. Feed each new handle back into `username_search`.
3. **Dork for the rest.** `google_dork` with operators:
   - `"handle" site:github.com` / `site:pastebin.com` / `site:linkedin.com`
   - `intext:"email@domain"` , `filetype:pdf "name"` , `inurl:` for exposed paths
   - domain recon: `site:target.com -www` (subdomains), `filetype:env OR filetype:sql site:target.com`
4. **Record everything as you go.** Use `add_osint_note` for names, emails, phones,
   orgs, locations, domains you infer, linking each to the node it came from. The
   graph is only as good as what you log.
5. **Render the map.** `render_osint_graph` produces an interactive Maltego-style
   graph (color-coded by entity type) in the workspace - the deliverable.

## For a target (domain/org)

- Enumerate subdomains (dorking + `reconftw`/`subfinder` if available), map the
  tech stack, find exposed docs/repos/employees, then pivot people-OSINT on the
  employees found. Chain: org -> employee handles -> personal accounts -> exposure.

## Principles
- Confirm before asserting - a 200 on a profile URL means the handle exists, not
  that it's the same person. Note confidence.
- Breadth first (enumerate), then depth (verify the promising leads).
- The graph + a short written summary of the strongest links is the output.
