# Playbook: email-first OSINT workflow (operator's flow)

The operator's people-OSINT method, codified. Public sources only, for
authorized investigation / CTF. Follow this order.

## The flow: email → behind-the-email → seed → correlate → graph

1. **Start from the email — go "behind the email" first.** `email_osint(email)`
   (Holehe) reveals which platforms/services the email is *registered on*,
   non-intrusively. This is the first move: it tells you where the person
   exists before you know anything else. Every hit is a lead and a graph node
   linked to the email.

2. **Seed everything you already know.** Put all known facts about the person
   into the graph up front with `add_osint_note` — name, phone, other emails,
   employer, location, known handles. These become anchor nodes to correlate
   against. (Don't wait until the end; seed first so later hits can link to them.)

3. **Derive and pivot on usernames.** From the email local-part and the
   registered sites, infer likely handles and run `username_search(handle)`
   across ~20 platforms. People reuse handles — a confirmed one on GitHub often
   links a personal site, a second handle, or another email in the bio/README.
   Feed every new handle back into `username_search`.

4. **Dork the gaps.** `google_dork` the email and each handle with operators:
   `"email" site:pastebin.com`, `"handle" site:github.com`, `intext:"email"`,
   `filetype:pdf "full name"`. Pull in anything the enumeration missed.

5. **Correlate.** As facts come in, link them with `add_osint_note` — every
   node tied to the node it came from with the relationship. The correlation
   IS the graph: email → registered accounts → usernames → profiles → real
   name / employer / location, with the strongest links standing out.

6. **Render the map.** `render_osint_graph` produces the interactive Maltego-
   style graph (color-coded, searchable) — the deliverable. Then write a short
   summary of the strongest correlations.

## Principles
- Breadth first (enumerate where they exist), then depth (verify the leads).
- Confirm before asserting — a hit means an account exists, not that it's the
  same person; note confidence and corroborate across ≥2 sources.
- The graph + a short written summary of the strongest links is the output.
