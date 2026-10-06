"""OSINT - username enumeration, search-engine dorking, and a shared entity
graph the agent builds up across a session (Maltego-style). Public-source
aggregation only, for authorized security research / CTF / the operator's
own OSINT workflow.

Ethics: this queries PUBLIC data (does a profile URL exist, public search
results). It is for authorized investigations and education. Do not use it
to target, harass, or de-anonymize private individuals.
"""
from __future__ import annotations

import re
import urllib.parse

import httpx

from c0mr4de.tools.base import Tool

# Shared graph the OSINT tools populate as they discover things.
# nodes: {id: {type, label}}, edges: [(src, dst, label)]
_GRAPH = {"nodes": {}, "edges": []}


def _add_node(node_id: str, ntype: str, label: str | None = None):
    _GRAPH["nodes"].setdefault(node_id, {"type": ntype, "label": label or node_id})


def _add_edge(src: str, dst: str, label: str = ""):
    if (src, dst, label) not in _GRAPH["edges"]:
        _GRAPH["edges"].append((src, dst, label))


# username -> profile URL template. Compact, high-signal set (Sherlock-style).
_SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Twitter/X": "https://x.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Reddit": "https://www.reddit.com/user/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Medium": "https://medium.com/@{}",
    "DevTo": "https://dev.to/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Keybase": "https://keybase.io/{}",
    "Telegram": "https://t.me/{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "SoundCloud": "https://soundcloud.com/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Replit": "https://replit.com/@{}",
    "HackTheBox": "https://app.hackthebox.com/users/{}",
    "TryHackMe": "https://tryhackme.com/p/{}",
    "Patreon": "https://www.patreon.com/{}",
}

_UA = {"User-Agent": "Mozilla/5.0 (compatible; c0mr4de-osint/1.0)"}


def username_search(username: str) -> str:
    """Check a username across popular platforms and add hits to the graph."""
    _add_node(f"user:{username}", "username", username)
    found, missing = [], 0
    with httpx.Client(timeout=8, headers=_UA, follow_redirects=True) as c:
        for site, tmpl in _SITES.items():
            url = tmpl.format(urllib.parse.quote(username))
            try:
                r = c.get(url)
                exists = r.status_code == 200 and "not found" not in r.text[:2000].lower()
            except httpx.HTTPError:
                exists = False
            if exists:
                found.append(f"  [+] {site}: {url}")
                node = f"profile:{site}:{username}"
                _add_node(node, "profile", f"{site}: {username}")
                _add_edge(f"user:{username}", node, "has profile")
            else:
                missing += 1
    return (
        f"username '{username}' - {len(found)} profiles found, {missing} not present:\n"
        + ("\n".join(found) if found else "  (none found)")
        + "\nPivot: reuse a confirmed handle to find linked accounts, then render_osint_graph."
    )


def google_dork(query: str) -> str:
    """Run a search query (supports dork operators: site:, inurl:, filetype:,
    intitle:, "exact"). Uses DuckDuckGo's HTML endpoint - no API key."""
    try:
        r = httpx.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query},
            headers=_UA,
            timeout=12,
        )
    except httpx.HTTPError as exc:
        return f"search error: {exc}"
    # extract result links + titles
    results = re.findall(r'result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', r.text, re.DOTALL)
    if not results:
        return f"no results for: {query} (or the endpoint changed layout)"
    out = [f"results for `{query}`:"]
    for url, title in results[:12]:
        clean_title = re.sub(r"<[^>]+>", "", title).strip()
        # DDG wraps target in a redirect; pull uddg param if present
        m = re.search(r"uddg=([^&]+)", url)
        real = urllib.parse.unquote(m.group(1)) if m else url
        out.append(f"  - {clean_title}\n    {real}")
        _add_node(f"url:{real}", "url", clean_title[:40] or real)
    return "\n".join(out)


def add_osint_note(entity: str, entity_type: str, linked_to: str = "", relation: str = "") -> str:
    """Manually add an entity/relationship to the graph (a name, email, phone,
    org, location the agent inferred) so the final graph is complete."""
    _add_node(f"{entity_type}:{entity}", entity_type, entity)
    if linked_to:
        _add_edge(linked_to, f"{entity_type}:{entity}", relation or "linked")
    return f"added {entity_type} '{entity}' to the graph" + (f", linked to {linked_to}" if linked_to else "")


# Luminous entity palette - jewel tones that glow on a deep warm-black stage.
_PALETTE = {
    "username": "#5eead4", "profile": "#7dd3fc", "url": "#c4b5fd", "email": "#fbbf24",
    "name": "#fca5a5", "phone": "#f9a8d4", "org": "#6ee7b7", "location": "#fcd34d", "domain": "#67e8f9",
}

_GRAPH_HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>c0mr4de · OSINT</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/dist/vis-network.min.js"></script>
<style>
 :root{{--amber:#e6a94e;--ink:#f2ede3;--soft:#a79e8d;--faint:#6f6858;--stage:#0b0a08;}}
 *{{box-sizing:border-box}}
 html,body{{height:100%}}
 body{{margin:0;background:var(--stage);color:var(--ink);
   font-family:"IBM Plex Mono",ui-monospace,Consolas,monospace;overflow:hidden}}
 /* deep stage: warm-black base + two drifting blooms + grain + vignette */
 .bloom{{position:fixed;border-radius:50%;filter:blur(80px);opacity:.5;pointer-events:none;z-index:0}}
 #b1{{width:60vw;height:60vw;left:-10vw;top:-18vw;
   background:radial-gradient(circle,rgba(230,169,78,.42),transparent 62%);animation:drift1 26s ease-in-out infinite}}
 #b2{{width:52vw;height:52vw;right:-14vw;bottom:-20vw;
   background:radial-gradient(circle,rgba(94,234,212,.24),transparent 62%);animation:drift2 32s ease-in-out infinite}}
 @keyframes drift1{{0%,100%{{transform:translate(0,0)}}50%{{transform:translate(6vw,4vw)}}}}
 @keyframes drift2{{0%,100%{{transform:translate(0,0)}}50%{{transform:translate(-5vw,-4vw)}}}}
 #grain{{position:fixed;inset:0;z-index:2;pointer-events:none;opacity:.05;mix-blend-mode:overlay;
   background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='2'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}}
 #vig{{position:fixed;inset:0;z-index:2;pointer-events:none;
   background:radial-gradient(120% 120% at 50% 42%,transparent 55%,rgba(0,0,0,.55) 100%)}}
 #h{{position:relative;z-index:3;padding:20px 26px 14px;display:flex;align-items:flex-end;
   justify-content:space-between;gap:16px}}
 #h .eyebrow{{font-size:11px;letter-spacing:.34em;text-transform:uppercase;color:var(--amber);opacity:.85}}
 #h h1{{margin:2px 0 0;font-family:"Instrument Serif",Georgia,serif;font-weight:400;
   font-size:34px;letter-spacing:.01em;line-height:1;color:var(--ink)}}
 #h h1 em{{font-style:italic;color:var(--amber)}}
 #h .stat{{text-align:right;font-size:11px;color:var(--soft);line-height:1.7}}
 #h .stat b{{color:var(--ink);font-weight:500}}
 #wrap{{position:relative;z-index:1}}
 #net{{width:100vw;height:calc(100vh - 78px)}}
 .glass{{background:rgba(20,17,12,.55);border:1px solid rgba(230,169,78,.16);border-radius:12px;
   backdrop-filter:blur(10px);box-shadow:0 8px 30px rgba(0,0,0,.45)}}
 #legend{{position:absolute;top:14px;right:16px;z-index:4;padding:12px 14px;font-size:11px}}
 #legend .cap{{color:var(--faint);letter-spacing:.18em;text-transform:uppercase;font-size:9.5px;margin-bottom:7px}}
 #legend .row{{display:flex;align-items:center;gap:8px;margin:5px 0;color:var(--soft)}}
 #legend .dot{{width:9px;height:9px;border-radius:50%;display:inline-block}}
 #search{{position:absolute;top:14px;left:16px;z-index:4;color:var(--ink);padding:9px 13px;
   font-family:inherit;font-size:12px;width:210px}}
 #search::placeholder{{color:var(--faint)}}
 #search:focus{{outline:none;border-color:rgba(230,169,78,.55);box-shadow:0 0 0 3px rgba(230,169,78,.12)}}
 #hint{{position:absolute;bottom:14px;left:16px;z-index:4;font-size:10.5px;color:var(--faint);letter-spacing:.04em}}
 @media (prefers-reduced-motion:reduce){{.bloom{{animation:none}}}}
</style></head><body>
<div class="bloom" id="b1"></div><div class="bloom" id="b2"></div>
<div id="grain"></div><div id="vig"></div>
<header id="h">
 <div><div class="eyebrow">c0mr4de · osint intelligence</div><h1>Entity <em>Graph</em></h1></div>
 <div class="stat"><b>{n}</b> entities&nbsp;&nbsp;·&nbsp;&nbsp;<b>{e}</b> links<br>drag to explore · scroll to zoom</div>
</header>
<div id="wrap">
 <input id="search" class="glass" placeholder="find a node…"/>
 <div id="legend" class="glass"><div class="cap">entities</div>{legend}</div>
 <div id="net"></div>
 <div id="hint">click a node to focus · hover for detail</div>
</div>
<script>
const COLORS={{username:'#5eead4',profile:'#7dd3fc',url:'#c4b5fd',email:'#fbbf24',name:'#fca5a5',phone:'#f9a8d4',org:'#6ee7b7',location:'#fcd34d',domain:'#67e8f9'}};
const nodes=new vis.DataSet({nodes});
const edges=new vis.DataSet({edges});
nodes.forEach(nd=>{{const c=COLORS[nd.group]||'#a8b0bd';nodes.update({{id:nd.id,
  color:{{background:c,border:'rgba(11,10,8,.85)',highlight:{{background:'#fff8ea',border:c}},hover:{{background:c,border:'#fff8ea'}}}},
  shadow:{{enabled:true,color:c,size:20,x:0,y:0}},
  font:{{color:'#efe8da',size:13,face:'IBM Plex Mono',strokeWidth:0,vadjust:2}}}});}});
const net=new vis.Network(document.getElementById('net'),{{nodes,edges}},{{
 nodes:{{shape:'dot',borderWidth:1.5,scaling:{{min:9,max:46,label:{{min:12,max:22}}}}}},
 edges:{{color:{{color:'rgba(167,158,141,.22)',highlight:'#e6a94e',hover:'rgba(230,169,78,.6)'}},
   arrows:{{to:{{enabled:true,scaleFactor:0.42}}}},smooth:{{type:'cubicBezier',roundness:0.55}},
   font:{{color:'#8a8272',size:9.5,strokeWidth:0,align:'middle'}},width:1,hoverWidth:1.6,selectionWidth:2}},
 physics:{{stabilization:{{iterations:240}},barnesHut:{{gravitationalConstant:-14000,springLength:165,springConstant:0.035,damping:0.55,avoidOverlap:0.2}}}},
 interaction:{{hover:true,tooltipDelay:110,navigationButtons:false}}
}});
// redraw once the webfont lands so canvas labels use IBM Plex Mono
if(document.fonts&&document.fonts.ready){{document.fonts.ready.then(()=>net.redraw());}}
document.getElementById('search').addEventListener('keydown',e=>{{
 if(e.key!=='Enter')return; const q=e.target.value.toLowerCase(); if(!q)return;
 const hit=nodes.get().find(n=>(n.label||'').toLowerCase().includes(q)||(''+n.id).toLowerCase().includes(q));
 if(hit){{net.focus(hit.id,{{scale:1.35,animation:{{duration:600,easingFunction:'easeInOutCubic'}}}});net.selectNodes([hit.id]);}}
}});
</script></body></html>"""


def _legend_html(types_present) -> str:
    labels = {
        "username": "username", "profile": "profile", "url": "url / page", "email": "email",
        "name": "name", "phone": "phone", "org": "org", "location": "location", "domain": "domain",
    }
    rows = [
        f'<div class="row"><span class="dot" style="background:{_PALETTE.get(t, "#a8b0bd")};'
        f'box-shadow:0 0 8px {_PALETTE.get(t, "#a8b0bd")}"></span>{labels.get(t, t)}</div>'
        for t in labels if t in types_present
    ]
    return "".join(rows) or '<div class="row">no entities yet</div>'


def render_osint_graph(name: str = "osint_graph.html") -> str:
    """Render the accumulated OSINT graph as an interactive Maltego-style
    HTML file (open it in a browser). Call this at the end of an investigation."""
    import json as _json

    from c0mr4de.tools.files import WORKSPACE

    if not _GRAPH["nodes"]:
        return "graph is empty - run username_search / google_dork / add_osint_note first."
    # node size scales with degree (hubs render bigger) via vis "value"
    degree: dict[str, int] = {}
    for s, d, _ in _GRAPH["edges"]:
        degree[s] = degree.get(s, 0) + 1
        degree[d] = degree.get(d, 0) + 1
    nodes = [
        {"id": nid, "label": meta["label"], "group": meta["type"], "value": degree.get(nid, 1)}
        for nid, meta in _GRAPH["nodes"].items()
    ]
    edges = [{"from": s, "to": d, "label": lbl} for s, d, lbl in _GRAPH["edges"]]
    types_present = {meta["type"] for meta in _GRAPH["nodes"].values()}
    html = _GRAPH_HTML.format(
        n=len(nodes), e=len(edges), nodes=_json.dumps(nodes), edges=_json.dumps(edges),
        legend=_legend_html(types_present),
    )
    dest = WORKSPACE / "osint"
    dest.mkdir(parents=True, exist_ok=True)
    safe = "".join(c for c in name if c.isalnum() or c in "._-") or "osint_graph.html"
    (dest / safe).write_text(html, encoding="utf-8")
    return f"OSINT graph rendered: workspace/osint/{safe} ({len(nodes)} nodes, {len(edges)} edges). Open it in a browser."


TOOLS = [
    Tool(
        name="render_osint_graph",
        description="Render the accumulated OSINT entities/links as an interactive Maltego-style graph (HTML). Call at the end of a people/target investigation.",
        parameters={"type": "object", "properties": {"name": {"type": "string"}}, "required": []},
        fn=render_osint_graph,
    ),
    Tool(
        name="username_search",
        description="Enumerate a username across ~20 platforms (GitHub, X, Reddit, HTB, TryHackMe, ...) and record found profiles in the OSINT graph. The core pivot for people-OSINT.",
        parameters={"type": "object", "properties": {"username": {"type": "string"}}, "required": ["username"]},
        fn=username_search,
    ),
    Tool(
        name="google_dork",
        description="Run a search-engine query, including dork operators (site:, inurl:, filetype:, intitle:, quotes). Use for discovering exposed files, subdomains, profiles, leaked data references.",
        parameters={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        fn=google_dork,
    ),
    Tool(
        name="add_osint_note",
        description="Add an inferred entity (name/email/phone/org/location) and its link to the OSINT graph, so the final Maltego-style graph captures everything you found.",
        parameters={
            "type": "object",
            "properties": {
                "entity": {"type": "string"},
                "entity_type": {"type": "string", "description": "name, email, phone, org, location, domain, ..."},
                "linked_to": {"type": "string", "description": "an existing node id to link from, e.g. user:handle"},
                "relation": {"type": "string"},
            },
            "required": ["entity", "entity_type"],
        },
        fn=add_osint_note,
    ),
]
