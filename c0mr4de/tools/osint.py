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


_GRAPH_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"/>
<title>c0mr4de OSINT graph</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/dist/vis-network.min.js"></script>
<style>
 body{{margin:0;background:#0a0c10;color:#d7dce5;font-family:ui-monospace,Consolas,monospace}}
 #h{{padding:12px 18px;border-bottom:1px solid #232936}} #h b{{color:#4ade80;letter-spacing:1px}}
 #net{{width:100vw;height:calc(100vh - 48px)}}
</style></head><body>
<div id="h"><b>c0mr4de</b> · OSINT graph · {n} entities, {e} links</div>
<div id="net"></div>
<script>
const nodes=new vis.DataSet({nodes});
const edges=new vis.DataSet({edges});
const colors={{username:'#4ade80',profile:'#60a5fa',url:'#a78bfa',email:'#f59e0b',name:'#f87171',phone:'#f472b6',org:'#34d399',location:'#fbbf24',domain:'#22d3ee'}};
nodes.forEach(nd=>nodes.update({{id:nd.id,color:{{background:colors[nd.group]||'#94a3b8',border:'#1f2937'}},font:{{color:'#d7dce5'}}}}));
new vis.Network(document.getElementById('net'),{{nodes,edges}},{{
 nodes:{{shape:'dot',size:16,borderWidth:2}},
 edges:{{color:'#334155',arrows:'to',font:{{color:'#7b8494',size:10,strokeWidth:0}}}},
 physics:{{stabilization:true,barnesHut:{{gravitationalConstant:-8000,springLength:130}}}}
}});
</script></body></html>"""


def render_osint_graph(name: str = "osint_graph.html") -> str:
    """Render the accumulated OSINT graph as an interactive Maltego-style
    HTML file (open it in a browser). Call this at the end of an investigation."""
    import json as _json

    from c0mr4de.tools.files import WORKSPACE

    if not _GRAPH["nodes"]:
        return "graph is empty - run username_search / google_dork / add_osint_note first."
    nodes = [
        {"id": nid, "label": meta["label"], "group": meta["type"]}
        for nid, meta in _GRAPH["nodes"].items()
    ]
    edges = [{"from": s, "to": d, "label": lbl} for s, d, lbl in _GRAPH["edges"]]
    html = _GRAPH_HTML.format(
        n=len(nodes), e=len(edges), nodes=_json.dumps(nodes), edges=_json.dumps(edges)
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
