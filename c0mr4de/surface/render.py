"""Render an AttackSurface to (a) a clean markdown report and (b) an interactive
attack-surface map (vis-network HTML), both written to the workspace. The report
leads with the prioritized weak points so the operator reads the answer first,
then the full surface."""
from __future__ import annotations

import json

from c0mr4de.surface.analyze import prioritize, summarize
from c0mr4de.surface.model import AttackSurface

_SEV_COLOR = {"critical": "#f2555a", "high": "#f2884b", "medium": "#e0b341",
              "low": "#5aa9e6", "info": "#7b8494"}


def to_markdown(surf: AttackSurface) -> str:
    ranked = prioritize(surf)
    st = surf.stats()
    md = [f"# Attack Surface — {surf.domain or '(target)'}", "",
          f"`{st['hosts']} hosts · {st['endpoints']} endpoints · {st['open_ports']} open ports · {st['findings']} findings`", ""]

    md.append("## Most likely vulnerable")
    if ranked:
        md.append("| # | score | asset | why |")
        md.append("|---|------:|-------|-----|")
        for i, it in enumerate(ranked[:20], 1):
            why = "; ".join(dict.fromkeys(it["reasons"]))[:180]
            md.append(f"| {i} | {it['score']} | `{it['ref']}` ({it['kind']}) | {why} |")
    else:
        md.append("_No high-signal weak points flagged. Run more tools, or the surface looks hardened._")
    md.append("")

    if surf.findings:
        md.append("## Findings by severity")
        for sev in ["critical", "high", "medium", "low", "info"]:
            fs = [f for f in surf.findings if f.severity == sev]
            if fs:
                md.append(f"### {sev.upper()} ({len(fs)})")
                for f in fs:
                    md.append(f"- **{f.ident}** {f.name} — `{f.location}` _({f.source})_")
        md.append("")

    md.append("## Hosts & open ports")
    for h in sorted(surf.hosts.values(), key=lambda x: x.host):
        ports = ", ".join(f"{p} {s}".strip() for p, s in sorted(h.ports.items())) or "—"
        ips = ", ".join(sorted(h.ips)) or "?"
        md.append(f"- `{h.host}` → {ips} · ports: {ports}")
    md.append("")

    md.append("## Web endpoints")
    for e in sorted(surf.endpoints.values(), key=lambda x: (x.status or 999, x.url)):
        tech = f" [{', '.join(e.tech)}]" if e.tech else ""
        md.append(f"- `{e.status or '?'}` {e.url}{tech}" + (f" — {e.title[:60]}" if e.title else ""))
    return "\n".join(md)


_GRAPH_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"/>
<title>c0mr4de attack surface — {domain}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/dist/vis-network.min.js"></script>
<style>
 body{{margin:0;background:#0a0c10;color:#d7dce5;font-family:ui-monospace,Consolas,monospace}}
 #h{{padding:12px 18px;border-bottom:1px solid #232936}} #h b{{color:#f2884b;letter-spacing:1px}}
 #h .s{{color:#7b8494;font-size:12px}} #net{{width:100vw;height:calc(100vh - 49px)}}
 #lg{{position:absolute;top:60px;right:14px;background:#12151ccc;border:1px solid #232936;border-radius:8px;padding:9px 12px;font-size:11px}}
 #lg .r{{display:flex;align-items:center;gap:7px;margin:3px 0}} #lg .d{{width:10px;height:10px;border-radius:50%}}
</style></head><body>
<div id="h"><b>c0mr4de</b> <span class="s">attack surface · {domain} · {n} nodes · node size = risk score · drag/scroll to explore</span></div>
<div id="lg">{legend}</div><div id="net"></div>
<script>
const nodes=new vis.DataSet({nodes}); const edges=new vis.DataSet({edges});
const net=new vis.Network(document.getElementById('net'),{{nodes,edges}},{{
 nodes:{{shape:'dot',borderWidth:2,scaling:{{min:8,max:52,label:{{min:11,max:22}}}},font:{{color:'#c7cede',size:12,face:'ui-monospace'}}}},
 edges:{{color:{{color:'#2b3444',highlight:'#f2884b'}},smooth:{{type:'continuous'}},width:1.1}},
 physics:{{stabilization:{{iterations:200}},barnesHut:{{gravitationalConstant:-14000,springLength:130,damping:0.5}}}},
 interaction:{{hover:true,tooltipDelay:120}}
}});
</script></body></html>"""


def to_graph_html(surf: AttackSurface) -> str:
    ranked = {it["ref"]: it["score"] for it in prioritize(surf)}
    nodes: list[dict] = []
    edges: list[dict] = []
    root = surf.domain or "target"
    nodes.append({"id": root, "label": root, "color": "#f2884b", "value": 30, "shape": "diamond"})
    for h in surf.hosts.values():
        risk = ranked.get(h.host, 0)
        color = "#f2555a" if risk >= 55 else "#e0b341" if risk >= 25 else "#4ade80"
        ports = ",".join(str(p) for p in sorted(h.ports)) or "—"
        nodes.append({"id": h.host, "label": h.host, "color": color, "value": 6 + risk,
                      "title": f"{h.host}\\nips: {', '.join(sorted(h.ips)) or '?'}\\nports: {ports}\\nrisk: {risk}"})
        edges.append({"from": root, "to": h.host})
    for e in surf.endpoints.values():
        from c0mr4de.surface.model import _host_of
        host = _host_of(e.url)
        risk = ranked.get(e.url, 0)
        color = "#f2555a" if risk >= 40 else "#e0b341" if risk >= 15 else "#60a5fa"
        nodes.append({"id": e.url, "label": e.url.split("/", 3)[-1][:24] or e.url, "color": color,
                      "value": 4 + risk, "shape": "box",
                      "title": f"{e.url}\\n{e.status or '?'} {e.title[:60]}\\ntech: {', '.join(e.tech) or '-'}\\nrisk: {risk}"})
        edges.append({"from": host if host in surf.hosts else root, "to": e.url})
    legend = ("<div class='r'><span class='d' style='background:#f2555a'></span>high risk</div>"
              "<div class='r'><span class='d' style='background:#e0b341'></span>notable</div>"
              "<div class='r'><span class='d' style='background:#4ade80'></span>host</div>"
              "<div class='r'><span class='d' style='background:#60a5fa'></span>endpoint</div>")
    return _GRAPH_HTML.format(domain=root, n=len(nodes), nodes=json.dumps(nodes),
                              edges=json.dumps(edges), legend=legend)


def write_reports(surf: AttackSurface, name: str = "") -> str:
    """Write both the markdown report and the HTML map to workspace/surface/."""
    from c0mr4de.tools.files import WORKSPACE
    dest = WORKSPACE / "surface"
    dest.mkdir(parents=True, exist_ok=True)
    slug = "".join(c for c in (name or surf.domain or "target") if c.isalnum() or c in ".-_") or "target"
    (dest / f"{slug}.md").write_text(to_markdown(surf), encoding="utf-8")
    (dest / f"{slug}.html").write_text(to_graph_html(surf), encoding="utf-8")
    return f"workspace/surface/{slug}.md (report) + workspace/surface/{slug}.html (interactive map)"
