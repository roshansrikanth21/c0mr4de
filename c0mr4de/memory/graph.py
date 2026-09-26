"""Knowledge graph layer over c0mr4de's memory — the relational recall that flat
vector RAG can't do.

Inspiration taken from graph-memory tools (OpenGlean/GraphRAG/mem0) WITHOUT their
weight: no Neo4j, no separate DB, no extraction LLM. The vector store (consult_
knowledge) stays the primary retriever for "what's similar"; this adds "what's
CONNECTED" — a light graph built from the markdown c0mr4de already has:

  - `[[wikilinks]]`  -> doc<->doc edges (preserves the vault links that ingest
                       otherwise flattens into plain text and discards)
  - concept mentions -> doc<->concept edges (bug classes / techniques), so two
                       engagements that both used SSRF are 2 hops apart

`recall_related(topic)` then answers relational queries ("what worked on JWT
bugs", "what chains from SSRF") by traversing, and render() reuses the same
vis-network view as the OSINT graph.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from c0mr4de.tools.base import Tool

_REPO = Path(__file__).resolve().parent.parent.parent
DEFAULT_SOURCES = [_REPO / "playbooks", _REPO / "pentest-vault"]

# concept -> match terms (lowercased, substring). Compact + high-signal: the bug
# classes and techniques c0mr4de reasons about. Edges link any doc that mentions one.
CONCEPTS: dict[str, tuple[str, ...]] = {
    "SSRF": ("ssrf", "server-side request forgery"), "IDOR": ("idor", "insecure direct object"),
    "access control": ("broken access control", "access control", "privilege escalation", "authz"),
    "XXE": ("xxe", "xml external entity"), "SQLi": ("sql injection", "sqli"),
    "XSS": ("xss", "cross-site scripting"), "RCE": ("rce", "remote code execution", "command injection"),
    "JWT": ("jwt", "json web token"), "deserialization": ("deserialization", "unserialize", "pickle"),
    "SSTI": ("ssti", "template injection"), "CSRF": ("csrf", "cross-site request forgery"),
    "race condition": ("race condition", "toctou"), "LFI": ("lfi", "local file inclusion", "file inclusion"),
    "path traversal": ("path traversal", "directory traversal"), "auth bypass": ("auth bypass", "authentication bypass"),
    "account takeover": ("account takeover", "ato", "password reset"), "GraphQL": ("graphql",),
    "CORS": ("cors",), "open redirect": ("open redirect",), "prototype pollution": ("prototype pollution",),
    "request smuggling": ("request smuggling", "h2.te", "cl.te"), "recon": ("recon", "enumerat", "subdomain"),
    "OSINT": ("osint", "username", "holehe"), "business logic": ("business logic", "logic flaw"),
}

_WIKILINK = re.compile(r"\[\[([^\]|]+)")


class KnowledgeGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, str] = {}                    # id -> kind ('doc'|'concept')
        self.edges: set[tuple[str, str, str]] = set()      # (src, dst, label)
        self._adj: dict[str, set[str]] = defaultdict(set)

    def _node(self, nid: str, kind: str) -> None:
        self.nodes.setdefault(nid, kind)

    def _edge(self, a: str, b: str, label: str) -> None:
        if a == b:
            return
        self.edges.add((a, b, label))
        self._adj[a].add(b)
        self._adj[b].add(a)

    def build(self, sources: list[Path] | None = None) -> "KnowledgeGraph":
        for root in (sources or DEFAULT_SOURCES):
            if not root.exists():
                continue
            for md in root.rglob("*.md"):
                doc = md.stem
                self._node(doc, "doc")
                text = md.read_text(encoding="utf-8", errors="replace")
                low = text.lower()
                for target in _WIKILINK.findall(text):          # doc -> doc (wikilinks)
                    t = target.strip()
                    self._node(t, "doc")
                    self._edge(doc, t, "links")
                for concept, terms in CONCEPTS.items():          # doc -> concept (mentions)
                    if any(term in low for term in terms):
                        self._node(concept, "concept")
                        self._edge(doc, concept, "covers")
        return self

    def related(self, topic: str, hops: int = 2, limit: int = 25) -> list[tuple[str, str, int]]:
        """Return [(node, kind, distance)] reachable from the node best matching `topic`."""
        start = self._match(topic)
        if start is None:
            return []
        seen = {start: 0}
        frontier = [start]
        for d in range(1, hops + 1):
            nxt = []
            for n in frontier:
                for m in self._adj[n]:
                    if m not in seen:
                        seen[m] = d
                        nxt.append(m)
            frontier = nxt
        out = [(n, self.nodes.get(n, "doc"), dist) for n, dist in seen.items() if dist > 0]
        out.sort(key=lambda x: (x[2], x[0]))
        return out[:limit]

    def _match(self, topic: str) -> str | None:
        t = topic.lower().strip()
        for nid in self.nodes:                                   # exact-ish
            if nid.lower() == t:
                return nid
        for concept in CONCEPTS:                                 # concept by term
            if concept.lower() == t or any(term in t for term in CONCEPTS[concept]):
                if concept in self.nodes:
                    return concept
        for nid in self.nodes:                                   # substring on doc names
            if t in nid.lower():
                return nid
        return None

    def stats(self) -> dict:
        return {"nodes": len(self.nodes), "edges": len(self.edges),
                "concepts": sum(1 for k in self.nodes.values() if k == "concept")}


_GRAPH_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"/>
<title>c0mr4de memory graph</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.6/dist/vis-network.min.js"></script>
<style>
 body{{margin:0;background:#0a0c10;color:#d7dce5;font-family:ui-monospace,Consolas,monospace}}
 #h{{padding:12px 18px;border-bottom:1px solid #232936}} #h b{{color:#4ade80;letter-spacing:1px}}
 #h .s{{color:#7b8494;font-size:12px}} #net{{width:100vw;height:calc(100vh - 49px)}}
</style></head><body>
<div id="h"><b>c0mr4de</b> <span class="s">memory graph · {n} nodes · {e} links · green=concept, blue=memory/playbook</span></div>
<div id="net"></div>
<script>
const nodes=new vis.DataSet({nodes}); const edges=new vis.DataSet({edges});
new vis.Network(document.getElementById('net'),{{nodes,edges}},{{
 nodes:{{shape:'dot',borderWidth:2,scaling:{{min:8,max:44}},font:{{color:'#c7cede',size:12,face:'ui-monospace'}}}},
 edges:{{color:{{color:'#2b3444',highlight:'#4ade80'}},smooth:{{type:'continuous'}},width:1.1,
   font:{{color:'#5b6570',size:9,strokeWidth:0}}}},
 physics:{{stabilization:{{iterations:200}},barnesHut:{{gravitationalConstant:-11000,springLength:140,damping:0.5}}}},
 interaction:{{hover:true}}
}});
</script></body></html>"""


def render_graph(name: str = "memory_graph.html") -> str:
    """Render the whole knowledge graph to an interactive HTML file in the workspace."""
    import json as _json

    from c0mr4de.tools.files import WORKSPACE
    g = _graph()
    if not g.nodes:
        return "knowledge graph empty."
    deg: dict[str, int] = defaultdict(int)
    for a, b, _ in g.edges:
        deg[a] += 1
        deg[b] += 1
    nodes = [{"id": nid, "label": nid, "value": 3 + deg[nid],
              "color": "#4ade80" if kind == "concept" else "#60a5fa"}
             for nid, kind in g.nodes.items()]
    edges = [{"from": a, "to": b, "label": lbl} for a, b, lbl in g.edges]
    html = _GRAPH_HTML.format(n=len(nodes), e=len(edges), nodes=_json.dumps(nodes), edges=_json.dumps(edges))
    dest = WORKSPACE / "surface"
    dest.mkdir(parents=True, exist_ok=True)
    safe = "".join(c for c in name if c.isalnum() or c in "._-") or "memory_graph.html"
    (dest / safe).write_text(html, encoding="utf-8")
    return f"memory graph: workspace/surface/{safe} ({len(nodes)} nodes, {len(edges)} links)"


_GRAPH: KnowledgeGraph | None = None


def _graph() -> KnowledgeGraph:
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = KnowledgeGraph().build()
    return _GRAPH


def recall_related(topic: str) -> str:
    """Graph recall: given a topic (a bug class, technique, target, or playbook name),
    return the CONNECTED memories — playbooks, past engagements, and related concepts —
    that flat similarity search would miss. Complements consult_knowledge."""
    g = _graph()
    if not g.nodes:
        return "knowledge graph empty — need playbooks/ + pentest-vault/ (and optionally the vault)."
    hits = g.related(topic)
    if not hits:
        return (f"no graph node matches '{topic}'. Try a bug class (SSRF, IDOR, JWT), a technique, or a "
                f"playbook/engagement name. Use consult_knowledge for free-text similarity search.")
    docs = [n for n, k, _ in hits if k == "doc"]
    concepts = [n for n, k, _ in hits if k == "concept"]
    out = [f"graph recall for '{topic}' — {len(hits)} connected nodes:"]
    if docs:
        out.append("  related memories/playbooks:")
        out += [f"    - {n}" for n in docs[:15]]
    if concepts:
        out.append("  related concepts (shared bug classes/techniques): " + ", ".join(concepts[:12]))
    out.append("  (then consult_knowledge on any of these for the full text.)")
    return "\n".join(out)


TOOLS = [
    Tool(
        name="recall_related",
        description=("Graph recall over memory: given a bug class, technique, target, or playbook name, "
                     "return CONNECTED past engagements/playbooks/concepts (multi-hop) that similarity "
                     "search misses. Use to find 'what else worked on this kind of bug/target'. "
                     "Complements consult_knowledge (free-text similarity)."),
        parameters={"type": "object", "properties": {"topic": {"type": "string"}}, "required": ["topic"]},
        fn=recall_related,
    ),
]
