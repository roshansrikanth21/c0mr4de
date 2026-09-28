"""The retrieval tool - this is what lets a small model follow a
pre-baked reasoning chain instead of deriving one from scratch. Queries
the vector store built by memory/ingest.py (Obsidian vault + playbooks)."""
from __future__ import annotations

from c0mr4de.memory.vectorstore import VectorStore
from c0mr4de.tools.base import Tool

_store: VectorStore | None = None


def _get_store() -> VectorStore:
    global _store
    if _store is None:
        _store = VectorStore()
    return _store


def consult_knowledge(query: str) -> str:
    try:
        store = _get_store()
        if store.count() == 0:
            return "Knowledge store is empty. Run `c0mr4de ingest` first to load playbooks and the Obsidian vault."
        results = store.query(query, n_results=4)
    except Exception as exc:  # noqa: BLE001 - embedder (Ollama) or store may be down
        return (f"consult_knowledge unavailable ({type(exc).__name__}: the local embedder/Ollama is likely "
                f"down). Vector search needs Ollama running (`ollama serve`). Meanwhile use recall_related "
                f"(graph recall, no embedder needed) for connected playbooks/engagements on a topic.")
    if not results:
        return "No relevant knowledge found for this query."
    parts = []
    for r in results:
        src = r["metadata"].get("file", "unknown")
        parts.append(f"--- from {src} ---\n{r['text']}")
    return "\n\n".join(parts)


TOOLS = [
    Tool(
        name="consult_knowledge",
        description=(
            "Search past pentest methodology, playbooks, and findings for relevant guidance before "
            "acting. ALWAYS check this before improvising on an unfamiliar pattern (JWTs, auth flows, "
            "known CVE classes) - it may already contain the exact chain that worked before."
        ),
        parameters={"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]},
        fn=consult_knowledge,
    ),
]
