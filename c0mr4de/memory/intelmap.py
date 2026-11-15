"""Intel Map ingest - build a structured, queryable index of real disclosed bugs
by vulnerability class, from Pentester Land's open writeup index (the same public
dataset pentesterland.py already RAG-ingests as markdown).

Why this exists alongside pentesterland.py: that module is built for semantic
RAG retrieval (consult_knowledge finds a relevant passage). This module builds a
compact structured JSON index instead - {class -> count/programs/items} - so the
`bug_class_intel`/`top_bug_classes` TOOLS (c0mr4de/tools/intelmap.py) can answer
"what are the most-reported bug classes, and show me real examples" INSTANTLY,
with no embedder/network, the same way cveintel/exploitdb/payloads work. Think of
it as a local, open-data answer to sites like HexBrain's disclosed-report map -
built from data c0mr4de already has the right to use.

    py -m c0mr4de.memory.intelmap --ingest      # download + build the structured index
    py -m c0mr4de.memory.intelmap --out <dir>   # just build it
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from c0mr4de.memory.pentesterland import fetch_list

DEFAULT_OUT = Path("workspace/intel-map")
_MAX_BUGS_PER_ENTRY = 4  # a multi-bug writeup counts under up to this many classes


def _compact(entries: list[dict]) -> list[dict]:
    """Raw pentester.land schema -> compact {t,l,b,p,a,d} items (title/link/bugs/
    programs/author/date), matching what the intelmap tool reads."""
    out = []
    for e in entries:
        links = e.get("Links") or [{}]
        title = (links[0].get("Title") or "").strip()
        link = (links[0].get("Link") or "").strip()
        if not title or not link:
            continue
        bugs = [b.strip() for b in (e.get("Bugs") or []) if b.strip()][:_MAX_BUGS_PER_ENTRY]
        programs = [p.strip() for p in (e.get("Programs") or []) if p.strip()][:3]
        author = ", ".join(e.get("Authors") or [])[:60]
        date = (e.get("PublicationDate") or e.get("AddedDate") or "")[:10]
        out.append({"t": title[:160], "l": link, "b": bugs or ["Uncategorized"],
                    "p": programs, "a": author, "d": date})
    return out


def build_index(items: list[dict]) -> dict:
    """items -> {generated_from, total_items, classes: {name: {count, top_programs}}, items}."""
    classes: dict[str, Counter] = {}
    for it in items:
        for b in it["b"]:
            classes.setdefault(b, Counter())
            for p in it["p"]:
                classes[b][p] += 1
    class_stats = {
        name: {"count": sum(1 for it in items if name in it["b"]),
               "top_programs": progs.most_common(5)}
        for name, progs in classes.items()
    }
    return {"source": "pentester.land/writeups.json", "total_items": len(items),
            "total_classes": len(class_stats), "classes": class_stats, "items": items}


def write_index(index: dict, out: Path) -> Path:
    out = out.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    path = out / "index.json"
    path.write_text(json.dumps(index, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return path


def build_summary_doc(index: dict) -> str:
    """A short markdown overview (top classes + counts) for the RAG store, so
    consult_knowledge can answer 'what bug classes show up most in the wild'
    without needing the structured tool."""
    ranked = sorted(index["classes"].items(), key=lambda kv: -kv[1]["count"])[:40]
    lines = [f"# Intel Map - disclosed bug-class frequency",
             f"\n_source: pentester.land, {index['total_items']} writeups, "
             f"{index['total_classes']} bug classes. Use bug_class_intel(class) or "
             f"top_bug_classes() for live structured queries._\n"]
    for name, stats in ranked:
        progs = ", ".join(p for p, _ in stats["top_programs"][:3])
        lines.append(f"- **{name}**: {stats['count']} disclosed writeups" +
                     (f" (seen on {progs})" if progs else ""))
    return "\n".join(lines)


def main() -> None:
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(description="Build the Intel Map structured bug-class index")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--ingest", action="store_true", help="Also embed a summary doc into the vector store")
    args = ap.parse_args()

    print("downloading pentester.land/writeups.json ...")
    items = _compact(fetch_list())
    index = build_index(items)
    path = write_index(index, args.out)
    print(f"built index: {index['total_items']} writeups across {index['total_classes']} bug classes -> {path}")

    if args.ingest:
        from c0mr4de.memory.ingest import ingest_directory
        from c0mr4de.memory.vectorstore import VectorStore

        summary_dir = args.out / "_summary"
        summary_dir.mkdir(parents=True, exist_ok=True)
        (summary_dir / "intel-map-summary.md").write_text(build_summary_doc(index), encoding="utf-8")
        store = VectorStore()
        n = ingest_directory(store, summary_dir, "source:intel-map")
        print(f"ingested {n} chunks; store now holds {store.count()} total")
    else:
        print(f"ready for bug_class_intel()/top_bug_classes() tools. "
              f"Add --ingest to also embed a summary into consult_knowledge.")


if __name__ == "__main__":
    main()
