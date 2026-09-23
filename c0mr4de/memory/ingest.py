"""Ingests markdown knowledge into the vector store: the Obsidian vault
(Claude-Context) and the playbooks/ directory in this repo. Run via
`python -m c0mr4de.memory.ingest` or `c0mr4de ingest` (see cli.py).

Chunking is deliberately simple (split on markdown headers, fall back
to fixed-size) - good enough for note-sized files. Re-running is safe;
upsert overwrites by id."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from c0mr4de.memory.vectorstore import VectorStore

DEFAULT_OBSIDIAN_VAULT = Path(r"C:\Users\rosha\OneDrive\ClaudeMemory\Claude-Context")
DEFAULT_PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent.parent / "playbooks"

_HEADER_SPLIT = re.compile(r"\n(?=## )")
_CHUNK_CHARS = 1500


def chunk_markdown(text: str) -> list[str]:
    sections = _HEADER_SPLIT.split(text)
    chunks: list[str] = []
    for section in sections:
        if len(section) <= _CHUNK_CHARS:
            if section.strip():
                chunks.append(section.strip())
            continue
        for i in range(0, len(section), _CHUNK_CHARS):
            piece = section[i : i + _CHUNK_CHARS].strip()
            if piece:
                chunks.append(piece)
    return chunks or [text.strip()]


def ingest_directory(store: VectorStore, root: Path, source_label: str) -> int:
    if not root.exists():
        print(f"skip (not found): {root}")
        return 0
    count = 0
    for md_file in root.rglob("*.md"):
        text = md_file.read_text(encoding="utf-8", errors="replace")
        rel = md_file.relative_to(root)
        for i, chunk in enumerate(chunk_markdown(text)):
            doc_id = f"{source_label}:{rel}:{i}"
            store.add(doc_id, chunk, metadata={"source": source_label, "file": str(rel)})
            count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest Obsidian vault + playbooks into the local vector store")
    parser.add_argument("--vault", type=Path, default=DEFAULT_OBSIDIAN_VAULT)
    parser.add_argument("--playbooks", type=Path, default=DEFAULT_PLAYBOOKS_DIR)
    args = parser.parse_args()

    store = VectorStore()
    n1 = ingest_directory(store, args.vault, "obsidian")
    n2 = ingest_directory(store, args.playbooks, "playbook")
    print(f"ingested {n1} chunks from vault, {n2} chunks from playbooks")
    print(f"total chunks in store: {store.count()}")


if __name__ == "__main__":
    main()
