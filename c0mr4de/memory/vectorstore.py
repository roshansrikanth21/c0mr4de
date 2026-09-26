"""Local vector store (Chroma, persisted to disk) holding the ingested
Obsidian vault + playbooks. This is the "knowledge" half of the RAG
approach we settled on instead of fine-tuning - see README for why."""
from __future__ import annotations

from pathlib import Path

import chromadb

from c0mr4de.memory.embeddings import OllamaEmbedder

DEFAULT_DB_PATH = Path("./memory_store").resolve()


class VectorStore:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH, collection: str = "knowledge"):
        self._client = chromadb.PersistentClient(path=str(db_path))
        self._collection = self._client.get_or_create_collection(collection)
        self._embedder = OllamaEmbedder()

    def add(self, doc_id: str, text: str, metadata: dict) -> None:
        embedding = self._embedder.embed_one(text)
        self._collection.upsert(ids=[doc_id], embeddings=[embedding], documents=[text], metadatas=[metadata])

    def query(self, text: str, n_results: int = 4) -> list[dict]:
        embedding = self._embedder.embed_one(text)
        results = self._collection.query(query_embeddings=[embedding], n_results=n_results)
        out = []
        for i in range(len(results["ids"][0])):
            out.append(
                {
                    "id": results["ids"][0][i],
                    "text": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i],
                }
            )
        return out

    def delete(self, ids: list[str] | None = None, where: dict | None = None) -> None:
        """Remove documents by id or metadata filter (e.g. where={'source': 'writeup-live'})."""
        if ids:
            self._collection.delete(ids=ids)
        if where:
            self._collection.delete(where=where)

    def count(self) -> int:
        return self._collection.count()
