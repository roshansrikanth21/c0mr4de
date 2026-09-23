"""Embeddings via local Ollama (nomic-embed-text) - free, runs fine on
a 4GB GPU since embedding models are tiny compared to chat models.
This is the same embedder JARVIS already uses (see memory: jarvis-env-setup)."""
from __future__ import annotations

import ollama


class OllamaEmbedder:
    def __init__(self, model: str = "nomic-embed-text", host: str = "http://localhost:11434"):
        self.model = model
        self._client = ollama.Client(host=host)

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._client.embeddings(model=self.model, prompt=t)["embedding"] for t in texts]

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]
