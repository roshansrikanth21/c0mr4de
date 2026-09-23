"""Tool registry. A Tool is a plain function plus a JSON-schema
description the LLM backends use for function-calling. Nothing here
is model-specific - backends.py translates this shape into whatever
each provider's API wants."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict[str, Any]
    fn: Callable[..., str]

    def schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "parameters": self.parameters}

    def run(self, **kwargs) -> str:
        try:
            return self.fn(**kwargs)
        except Exception as exc:  # noqa: BLE001 - tool errors go back to the model, not the operator
            return f"TOOL ERROR ({self.name}): {exc}"


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def schemas(self) -> list[dict[str, Any]]:
        return [t.schema() for t in self._tools.values()]

    def names(self) -> list[str]:
        return list(self._tools.keys())
