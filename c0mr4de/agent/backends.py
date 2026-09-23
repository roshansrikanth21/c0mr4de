"""
LLM backend abstraction. The agent loop talks to this interface only -
it never knows whether it's calling a local Ollama model or a hosted API.
This is what makes the "route cheap steps to local, hard steps to a paid
brain" architecture possible without touching the agent loop itself.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"
    usage: dict[str, int] = field(default_factory=dict)


class Backend(ABC):
    """A chat-completions-with-tools backend. Implementations wrap a
    specific provider's SDK/API and normalize it to this shape."""

    name: str

    @abstractmethod
    def generate(
        self,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        ...

    def format_turn(self, response: LLMResponse, tool_results: list[tuple[ToolCall, str]]) -> list[dict[str, Any]]:
        """Given a response and the (call, result) pairs from executing its
        tool calls, return the message(s) to append to the conversation so
        the next generate() call has proper context. Default: OpenAI/Ollama
        style (assistant w/ tool_calls, then one role=tool message per call).
        Anthropic overrides this - see AnthropicBackend."""
        assistant_msg = {
            "role": "assistant",
            "content": response.text,
            "tool_calls": [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
                }
                for call, _ in tool_results
            ],
        }
        tool_msgs = [
            {"role": "tool", "tool_call_id": call.id, "content": result} for call, result in tool_results
        ]
        return [assistant_msg, *tool_msgs]


class OllamaBackend(Backend):
    """Local, free, unlimited-tokens tier. Slower and weaker at
    multi-step tool chaining - use for routine/cheap steps, not the
    hard reasoning chain. Requires `ollama pull <model>` first."""

    def __init__(self, model: str = "qwen2.5-coder:7b", host: str = "http://localhost:11434"):
        import ollama

        self.model = model
        self.name = f"ollama:{model}"
        self._client = ollama.Client(host=host)

    def generate(self, system, messages, tools=None, max_tokens=2048) -> LLMResponse:
        chat_messages = [{"role": "system", "content": system}] + messages
        response = self._client.chat(
            model=self.model,
            messages=chat_messages,
            tools=tools or [],
            options={"num_predict": max_tokens},
        )
        msg = response["message"]
        tool_calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc["function"]
            args = fn["arguments"]
            if isinstance(args, str):
                args = json.loads(args)
            tool_calls.append(ToolCall(id=f"call_{i}", name=fn["name"], arguments=args))
        return LLMResponse(
            text=msg.get("content", "") or "",
            tool_calls=tool_calls,
            stop_reason="tool_use" if tool_calls else "end_turn",
            usage={
                "input_tokens": response.get("prompt_eval_count", 0),
                "output_tokens": response.get("eval_count", 0),
            },
        )


class AnthropicBackend(Backend):
    """Hosted frontier tier. Use for the hard reasoning steps - this is
    what actually found the Haveloc JWT chain. Costs per token; see
    README for the routing pattern that keeps that bounded."""

    def __init__(self, model: str = "claude-sonnet-5", api_key: str | None = None):
        import anthropic

        self.model = model
        self.name = f"anthropic:{model}"
        self._client = anthropic.Anthropic(api_key=api_key)

    def generate(self, system, messages, tools=None, max_tokens=2048) -> LLMResponse:
        anthropic_tools = [
            {
                "name": t["name"],
                "description": t.get("description", ""),
                "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
            }
            for t in (tools or [])
        ]
        response = self._client.messages.create(
            model=self.model,
            system=system,
            messages=messages,
            tools=anthropic_tools,
            max_tokens=max_tokens,
        )
        text_parts = []
        tool_calls = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(id=block.id, name=block.name, arguments=block.input))
        return LLMResponse(
            text="".join(text_parts),
            tool_calls=tool_calls,
            stop_reason=response.stop_reason or "end_turn",
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        )

    def format_turn(self, response: LLMResponse, tool_results: list[tuple[ToolCall, str]]) -> list[dict[str, Any]]:
        content_blocks: list[dict[str, Any]] = []
        if response.text:
            content_blocks.append({"type": "text", "text": response.text})
        for call, _ in tool_results:
            content_blocks.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments})
        assistant_msg = {"role": "assistant", "content": content_blocks}
        result_blocks = [
            {"type": "tool_result", "tool_use_id": call.id, "content": result} for call, result in tool_results
        ]
        user_msg = {"role": "user", "content": result_blocks}
        return [assistant_msg, user_msg]


class OpenAICompatibleBackend(Backend):
    """Hosted open-weight models (DeepSeek-R1, Kimi K2, Qwen3-235B, ...)
    via any OpenAI-compatible endpoint - DeepInfra, Together, Fireworks,
    OpenRouter, Groq. Cheaper than Anthropic per token, modest capability
    gap on the hardest reasoning chains. Point base_url at your provider."""

    def __init__(self, model: str, base_url: str, api_key: str):
        from openai import OpenAI

        self.model = model
        self.name = f"openai-compat:{model}"
        self._client = OpenAI(base_url=base_url, api_key=api_key)

    def generate(self, system, messages, tools=None, max_tokens=2048) -> LLMResponse:
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                },
            }
            for t in (tools or [])
        ]
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system}] + messages,
            tools=openai_tools or None,
            max_tokens=max_tokens,
        )
        choice = response.choices[0]
        tool_calls = []
        for tc in choice.message.tool_calls or []:
            tool_calls.append(
                ToolCall(id=tc.id, name=tc.function.name, arguments=json.loads(tc.function.arguments))
            )
        return LLMResponse(
            text=choice.message.content or "",
            tool_calls=tool_calls,
            stop_reason=choice.finish_reason or "stop",
            usage={
                "input_tokens": response.usage.prompt_tokens if response.usage else 0,
                "output_tokens": response.usage.completion_tokens if response.usage else 0,
            },
        )


def build_backend(cfg: dict[str, Any]) -> Backend:
    """Factory from a config dict (see config/config.example.yaml)."""
    kind = cfg["type"]
    if kind == "ollama":
        return OllamaBackend(model=cfg.get("model", "qwen2.5-coder:7b"), host=cfg.get("host", "http://localhost:11434"))
    if kind == "anthropic":
        return AnthropicBackend(model=cfg.get("model", "claude-sonnet-5"), api_key=cfg.get("api_key"))
    if kind == "openai_compatible":
        return OpenAICompatibleBackend(model=cfg["model"], base_url=cfg["base_url"], api_key=cfg["api_key"])
    raise ValueError(f"unknown backend type: {kind}")
