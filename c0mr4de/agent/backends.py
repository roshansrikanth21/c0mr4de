"""
LLM backend abstraction. The agent loop talks to this interface only -
it never knows whether it's calling a local Ollama model or a hosted API.
This is what makes the "route cheap steps to local, hard steps to a paid
brain" architecture possible without touching the agent loop itself.
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


def _extract_fallback_tool_call(text: str) -> "ToolCall | None":
    """Best-effort recovery for models that write a correctly-shaped tool
    call as plain text instead of using structured output. Looks for the
    first {"name": ..., "arguments": {...}} object anywhere in the text."""
    # Find candidate JSON objects by bracket-matching from each '{"name"' occurrence,
    # since tool arguments can themselves contain nested braces.
    for match_start in (m.start() for m in re.finditer(r'\{\s*"name"\s*:', text)):
        depth = 0
        for i in range(match_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[match_start : i + 1]
                    try:
                        obj = json.loads(candidate)
                    except json.JSONDecodeError:
                        break
                    if isinstance(obj, dict) and "name" in obj and "arguments" in obj:
                        return ToolCall(id="fallback_0", name=obj["name"], arguments=obj["arguments"])
                    break
    return None


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
        # Normalize history that a cloud (OpenAI-style) backend may have built
        # before failover: its tool_calls[].function.arguments are JSON strings,
        # but Ollama's client validates them as dicts. Convert so mid-conversation
        # failover to local doesn't crash.
        norm_messages = []
        for m in messages:
            tcs = m.get("tool_calls") if isinstance(m, dict) else None
            if tcs:
                m = dict(m)
                m["tool_calls"] = []
                for tc in tcs:
                    tc = dict(tc)
                    fn = dict(tc.get("function", {}))
                    if isinstance(fn.get("arguments"), str):
                        try:
                            fn["arguments"] = json.loads(fn["arguments"])
                        except json.JSONDecodeError:
                            fn["arguments"] = {}
                    tc["function"] = fn
                    m["tool_calls"].append(tc)
            norm_messages.append(m)
        chat_messages = [{"role": "system", "content": system}] + norm_messages
        # Ollama mirrors the OpenAI tool-calling convention: each tool must be
        # wrapped as {"type": "function", "function": {...}}, not passed flat.
        wrapped_tools = [
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
        response = self._client.chat(
            model=self.model,
            messages=chat_messages,
            tools=wrapped_tools,
            options={"num_predict": max_tokens},
        )
        msg = response["message"]
        content = msg.get("content", "") or ""
        tool_calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc["function"]
            args = fn["arguments"]
            if isinstance(args, str):
                args = json.loads(args)
            tool_calls.append(ToolCall(id=f"call_{i}", name=fn["name"], arguments=args))

        # Fallback: some Ollama model tags (confirmed with qwen2.5-coder:7b) have a
        # broken tool-calling chat template - the model produces the *correct* tool
        # call JSON but Ollama leaves tool_calls empty and dumps it in `content` as
        # text instead. Detect and parse that case rather than silently losing it.
        if not tool_calls:
            fallback = _extract_fallback_tool_call(content)
            if fallback is not None:
                tool_calls.append(fallback)
                content = ""  # the "text" was really a mis-routed tool call, not a message

        return LLMResponse(
            text=content,
            tool_calls=tool_calls,
            stop_reason="tool_use" if tool_calls else "end_turn",
            usage={
                "input_tokens": response.get("prompt_eval_count", 0),
                "output_tokens": response.get("eval_count", 0),
            },
        )

    def format_turn(self, response: LLMResponse, tool_results: list[tuple[ToolCall, str]]) -> list[dict[str, Any]]:
        # Same OpenAI-style shape as the base implementation, except Ollama's
        # client validates tool_calls[].function.arguments as a dict, not a
        # JSON string - confirmed by a live pydantic ValidationError otherwise.
        assistant_msg = {
            "role": "assistant",
            "content": response.text,
            "tool_calls": [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": call.arguments},
                }
                for call, _ in tool_results
            ],
        }
        tool_msgs = [
            {"role": "tool", "tool_call_id": call.id, "content": result} for call, result in tool_results
        ]
        return [assistant_msg, *tool_msgs]


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
        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system}] + messages,
                tools=openai_tools or None,
                max_tokens=max_tokens,
            )
        except Exception as exc:  # noqa: BLE001
            # Some providers (Groq gpt-oss) return 400 output_parse_failed when
            # the model emits reasoning the tool-parser can't structure. The
            # useful reasoning is in `failed_generation` - recover it as a plain
            # thought (with any tool call it contains) instead of crashing, so
            # the loop can nudge and continue.
            failed = getattr(getattr(exc, "body", None), "get", lambda *_: None)("failed_generation") \
                if isinstance(getattr(exc, "body", None), dict) else None
            if failed is None and "failed_generation" in str(exc):
                failed = str(exc).split("failed_generation", 1)[1][:2000]
            if failed:
                recovered = _extract_fallback_tool_call(failed)
                return LLMResponse(
                    text="" if recovered else failed[:1500],
                    tool_calls=[recovered] if recovered else [],
                    stop_reason="tool_use" if recovered else "end_turn",
                )
            raise
        choice = response.choices[0]
        content = choice.message.content or ""
        tool_calls = []
        for tc in choice.message.tool_calls or []:
            tool_calls.append(
                ToolCall(id=tc.id, name=tc.function.name, arguments=json.loads(tc.function.arguments))
            )
        # Same fallback as Ollama: some free-tier models emit a correct tool
        # call as text instead of using the structured field.
        if not tool_calls:
            fallback = _extract_fallback_tool_call(content)
            if fallback is not None:
                tool_calls.append(fallback)
                content = ""
        return LLMResponse(
            text=content,
            tool_calls=tool_calls,
            stop_reason=choice.finish_reason or "stop",
            usage={
                "input_tokens": response.usage.prompt_tokens if response.usage else 0,
                "output_tokens": response.usage.completion_tokens if response.usage else 0,
            },
        )


def _is_rate_limit(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(s in msg for s in ("429", "rate limit", "rate_limit", "quota", "too many requests", "resource_exhausted"))


class RotatingBackend(Backend):
    """Free-tier survival: an ordered chain of backends tried in round-robin.
    Put free capable APIs first (Groq Llama-70B, Gemini Flash, Cerebras), the
    local model last. On a rate-limit it advances a cursor so the next call
    starts at a fresh provider (spreading load across free quotas); on any
    error it fails forward to the next backend, so a single task never stalls
    halfway as long as ONE member is reachable.

    Keep the chain OpenAI-compatible (Groq/Gemini/Cerebras/Ollama all are).
    Mixing in the Anthropic backend is not supported here - its message shape
    differs, so a mid-conversation switch to/from it would mismatch history."""

    def __init__(self, backends: list[Backend]):
        if not backends:
            raise ValueError("rotating backend needs at least one member")
        self._backends = backends
        self._cursor = 0
        self._last_used = backends[0]
        self.name = "rotating:" + ",".join(b.name for b in backends)

    def generate(self, system, messages, tools=None, max_tokens=2048) -> LLMResponse:
        n = len(self._backends)
        errors = []
        start = self._cursor  # capture ONCE - mutating self._cursor inside the loop
        next_cursor = self._cursor  # would make idx skip members (it retried Groq
        for offset in range(n):  # instead of trying Ollama - the fallback never fired).
            idx = (start + offset) % n
            backend = self._backends[idx]
            try:
                resp = backend.generate(system, messages, tools=tools, max_tokens=max_tokens)
                self._last_used = backend
                self._cursor = next_cursor
                return resp
            except Exception as exc:  # noqa: BLE001 - failover is the whole point
                errors.append(f"{backend.name}: {exc}")
                if _is_rate_limit(exc):
                    # start the NEXT call after this rate-limited member (spread load /
                    # skip a provider whose daily quota is spent)
                    next_cursor = (idx + 1) % n
                continue
        self._cursor = next_cursor
        raise RuntimeError("all backends failed:\n" + "\n".join(errors))

    def format_turn(self, response, tool_results):
        # Delegate to whichever backend actually produced this response.
        return self._last_used.format_turn(response, tool_results)


def build_backend(cfg: dict[str, Any]) -> Backend:
    """Factory from a config dict (see config/config.example.yaml)."""
    kind = cfg["type"]
    if kind == "ollama":
        return OllamaBackend(model=cfg.get("model", "qwen2.5-coder:7b"), host=cfg.get("host", "http://localhost:11434"))
    if kind == "anthropic":
        return AnthropicBackend(model=cfg.get("model", "claude-sonnet-5"), api_key=cfg.get("api_key"))
    if kind == "openai_compatible":
        return OpenAICompatibleBackend(model=cfg["model"], base_url=cfg["base_url"], api_key=cfg["api_key"])
    if kind == "rotating":
        return RotatingBackend([build_backend(m) for m in cfg["chain"]])
    raise ValueError(f"unknown backend type: {kind}")
