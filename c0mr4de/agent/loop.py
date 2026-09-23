"""The ReAct-style agent loop: generate -> execute any tool calls ->
feed results back -> repeat until the model stops calling tools or the
step cap is hit. Backend-agnostic - swap Ollama for Anthropic in config
and nothing here changes."""
from __future__ import annotations

from dataclasses import dataclass, field

from c0mr4de.agent.backends import Backend
from c0mr4de.agent.prompts import SYSTEM_PROMPT
from c0mr4de.tools.base import ToolRegistry
from c0mr4de.tools.playbook import consult_knowledge


@dataclass
class StepLog:
    step: int
    assistant_text: str
    tool_calls: list[str] = field(default_factory=list)
    tool_results: list[str] = field(default_factory=list)


class AgentLoop:
    def __init__(self, backend: Backend, tools: ToolRegistry, max_steps: int = 25, verbose: bool = True):
        self.backend = backend
        self.tools = tools
        self.max_steps = max_steps
        self.verbose = verbose
        self.log: list[StepLog] = []

    def run(self, task: str) -> str:
        # Auto-inject relevant playbook/vault knowledge up front rather than
        # relying on the model to remember to call consult_knowledge itself -
        # live testing showed a 7B model will happily skip that step even when
        # explicitly told to use it. This guarantees the grounding is present
        # regardless of the backend's tool-use discipline.
        knowledge = consult_knowledge(task)
        primed_task = (
            f"{task}\n\n"
            f"--- Relevant knowledge auto-retrieved for this task (already consulted, no need to call "
            f"consult_knowledge again for this exact question - call it again only if you need something "
            f"more specific as you go) ---\n{knowledge}"
        )
        messages: list[dict] = [{"role": "user", "content": primed_task}]
        tool_schemas = self.tools.schemas()

        for step in range(1, self.max_steps + 1):
            response = self.backend.generate(SYSTEM_PROMPT, messages, tools=tool_schemas)
            step_log = StepLog(step=step, assistant_text=response.text)

            if self.verbose and response.text:
                print(f"\n[step {step}] {self.backend.name} thinks:\n{response.text}\n")

            if not response.tool_calls:
                self.log.append(step_log)
                return response.text

            tool_results: list[tuple] = []
            for call in response.tool_calls:
                tool = self.tools.get(call.name)
                if tool is None:
                    result = f"ERROR: unknown tool '{call.name}'"
                else:
                    if self.verbose:
                        print(f"  -> calling {call.name}({call.arguments})")
                    result = tool.run(**call.arguments)
                    if self.verbose:
                        preview = result if len(result) < 500 else result[:500] + "... (truncated)"
                        print(f"  <- {preview}")
                step_log.tool_calls.append(f"{call.name}({call.arguments})")
                step_log.tool_results.append(result)
                tool_results.append((call, result))

            self.log.append(step_log)
            messages.extend(self.backend.format_turn(response, tool_results))

        return (
            f"Stopped after {self.max_steps} steps without a final answer. "
            f"Raise max_steps if this task genuinely needs more, or check the log for a loop."
        )
