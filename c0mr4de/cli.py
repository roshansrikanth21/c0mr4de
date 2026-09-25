"""Entry point: `c0mr4de run "task"` or `python -m c0mr4de.cli run "task"`."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# Windows consoles default to cp1252 and crash on non-ASCII the model echoes.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

from c0mr4de.agent.backends import build_backend
from c0mr4de.agent.loop import AgentLoop
from c0mr4de.tools import build_default_registry

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "config.yaml"


def load_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Copy config/config.example.yaml to config/config.yaml and fill in your backend choice."
        )
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> None:
    parser = argparse.ArgumentParser(prog="c0mr4de", description="c0mr4de - autonomous pentest assistant")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run the agent on a task")
    run_p.add_argument("task", type=str, help="What to do, e.g. 'recon example.com and report findings'")
    run_p.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    run_p.add_argument("--max-steps", type=int, default=25)
    run_p.add_argument("--save", metavar="TARGET", default=None,
                       help="After the run, auto-save the engagement to the vault under this target label")

    ingest_p = sub.add_parser("ingest", help="Ingest the Obsidian vault + playbooks into the knowledge store")
    ingest_p.add_argument("--vault", type=Path, default=None)

    swarm_p = sub.add_parser("swarm", help="Run the multi-agent swarm (recon -> exploit -> report) on a target")
    swarm_p.add_argument("target", type=str, help="Target URL/host")
    swarm_p.add_argument("--objective", type=str, default="Find, exploit and chain vulnerabilities; capture any secret; report.")
    swarm_p.add_argument("--max-steps", type=int, default=16)

    args = parser.parse_args()

    if args.command == "swarm":
        from c0mr4de.swarm.orchestrator import Swarm

        def on_event(kind, data):
            agent = data.get("agent", "")
            if kind == "agent_start":
                print(f"\n===== [{data['agent'].upper()}] specialist starting =====")
            elif kind == "thought" and data.get("text"):
                print(f"[{agent}] {data['text'][:300]}")
            elif kind == "tool_call":
                print(f"  [{agent}] -> {data['name']}({data.get('arguments', {})})")
            elif kind == "tool_result":
                r = data.get("result", "")
                print(f"  [{agent}] <- {r[:200]}")
            elif kind == "agent_done":
                print(f"===== [{data['agent'].upper()}] done =====")

        swarm = Swarm(max_steps=args.max_steps, on_event=on_event)
        bb = swarm.run(args.target, args.objective)
        print("\n===== SWARM COMPLETE =====")
        print(f"findings: {len(bb.findings)}")
        for f in bb.findings:
            print(f"  - [{f['agent']}] {f['text'][:160]}")
        return

    if args.command == "ingest":
        from c0mr4de.memory.ingest import main as ingest_main

        ingest_main()
        return

    if args.command == "run":
        cfg = load_config(args.config)
        backend = build_backend(cfg["backend"])
        registry = build_default_registry()
        print(f"backend: {backend.name} | tools: {', '.join(registry.names())}")
        loop = AgentLoop(backend=backend, tools=registry, max_steps=args.max_steps)
        result = loop.run(args.task)
        print("\n=== FINAL ===\n" + result)
        if args.save:
            from c0mr4de.engagement import save_engagement

            path = save_engagement(loop, args.save)
            print(f"\n[engagement saved to vault: {path}]")


if __name__ == "__main__":
    main()
