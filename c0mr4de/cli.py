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

    ingest_p = sub.add_parser("ingest", help="Ingest the Obsidian vault + playbooks into the knowledge store")
    ingest_p.add_argument("--vault", type=Path, default=None)

    args = parser.parse_args()

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


if __name__ == "__main__":
    main()
