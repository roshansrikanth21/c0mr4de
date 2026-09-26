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
    for p in (run_p,):
        p.add_argument("--auth-host", default="", help="Host you're authorized to test as a logged-in user")
        p.add_argument("--auth-cookie", default="", help="Session cookie for --auth-host, e.g. 'session=abc; csrf=xyz'")
        p.add_argument("--auth-header", default="", help="Auth header for --auth-host, e.g. 'Authorization: Bearer ...'")
        p.add_argument("--in-scope", default="", help="Comma-separated in-scope hosts (rules of engagement)")
        p.add_argument("--out-scope", default="", help="Comma-separated out-of-scope hosts (blocked)")
        p.add_argument("--focus", default="", help="Preferred vuln classes, e.g. 'IDOR, SSRF, business logic'")

    ingest_p = sub.add_parser("ingest", help="Ingest the Obsidian vault + playbooks into the knowledge store")
    ingest_p.add_argument("--vault", type=Path, default=None)

    prep_p = sub.add_parser("prep-writeups",
                            help="Strip a downloaded writeup repo to clean text ready for --sources ingestion")
    prep_p.add_argument("src", type=Path, help="Cloned writeup repo / doc folder")
    prep_p.add_argument("--out", type=Path, default=Path("workspace/writeup-corpus"))
    prep_p.add_argument("--label", default="writeups")
    prep_p.add_argument("--max-files", type=int, default=0)
    prep_p.add_argument("--ingest", action="store_true", help="Ingest the cleaned output immediately")

    swarm_p = sub.add_parser("swarm", help="Run the multi-agent swarm (recon -> exploit -> report) on a target")
    swarm_p.add_argument("target", type=str, help="Target URL/host")
    swarm_p.add_argument("--objective", type=str, default="Find, exploit and chain vulnerabilities; capture any secret; report.")
    swarm_p.add_argument("--max-steps", type=int, default=16)
    swarm_p.add_argument("--auth-host", default="")
    swarm_p.add_argument("--auth-cookie", default="")
    swarm_p.add_argument("--auth-header", default="")
    swarm_p.add_argument("--in-scope", default="")
    swarm_p.add_argument("--out-scope", default="")
    swarm_p.add_argument("--focus", default="")

    args = parser.parse_args()

    # apply operator-provided auth for authenticated testing
    if getattr(args, "auth_host", ""):
        from c0mr4de import auth
        hdrs = {}
        if getattr(args, "auth_header", ""):
            k, _, v = args.auth_header.partition(":")
            hdrs[k.strip()] = v.strip()
        auth.set_auth(args.auth_host, cookie=getattr(args, "auth_cookie", ""), headers=hdrs)
        print(f"[auth] session set for {args.auth_host} — tools will operate as the logged-in user there")

    # apply rules of engagement / scope
    if getattr(args, "in_scope", "") or getattr(args, "out_scope", "") or getattr(args, "focus", ""):
        from c0mr4de import scope
        scope.set_scope(
            in_scope=[s for s in getattr(args, "in_scope", "").split(",") if s.strip()],
            out_of_scope=[s for s in getattr(args, "out_scope", "").split(",") if s.strip()],
            focus=getattr(args, "focus", ""))
        print("[scope] rules of engagement set — out-of-scope hosts will be blocked")

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

    if args.command == "prep-writeups":
        from c0mr4de.memory.writeup_prep import prepare

        summary = prepare(args.src, args.out, source_label=args.label, max_files=args.max_files)
        print(f"scanned {summary['scanned']} -> kept {summary['kept']} "
              f"(skipped {summary['skipped_small']} small, {summary['skipped_dupe']} dupe); "
              f"~{summary['total_chars']:,} chars in {summary['out']}")
        if summary["by_category"]:
            print("by category: " + ", ".join(f"{k}:{v}" for k, v in sorted(summary["by_category"].items())))
        if args.ingest:
            from c0mr4de.memory.ingest import ingest_directory
            from c0mr4de.memory.vectorstore import VectorStore

            store = VectorStore()
            n = ingest_directory(store, args.out, f"source:{Path(summary['out']).name}")
            print(f"ingested {n} chunks; store now holds {store.count()} total")
        else:
            print(f"next: c0mr4de ingest --sources {summary['out']}")
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
