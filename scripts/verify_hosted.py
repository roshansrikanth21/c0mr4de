"""Prove the hosted (GLM / DeepSeek / any OpenAI-compatible) path for real.

The hivemind only runs its specialists in TRUE parallel on a hosted backend - a
single local model serializes. This script confirms a hosted endpoint actually
answers your key, then (optionally) runs the hivemind against an authorized target
and shows the specialists starting concurrently + the confirmed-finding count.

It is the one command to run the moment you have a key. With no key it tells you
exactly what to add - it never fabricates a result.

Usage:
  # just confirm the endpoint answers your key:
  OPENCODE_API_KEY=sk-... py scripts/verify_hosted.py
  # or point at a preset you put in config/config.yaml:
  py scripts/verify_hosted.py --preset opencode-zen
  # full proof: run the hivemind in parallel against an AUTHORIZED target:
  py scripts/verify_hosted.py --preset opencode-zen --target http://localhost:3000

Env overrides (used if no reachable preset is found):
  OPENCODE_API_KEY / HOSTED_API_KEY   the key
  HOSTED_BASE_URL   default https://opencode.ai/zen/v1
  HOSTED_MODEL      default deepseek-v4-flash-free
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

import httpx
import yaml

REPO = Path(__file__).resolve().parent.parent
_PLACEHOLDER = {"", "...", "<your-key>", "YOUR_KEY", "local", None}


def _is_local(url: str) -> bool:
    return any(h in (url or "") for h in ("localhost", "127.0.0.1", "[::1]"))


def _resolve_cfg(preset: str | None) -> dict | None:
    """Pick a hosted openai_compatible backend: the named preset, else the first
    config preset that has a real key on a remote URL, else env vars."""
    try:
        cfg = yaml.safe_load((REPO / "config" / "config.yaml").read_text())
    except Exception:  # noqa: BLE001
        cfg = {}
    models = (cfg or {}).get("models") or {}
    if preset:
        m = models.get(preset)
        if not m:
            print(f"[x] preset '{preset}' not found in config/config.yaml. "
                  f"Available: {', '.join(models) or '(none)'}")
            return None
        return dict(m, _name=preset)
    # auto-pick: first remote openai_compatible preset with a real key
    for name, m in models.items():
        if (m.get("type") == "openai_compatible" and not _is_local(m.get("base_url", ""))
                and str(m.get("api_key", "")).strip() not in _PLACEHOLDER):
            return dict(m, _name=name)
    # env fallback
    key = os.environ.get("OPENCODE_API_KEY") or os.environ.get("HOSTED_API_KEY")
    if key:
        return {"type": "openai_compatible", "_name": "env",
                "model": os.environ.get("HOSTED_MODEL", "deepseek-v4-flash-free"),
                "base_url": os.environ.get("HOSTED_BASE_URL", "https://opencode.ai/zen/v1"),
                "api_key": key}
    return None


def _how_to() -> None:
    print("\n  No hosted key found. To enable the parallel GLM/DeepSeek path:\n"
          "  1. Get a key:\n"
          "       OpenCode Zen (DeepSeek free variant): https://opencode.ai/auth\n"
          "       NVIDIA NIM (DeepSeek V4.1 Flash, free): https://build.nvidia.com\n"
          "       Z.ai (GLM):                            https://z.ai/manage-apikey/apikey-list\n"
          "  2a. Quick test now:   OPENCODE_API_KEY=sk-... py scripts/verify_hosted.py\n"
          "  2b. Or pin a preset in config/config.yaml (see config.example.yaml), e.g.:\n"
          "        active_model: opencode-zen\n"
          "        models:\n"
          "          opencode-zen:\n"
          "            type: openai_compatible\n"
          "            model: deepseek-v4-flash-free\n"
          "            base_url: https://opencode.ai/zen/v1\n"
          "            api_key: <your-key>\n"
          "      then:  py scripts/verify_hosted.py --preset opencode-zen --target <authorized-url>\n"
          "  Note: free model IDs rotate - check the /models list this script prints.\n")


def _probe_models(cfg: dict) -> list[str]:
    url = cfg["base_url"].rstrip("/") + "/models"
    r = httpx.get(url, headers={"Authorization": f"Bearer {cfg['api_key']}"}, timeout=15)
    r.raise_for_status()
    data = r.json()
    return [m.get("id", "?") for m in (data.get("data") or [])]


def _run_hivemind(cfg: dict, target: str) -> int:
    from c0mr4de.agent.backends import build_backend
    from c0mr4de.swarm.orchestrator import Hivemind

    starts: list[tuple[float, str]] = []
    t0 = time.time()

    def on_event(kind, data):
        ag = data.get("agent", "")
        if kind == "phase":
            print(f"\n== PHASE {data['name']}  [{', '.join(data['specialists'])}]  "
                  f"({'PARALLEL' if data.get('parallel') else 'sequential'}) ==", flush=True)
        elif kind == "agent_start":
            starts.append((time.time(), ag))
            print(f"  >> {ag} start (+{time.time()-t0:.2f}s)", flush=True)
        elif kind == "tool_result" and "[CONFIRMED]" in (data.get("result") or ""):
            print(f"     [{ag}] <- {data['result'].splitlines()[0][:90]}", flush=True)

    # make_backend seam -> each specialist builds its OWN hosted client -> real parallelism
    bb = Hivemind(on_event=on_event, max_steps=6,
                  make_backend=lambda: build_backend({k: v for k, v in cfg.items() if not k.startswith("_")})
                  ).run(target, f"Authorized pentest of {target}: find and CONFIRM web vulns.")
    c = bb.counts()
    print(f"\n=== hivemind complete via HOSTED backend '{cfg['_name']}' "
          f"({cfg['model']}) ===", flush=True)
    print(f"blackboard: confirmed={c['confirmed']}  leads={c['leads']}  surface={c['surface']}", flush=True)
    exploit = [s for s in starts if s[1] in ("injection", "client-side", "access-control", "auth")]
    if len(exploit) >= 2:
        span = max(s[0] for s in exploit) - min(s[0] for s in exploit)
        print(f"{len(exploit)} exploit specialists started within {span:.2f}s of each other => PARALLEL", flush=True)
    return c["confirmed"]


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the hosted GLM/DeepSeek parallel path.")
    ap.add_argument("--preset", help="named preset in config/config.yaml (e.g. opencode-zen)")
    ap.add_argument("--target", help="authorized target URL; runs the hivemind in parallel against it")
    args = ap.parse_args()

    cfg = _resolve_cfg(args.preset)
    if not cfg:
        _how_to()
        return 2

    print(f"[*] hosted backend '{cfg['_name']}': {cfg['model']} @ {cfg['base_url']}")
    try:
        ids = _probe_models(cfg)
    except Exception as exc:  # noqa: BLE001
        print(f"[x] endpoint did not answer the key: {exc}")
        print("    check the api_key, base_url, and that the model id exists for your account.")
        return 1
    print(f"[ok] endpoint answered. {len(ids)} models visible.")
    if ids:
        hit = cfg["model"] in ids
        print(f"     your model '{cfg['model']}': {'FOUND' if hit else 'NOT in list - pick one below'}")
        print("     available: " + ", ".join(ids[:25]) + (" ..." if len(ids) > 25 else ""))
        if not hit:
            print("     (free ids rotate - set models.<preset>.model to one of the above)")

    if not args.target:
        print("\n[ok] hosted path reachable. Re-run with --target <authorized-url> for the full "
              "parallel hivemind proof.")
        return 0
    conf = _run_hivemind(cfg, args.target)
    print(f"\n{'[ok]' if conf else '[!]'} finished. {conf} finding(s) deterministically CONFIRMED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
