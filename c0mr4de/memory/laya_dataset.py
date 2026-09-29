"""Turn real engagement reports + the pentest-vault into a labelled DECISIONS
dataset for fine-tuning Laya on how Roshan actually judges findings.

Laya learns typed decisions (choice / score / noul) over a state. The richest
signal is a finished report like the pixstech VA: each finding carries a severity,
a confidence, and a vulnerable-or-not judgment (incl. explicit positive controls =
negative examples). This extractor pulls those into JSONL, one labelled decision
per line, in the natural Laya shape:

    {"state": "<evidence/observation>",
     "question": {"type": "score", "instructions": "...", "criteria": [...]},
     "answer": "high", "source": "pixstech"}

HONEST NOTE: fine-tuning a 400M model needs hundreds–thousands of decisions; a
handful of reports yields dozens. This is the PIPELINE — run every finished report
through it as the vault grows, curate, then fine-tune on Kaggle (see the runner
printed by `c0mr4de laya-dataset`). Reports vary in format, so treat the output as
a draft to review, not gospel.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_SEV_SCALE = ["info", "low", "medium", "high", "critical"]
_SEV_Q = {"type": "score", "instructions": "How severe is this finding?", "criteria": _SEV_SCALE}
_VULN_Q = {"type": "noul", "instructions": "Is this a real, exploitable security weakness (yes) "
           "rather than an accepted/positive control (no)?"}

_SEV_RE = re.compile(r"\*\*Severity:\*\*\s*([A-Za-z/ –-]+)", re.I)
_FINDING_HDR = re.compile(r"^#{2,4}\s+(F-?\d+[^\n]*)", re.M)
_POSITIVE = re.compile(r"positive|keep these|good\)|controls observed", re.I)
_NOISE = re.compile(r"\*\*(Severity|CVSS[^:]*|Confidence)[^\n]*\n?", re.I)


def _norm_sev(text: str) -> str | None:
    low = text.lower()
    for s in ("critical", "high", "medium", "low", "info"):   # first/headline severity wins
        if s in low:
            return s
    return None


def _clean_state(body: str, limit: int = 700) -> str:
    body = _NOISE.sub("", body)
    body = re.sub(r"\s+", " ", body).strip()
    return body[:limit]


def _parse_report(text: str, source: str) -> list[dict]:
    """Split on finding headers (### F-01 ...); per finding emit a severity decision
    and a vulnerable-or-not decision. State excludes the severity label itself."""
    out: list[dict] = []
    heads = list(_FINDING_HDR.finditer(text))
    for i, m in enumerate(heads):
        title = m.group(1).strip()
        body = text[m.end(): heads[i + 1].start() if i + 1 < len(heads) else len(text)]
        is_positive = bool(_POSITIVE.search(title)) or "positive controls" in body.lower()[:200]
        state = f"{title}. {_clean_state(body)}"
        sev_m = _SEV_RE.search(body)
        sev = _norm_sev(sev_m.group(1)) if sev_m else ("info" if is_positive else None)
        if sev:
            out.append({"state": state, "question": _SEV_Q, "answer": sev, "source": source})
        out.append({"state": state, "question": _VULN_Q,
                    "answer": "no" if is_positive else "yes", "source": source})
    return out


def _parse_engagement(text: str, source: str) -> list[dict]:
    """Vault engagement → a vulnerable-or-not decision from the outcome, and (if a
    'generalizes' note exists) the target state as context."""
    out: list[dict] = []
    m = re.search(r"\*\*Outcome:\*\*\s*([^\n]+)", text, re.I)
    target = re.search(r"\*\*Target:\*\*\s*([^\n]+)", text, re.I)
    state = (f"Target: {target.group(1).strip()}. " if target else "") + _clean_state(text, 600)
    if m:
        low = m.group(1).lower()
        clean = any(k in low for k in ("no way in", "clean", "no findings", "hardened", "nothing"))
        vuln = any(k in low for k in ("pass", "solved", "flag", "bypass", "exploit")) and not clean
        out.append({"state": state, "question": _VULN_Q, "answer": "yes" if vuln else "no", "source": source})
    return out


def build_dataset(sources: list[Path]) -> list[dict]:
    decisions: list[dict] = []
    for path in sources:
        for md in ([path] if path.is_file() else sorted(path.rglob("*.md"))):
            if md.name.lower() == "readme.md":
                continue
            text = md.read_text(encoding="utf-8", errors="replace")
            src = md.stem
            if _FINDING_HDR.search(text):                 # looks like a findings report
                decisions += _parse_report(text, src)
            else:                                          # engagement-vault entry
                decisions += _parse_engagement(text, src)
    # dedupe identical (state, question-type, answer)
    seen, uniq = set(), []
    for d in decisions:
        key = (d["state"][:120], d["question"]["type"], d["answer"])
        if key not in seen:
            seen.add(key)
            uniq.append(d)
    return uniq


def main() -> None:
    import argparse
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    repo = Path(__file__).resolve().parent.parent.parent
    ap = argparse.ArgumentParser(description="Build a Laya fine-tune decisions dataset from reports + the vault")
    ap.add_argument("--sources", type=Path, nargs="*", default=[repo / "pentest-vault"],
                    help="report .md files and/or folders (e.g. pentest-vault, a PIXSTECH report)")
    ap.add_argument("--out", type=Path, default=repo / "workspace" / "laya-decisions.jsonl")
    args = ap.parse_args()
    data = build_dataset(list(args.sources))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for d in data:
            f.write(json.dumps(d, ensure_ascii=False) + "\n")
    by_type: dict[str, int] = {}
    for d in data:
        by_type[d["question"]["type"]] = by_type.get(d["question"]["type"], 0) + 1
    print(f"built {len(data)} labelled decisions -> {args.out}")
    print("by type: " + ", ".join(f"{k}={v}" for k, v in sorted(by_type.items())))
    print("\nHONEST: this is pipeline output, not a trained model. A few reports = dozens of rows; "
          "real fine-tuning wants hundreds. Grow it by running every finished report through this, "
          "curate the labels, then train on GPU:")
    print("  1) review/curate the JSONL (labels are auto-extracted — fix any wrong severities)")
    print("  2) Laya fine-tune notebook (free Kaggle 2xT4): https://nandhakishorm.github.io/laya/  -> Fine-tuning")
    print("  3) push the fine-tuned checkpoint; point laya_decider at it. Expected lift ~0.36 -> ~0.77.")


if __name__ == "__main__":
    main()
