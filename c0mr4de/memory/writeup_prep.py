"""Strip a downloaded writeup repo down to just the useful text, so it can be
ingested into the RAG knowledge base WITHOUT dragging in binaries, images and
challenge files.

This is the honest way to grow the CTF/pentest brain: RAG retrieves on relevance,
not volume. A 50GB clone of challenge archives is mostly un-embeddable noise; what
helps the model is clean prose - writeups, methodology, cheat sheets. This tool
takes a cloned repo (or any doc-heavy folder) and produces a flat folder of
cleaned .md files ready for `ingest --sources`.

Usage:
    python -m c0mr4de.memory.writeup_prep <src_repo> --out workspace/writeup-corpus
    python -m c0mr4de.memory.writeup_prep <src_repo> --out <dir> --ingest

Then (if you didn't pass --ingest):
    c0mr4de ingest --sources workspace/writeup-corpus   # or python -m c0mr4de.memory.ingest --sources ...
"""
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

# Only text that embeds usefully. Everything else (binaries, challenge files,
# images, archives) is deliberately dropped.
TEXT_EXTS = {".md", ".markdown", ".mdx", ".txt", ".rst", ".adoc"}

# Directories that never contain writeup prose - skip wholesale.
SKIP_DIRS = {
    ".git", ".github", "node_modules", "vendor", "__pycache__", ".venv", "venv",
    "assets", "images", "image", "img", "screenshots", "static", "dist", "build",
    "files", "attachments", "bin", "obj", ".idea", ".vscode", "site-packages",
}

# Repo-boilerplate filenames that aren't writeups.
SKIP_NAMES = {
    "license", "license.md", "code_of_conduct.md", "contributing.md",
    "changelog.md", "security.md", "codeowners",
}

MIN_CHARS = 200        # below this it's a nav stub / near-empty - not worth a chunk
MAX_CHARS = 40_000     # cap one file so a giant dump can't dominate retrieval

# Category tag from path, so retrieval and provenance survive the flattening.
# NOTE: matched against whole path TOKENS (exact first, then >=4-char substring),
# never bare substrings - a short key like "re" must not match "Request".
_CATEGORIES = {
    # web + the many vuln-class dir names a bug-bounty repo is mostly made of
    "web": "web", "xss": "web", "sql": "web", "sqli": "web", "nosql": "web",
    "ssrf": "web", "csrf": "web", "xxe": "web", "ssti": "web", "lfi": "web",
    "rfi": "web", "idor": "web", "cors": "web", "jwt": "web", "oauth": "web",
    "saml": "web", "graphql": "web", "injection": "web", "traversal": "web",
    "deserialization": "web", "upload": "web", "redirect": "web", "template": "web",
    "prototype": "web", "smuggling": "web", "crlf": "web", "clickjacking": "web",
    "ldap": "web", "xpath": "web", "api": "web",
    # binary / pwn
    "pwn": "pwn", "binary": "pwn", "heap": "pwn", "rop": "pwn", "bof": "pwn",
    # crypto
    "crypto": "crypto", "cryptography": "crypto", "rsa": "crypto", "aes": "crypto",
    # forensics
    "forensic": "forensics", "forensics": "forensics", "stego": "forensics",
    "steganography": "forensics",
    # reversing (no bare "re" - too ambiguous)
    "rev": "reversing", "reverse": "reversing", "reversing": "reversing",
    "ghidra": "reversing", "decompil": "reversing", "disassembl": "reversing",
    # everything else
    "osint": "osint", "recon": "recon", "misc": "misc", "jail": "misc",
    "mobile": "mobile", "android": "mobile", "ios": "mobile",
    "hardware": "hardware", "network": "network",
    "cloud": "cloud", "aws": "cloud", "azure": "cloud", "kubernetes": "cloud",
}

# Cleaning patterns.
_IMG_MD = re.compile(r"!\[[^\]]*\]\([^)]*\)")            # ![alt](path)
_IMG_HTML = re.compile(r"<img[^>]*>", re.IGNORECASE)      # <img ...>
_DATA_URI = re.compile(r"data:[^;]+;base64,[A-Za-z0-9+/=]+")
_LONG_B64 = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")      # stray long base64 blobs
_MANY_BLANKS = re.compile(r"\n{3,}")


def _category_for(rel: Path) -> str:
    tokens = [t for t in re.split(r"[^a-z0-9]+", rel.as_posix().lower()) if t]
    tokset = set(tokens)
    for key, cat in _CATEGORIES.items():   # exact whole-token match wins
        if key in tokset:
            return cat
    for key, cat in _CATEGORIES.items():   # then a >=4-char substring of a token
        if len(key) >= 4 and any(key in t for t in tokens):
            return cat
    return "unsorted"


def _clean(text: str) -> str:
    text = _DATA_URI.sub("", text)
    text = _IMG_MD.sub("", text)
    text = _IMG_HTML.sub("", text)
    text = _LONG_B64.sub("[omitted-blob]", text)
    text = _MANY_BLANKS.sub("\n\n", text)
    return text.strip()


def prepare(src: Path, out: Path, source_label: str = "writeups",
            max_files: int = 0) -> dict:
    """Walk `src`, clean every text file, write flattened .md into `out`.

    Returns a summary dict. Idempotent-ish: re-running overwrites by name and
    skips content-duplicate files within a single run.
    """
    src = src.expanduser().resolve()
    out = out.expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(f"source not found: {src}")
    out.mkdir(parents=True, exist_ok=True)

    seen_hashes: set[str] = set()
    kept = skipped_small = skipped_dupe = 0
    scanned = 0
    total_chars = 0
    by_cat: dict[str, int] = {}

    for f in sorted(src.rglob("*")):
        if not f.is_file() or f.suffix.lower() not in TEXT_EXTS:
            continue
        if any(part.lower() in SKIP_DIRS for part in f.relative_to(src).parts):
            continue
        if f.name.lower() in SKIP_NAMES:
            continue
        scanned += 1
        raw = f.read_text(encoding="utf-8", errors="replace")
        cleaned = _clean(raw)
        if len(cleaned) < MIN_CHARS:
            skipped_small += 1
            continue
        digest = hashlib.sha1(cleaned.encode("utf-8", "replace")).hexdigest()
        if digest in seen_hashes:
            skipped_dupe += 1
            continue
        seen_hashes.add(digest)
        if len(cleaned) > MAX_CHARS:
            cleaned = cleaned[:MAX_CHARS] + "\n\n[truncated]"

        rel = f.relative_to(src)
        cat = _category_for(rel)
        by_cat[cat] = by_cat.get(cat, 0) + 1
        # Provenance + category header so the chunk is self-describing in RAG.
        header = f"# Writeup: {rel.as_posix()}\n\n_category: {cat} | source: {source_label}_\n\n"
        flat = re.sub(r"[^A-Za-z0-9._-]", "_", rel.as_posix())
        flat_name = (flat.rsplit(".", 1)[0] if "." in flat else flat) + ".md"
        (out / flat_name).write_text(header + cleaned, encoding="utf-8")
        kept += 1
        total_chars += len(cleaned)
        if max_files and kept >= max_files:
            break

    return {
        "src": str(src), "out": str(out), "scanned": scanned, "kept": kept,
        "skipped_small": skipped_small, "skipped_dupe": skipped_dupe,
        "total_chars": total_chars, "by_category": by_cat,
    }


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="c0mr4de.memory.writeup_prep",
        description="Strip a writeup repo to clean text ready for RAG ingestion.")
    ap.add_argument("src", type=Path, help="Cloned writeup repo or doc folder")
    ap.add_argument("--out", type=Path, default=Path("workspace/writeup-corpus"),
                    help="Where cleaned .md files are written (default: workspace/writeup-corpus)")
    ap.add_argument("--label", default="writeups", help="Source label recorded in each file header")
    ap.add_argument("--max-files", type=int, default=0, help="Cap files kept (0 = no cap)")
    ap.add_argument("--ingest", action="store_true",
                    help="After cleaning, ingest the output folder into the vector store")
    args = ap.parse_args()

    summary = prepare(args.src, args.out, source_label=args.label, max_files=args.max_files)
    print(
        f"scanned {summary['scanned']} text files -> kept {summary['kept']} "
        f"(skipped {summary['skipped_small']} too-small, {summary['skipped_dupe']} duplicate)")
    if summary["by_category"]:
        cats = ", ".join(f"{k}:{v}" for k, v in sorted(summary["by_category"].items()))
        print(f"by category: {cats}")
    print(f"~{summary['total_chars']:,} chars of clean text in {summary['out']}")

    if args.ingest:
        from c0mr4de.memory.ingest import ingest_directory
        from c0mr4de.memory.vectorstore import VectorStore

        store = VectorStore()
        n = ingest_directory(store, args.out, f"source:{Path(summary['out']).name}")
        print(f"ingested {n} chunks; store now holds {store.count()} total")
    else:
        print(f"\nnext: c0mr4de ingest --sources {summary['out']}")


if __name__ == "__main__":
    main()
