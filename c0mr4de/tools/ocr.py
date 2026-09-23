"""OCR tool - pull text out of an uploaded image (a screenshot of a JWT,
an error message, a config, a token in devtools). Uses EasyOCR locally
(free, CPU-fine, already installed). This is the "read what's in my
screenshot" capability; for reasoning ABOUT an image (understanding a UI),
route to a vision model via the rotating backend instead."""
from __future__ import annotations

from pathlib import Path

from c0mr4de.tools.base import Tool

_reader = None


def _get_reader():
    global _reader
    if _reader is None:
        import easyocr

        # english by default; GPU off to avoid competing with a local LLM for the 4GB card
        _reader = easyocr.Reader(["en"], gpu=False)
    return _reader


def ocr_image(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return f"ERROR: image not found: {path}"
    try:
        reader = _get_reader()
        lines = reader.readtext(str(p), detail=0, paragraph=True)
    except Exception as exc:  # noqa: BLE001
        return f"OCR ERROR: {exc}"
    if not lines:
        return "(no text detected in image)"
    return "extracted text:\n" + "\n".join(lines)


TOOLS = [
    Tool(
        name="ocr_image",
        description=(
            "Extract text from an image file (screenshot, photo). Use this to read a JWT, token, "
            "error message, config value, or any text visible in an uploaded image."
        ),
        parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        fn=ocr_image,
    ),
]
