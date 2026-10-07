"""EXIF / file-metadata extraction - the "ExifTool" capability from the tool map.
Pulls hidden metadata out of an image or document: GPS coordinates, author/creator,
the software that produced it, timestamps, camera make/model. This is pure OSINT
signal - a photo's GPS tag or a PDF's Author field leaks location and identity that
the visible content never shows.

Prefers the `exiftool` binary when it is installed (broadest format coverage: PDF,
Office, video, RAW); otherwise falls back to Pillow's EXIF reader for images, which
is always available here. GPS is decoded to decimal degrees plus a maps link so the
location is immediately usable. Local-file only - it reads a path, no network.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from c0mr4de.tools.base import Tool

# Metadata keys worth surfacing first - identity/location/provenance leaks. Matched
# case-insensitively against both exiftool and Pillow tag names.
_HIGH_SIGNAL = (
    "gps", "author", "creator", "artist", "owner", "copyright", "software",
    "make", "model", "createdate", "datetimeoriginal", "modifydate", "producer",
    "lastmodifiedby", "hostcomputer", "serialnumber",
)


def _rat(value) -> float:
    """Coerce a Pillow/exif rational (IFDRational, (num,den) tuple, or number) to float."""
    try:
        if isinstance(value, tuple) and len(value) == 2:
            return value[0] / value[1] if value[1] else 0.0
        return float(value)
    except (TypeError, ZeroDivisionError, ValueError):
        return 0.0


def _gps_to_decimal(gps: dict):
    """Convert a GPS tag dict (keys like GPSLatitude/GPSLatitudeRef) to
    (lat, lon) decimal degrees, or None if the required fields are absent."""
    lat = gps.get("GPSLatitude")
    lon = gps.get("GPSLongitude")
    if not lat or not lon:
        return None
    def dms(v):
        d, m, s = (_rat(x) for x in v)
        return d + m / 60 + s / 3600
    try:
        la, lo = dms(lat), dms(lon)
    except (TypeError, ValueError):
        return None
    if str(gps.get("GPSLatitudeRef", "N")).upper().startswith("S"):
        la = -la
    if str(gps.get("GPSLongitudeRef", "E")).upper().startswith("W"):
        lo = -lo
    return round(la, 6), round(lo, 6)


def _read_pillow(path: Path) -> dict:
    """EXIF for an image via Pillow -> {tagname: value}, with a nested 'GPS' dict."""
    from PIL import Image
    from PIL.ExifTags import GPSTAGS, TAGS
    out: dict = {}
    with Image.open(path) as img:
        exif = img.getexif()
        if not exif:
            return out
        for tag_id, value in exif.items():
            out[TAGS.get(tag_id, str(tag_id))] = value
        try:
            gps_ifd = exif.get_ifd(0x8825)
        except Exception:  # noqa: BLE001
            gps_ifd = {}
        if gps_ifd:
            out["GPS"] = {GPSTAGS.get(k, str(k)): v for k, v in gps_ifd.items()}
    return out


def _format_meta(meta: dict) -> str:
    """Render a flat metadata dict, high-signal keys first, with GPS decoded."""
    if not meta:
        return "(no metadata found)"
    gps = meta.get("GPS") if isinstance(meta.get("GPS"), dict) else None
    lines: list[str] = []
    coord = _gps_to_decimal(gps) if gps else None
    if coord:
        lines.append(f"  GPS: {coord[0]}, {coord[1]}  "
                     f"(https://maps.google.com/?q={coord[0]},{coord[1]})")
    def is_high(k):
        return any(h in k.lower() for h in _HIGH_SIGNAL)
    for key in sorted(meta, key=lambda k: (not is_high(k), k.lower())):
        if key == "GPS":
            continue
        val = meta[key]
        if isinstance(val, (dict, list, bytes)):
            continue
        sval = str(val).strip()
        if sval:
            lines.append(f"  {key}: {sval[:120]}")
    return "\n".join(lines) if lines else "(no readable metadata fields)"


def _exiftool_json(path: Path) -> dict | None:
    """Run the exiftool binary if present; return its parsed dict, or None if the
    binary is unavailable or failed."""
    if shutil.which("exiftool") is None:
        return None
    try:
        r = subprocess.run(["exiftool", "-json", "-n", str(path)],
                           capture_output=True, text=True, timeout=30)
        data = json.loads(r.stdout)
        return data[0] if isinstance(data, list) and data else None
    except Exception:  # noqa: BLE001
        return None


def exif_metadata(path: str) -> str:
    """Extract hidden metadata (GPS, author, software, timestamps, camera) from an
    image or document. Uses the exiftool binary when installed (PDF/Office/video/RAW
    too), else Pillow for images. GPS is decoded to decimal degrees + a maps link."""
    p = Path(path)
    if not p.exists():
        return f"ERROR: file not found: {path}"
    tool_data = _exiftool_json(p)
    if tool_data is not None:
        # exiftool flattens GPS to GPSLatitude/GPSLongitude at top level with -n
        gps = {k: tool_data[k] for k in tool_data if k.lower().startswith("gps")}
        if gps:
            tool_data["GPS"] = {"GPSLatitude": tool_data.get("GPSLatitude"),
                                "GPSLongitude": tool_data.get("GPSLongitude"),
                                "GPSLatitudeRef": tool_data.get("GPSLatitudeRef", "N"),
                                "GPSLongitudeRef": tool_data.get("GPSLongitudeRef", "E")}
        return f"metadata for {p.name} (exiftool):\n" + _format_meta(tool_data)
    # fallback: Pillow (images only)
    try:
        meta = _read_pillow(p)
    except Exception as exc:  # noqa: BLE001
        return (f"exiftool is not installed and Pillow could not read '{p.name}' "
                f"({exc}). Install exiftool for non-image formats (PDF/Office/video).")
    return f"metadata for {p.name} (Pillow EXIF):\n" + _format_meta(meta)


TOOLS = [
    Tool(
        name="exif_metadata",
        description=("Extract hidden file metadata (GPS location, author/creator, producing software, "
                     "timestamps, camera make/model) from an image or document at a local path. GPS is "
                     "decoded to decimal degrees with a maps link. Uses exiftool when installed, else "
                     "Pillow for images. Pure OSINT - a photo or PDF often leaks location and identity."),
        parameters={"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        fn=exif_metadata,
    ),
]
