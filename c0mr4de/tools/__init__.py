import shutil
import subprocess

from c0mr4de.tools.base import ToolRegistry
from c0mr4de.tools import browser, files, fuzz, ocr, operator, osint, playbook, recon, recon_stack, report, web


def _docker_available() -> bool:
    """The recon tools shell out to the kali-mcp Docker image. If Docker
    isn't running, registering them just gives a weak model failing tools
    to get distracted by - so we probe once and skip them if unavailable."""
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=8)
        return r.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def build_default_registry(include_recon: bool | None = None) -> ToolRegistry:
    if include_recon is None:
        include_recon = _docker_available()
    registry = ToolRegistry()
    for module in (web, browser, fuzz, osint, files, ocr, operator, recon_stack, playbook, report):
        for tool in module.TOOLS:
            registry.register(tool)
    if include_recon:
        for tool in (*recon.TOOLS, *web.DOCKER_TOOLS):
            registry.register(tool)
    return registry
