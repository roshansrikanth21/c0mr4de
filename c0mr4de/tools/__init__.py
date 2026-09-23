from c0mr4de.tools.base import ToolRegistry
from c0mr4de.tools import files, playbook, recon, report, web


def build_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    for module in (recon, web, files, playbook, report):
        for tool in module.TOOLS:
            registry.register(tool)
    return registry
