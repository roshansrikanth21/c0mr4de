"""Attack-surface engine: normalize the messy output of many recon tools
(subfinder, amass, naabu, httpx, nuclei, shodan, bbot, wappalyzer) into ONE
structured model, score where it's most likely vulnerable, and render a clean
report + interactive map. See model.py / analyze.py / render.py."""
from c0mr4de.surface.model import AttackSurface, Endpoint, Finding, Host

__all__ = ["AttackSurface", "Host", "Endpoint", "Finding"]
