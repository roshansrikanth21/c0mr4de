"""Helpers for running tools inside Docker against local targets.

On Docker Desktop (Windows/macOS), a container's `localhost` is the CONTAINER,
not the host - so a dockerized scanner aimed at http://localhost:PORT can't
reach a server running on the operator's machine. Containers reach the host
via `host.docker.internal`. This rewrites local targets accordingly so local
testing (mock apps, Juice Shop) actually works; real external targets pass
through unchanged."""
from __future__ import annotations

import re


def docker_target(url_or_host: str) -> str:
    return re.sub(r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0)\b", "host.docker.internal", url_or_host)


# passed to `docker run` so host.docker.internal resolves even on Linux engines
ADD_HOST = ["--add-host", "host.docker.internal:host-gateway"]
