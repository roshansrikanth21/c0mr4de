"""Browser control via Playwright - the capability gap for REAL targets.

Raw HTTP can't see a token that lives in localStorage or is set by JS after
load (exactly how the real Haveloc JWT was found). This drives a real
headless Chromium: navigate, read localStorage/sessionStorage/cookies, run
JS, screenshot. The browser is stateful across calls within a run, so the
agent can log in, then navigate authenticated, then read the session token.

Needs: pip install playwright && playwright install chromium.
Everything degrades to a clear message if Playwright isn't installed."""
from __future__ import annotations

from pathlib import Path

from c0mr4de.tools.base import Tool
from c0mr4de.tools.files import WORKSPACE

_pw = None
_browser = None
_page = None


def _ensure_page():
    global _pw, _browser, _page
    if _page is not None:
        return _page
    from playwright.sync_api import sync_playwright

    _pw = sync_playwright().start()
    _browser = _pw.chromium.launch(headless=True)
    _page = _browser.new_page()
    return _page


def _guard(fn):
    def wrapper(*a, **k):
        try:
            return fn(*a, **k)
        except ImportError:
            return "ERROR: Playwright not installed. Run: pip install playwright && playwright install chromium"
        except Exception as exc:  # noqa: BLE001
            return f"BROWSER ERROR: {exc}"

    return wrapper


@_guard
def browser_navigate(url: str) -> str:
    page = _ensure_page()
    resp = page.goto(url, wait_until="domcontentloaded", timeout=20000)
    status = resp.status if resp else "?"
    title = page.title()
    text = page.inner_text("body")[:1500]
    return f"navigated to {url}\nstatus: {status}\ntitle: {title}\nvisible text (first 1500):\n{text}"


@_guard
def browser_storage() -> str:
    page = _ensure_page()
    local = page.evaluate("() => JSON.stringify(window.localStorage)")
    session = page.evaluate("() => JSON.stringify(window.sessionStorage)")
    cookies = page.context.cookies()
    cookie_str = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    return (
        f"localStorage: {local}\n"
        f"sessionStorage: {session}\n"
        f"cookies: {cookie_str or '(none)'}\n"
        f"TIP: decode any JWT-shaped value with decode_jwt, then tamper_jwt to test it."
    )


@_guard
def browser_eval(js: str) -> str:
    page = _ensure_page()
    result = page.evaluate(js)
    return f"result: {result}"


@_guard
def browser_screenshot(name: str = "page.png") -> str:
    page = _ensure_page()
    safe = "".join(c for c in name if c.isalnum() or c in "._-") or "page.png"
    dest = WORKSPACE / "screenshots"
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / safe
    page.screenshot(path=str(path), full_page=True)
    return f"screenshot saved to {path.relative_to(WORKSPACE)}"


TOOLS = [
    Tool(
        name="browser_navigate",
        description="Open a URL in a real headless browser (runs page JS). Use before browser_storage/eval. Stateful across calls in a run.",
        parameters={"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        fn=browser_navigate,
    ),
    Tool(
        name="browser_storage",
        description="Dump the current page's localStorage, sessionStorage, and cookies. This is where auth/session/payment tokens usually live - check it on any app before assuming there's nothing to tamper.",
        parameters={"type": "object", "properties": {}, "required": []},
        fn=browser_storage,
    ),
    Tool(
        name="browser_eval",
        description="Run JavaScript in the current page and return the result. Use to read a specific storage key, inspect JS variables, or extract data the page holds.",
        parameters={"type": "object", "properties": {"js": {"type": "string", "description": "a JS expression, e.g. localStorage.getItem('session')"}}, "required": ["js"]},
        fn=browser_eval,
    ),
    Tool(
        name="browser_screenshot",
        description="Screenshot the current page to the workspace.",
        parameters={"type": "object", "properties": {"name": {"type": "string"}}, "required": []},
        fn=browser_screenshot,
    ),
]
