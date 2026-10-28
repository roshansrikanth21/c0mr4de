"""Tool-result cache tests. The cache must: hit on identical (tool,args) within
TTL, miss on different args, never freeze a transient failure, leave non-cacheable
tools untouched, and be disableable. Uses synthetic Tools with a call counter so a
'hit' is proven by the inner fn NOT running again."""
import c0mr4de.tools.cache as cache
from c0mr4de.tools.base import Tool


def _counter_tool(name="crawl_site"):
    calls = {"n": 0}

    def fn(url="http://t/"):
        calls["n"] += 1
        return f"crawled {url} (call {calls['n']})"

    return Tool(name=name, description="", parameters={}, fn=fn), calls


def test_hit_skips_inner_on_same_args():
    cache.clear()
    tool, calls = _counter_tool()
    wrapped = cache.maybe_wrap(tool)
    r1 = wrapped.fn(url="http://a/")
    r2 = wrapped.fn(url="http://a/")
    assert r1 == r2                 # identical cached result
    assert calls["n"] == 1          # inner fn ran once; second call was a hit


def test_miss_on_different_args():
    cache.clear()
    tool, calls = _counter_tool()
    wrapped = cache.maybe_wrap(tool)
    wrapped.fn(url="http://a/")
    wrapped.fn(url="http://b/")     # different arg -> different key -> miss
    assert calls["n"] == 2


def test_transient_failures_not_cached():
    cache.clear()
    calls = {"n": 0}

    def fn(url="x"):
        calls["n"] += 1
        return "crawl unavailable: Docker not running" if calls["n"] == 1 else "crawled ok"

    wrapped = cache.maybe_wrap(Tool("crawl_site", "", {}, fn))
    assert "unavailable" in wrapped.fn(url="http://a/")
    second = wrapped.fn(url="http://a/")     # first (transient) was not cached -> re-runs
    assert second == "crawled ok" and calls["n"] == 2


def test_noncacheable_tool_is_untouched():
    cache.clear()
    tool, calls = _counter_tool(name="http_request")   # not in CACHEABLE
    wrapped = cache.maybe_wrap(tool)
    assert wrapped is tool                               # returned unchanged
    wrapped.fn(url="http://a/")
    wrapped.fn(url="http://a/")
    assert calls["n"] == 2                               # no caching


def test_disabled_via_env(monkeypatch):
    cache.clear()
    monkeypatch.setenv("C0MR4DE_TOOL_CACHE", "0")
    tool, calls = _counter_tool()
    wrapped = cache.maybe_wrap(tool)
    wrapped.fn(url="http://a/")
    wrapped.fn(url="http://a/")
    assert calls["n"] == 2                               # caching off -> always runs


def test_clear_and_stats():
    cache.clear()
    cache._STATS.update(hits=0, misses=0, stored=0)
    tool, _ = _counter_tool()
    wrapped = cache.maybe_wrap(tool)
    wrapped.fn(url="http://a/")       # miss + stored
    wrapped.fn(url="http://a/")       # hit
    s = cache.stats()
    assert s["hits"] == 1 and s["misses"] == 1 and s["stored"] == 1 and s["entries"] == 1
    assert s["hit_rate"] == 0.5
    cache.clear()
    assert cache.stats()["entries"] == 0


def test_registry_wraps_cacheable_only():
    from c0mr4de.tools import build_default_registry
    reg = build_default_registry()
    # a cacheable recon tool and a non-cacheable one both still resolve + run
    assert reg.get("crawl_site") and reg.get("http_request") and reg.get("cve_lookup")
