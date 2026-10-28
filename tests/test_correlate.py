"""Source<->runtime correlation tests. The value is that a SAST sink and the live
endpoint recon found are matched into one high-priority, specialist-routed lead -
and that unrelated items are NOT matched. Pure logic, no network/model."""
from c0mr4de.swarm.blackboard import Blackboard
from c0mr4de.swarm.correlate import (_params, _route_tokens, _sink_class, correlate,
                                      correlate_blackboard)


def test_param_and_route_extraction():
    assert _params("search.php param 'id' -> mysql_query") == {"id"}
    assert _params("GET http://t/x?user=1&id=2") == {"user", "id"}
    assert _params("echo $_GET['name']") == {"name"}
    assert "search" in _route_tokens("GET http://t/search?id=1")
    assert "login" in _route_tokens("login.php has a sink")           # filename stem
    assert "about" not in (_route_tokens("http://t/about") & {"index", "api"})  # stop-routes excluded elsewhere


def test_sink_classification_routes_to_specialist():
    assert _sink_class("mysql_query($x)") == ("sqli", "injection")
    assert _sink_class("subprocess.run(cmd)") == ("command injection", "injection")
    assert _sink_class("echo $_GET['x']") == ("xss", "client-side")
    assert _sink_class("nothing dangerous here") == ("", "")


def test_correlate_matches_param_and_sink():
    source = [{"agent": "code-audit", "text": "search.php param 'id' -> mysql_query (SQLi)"}]
    runtime = [{"agent": "runtime-recon", "text": "GET http://t/search?id=1 (200)"}]
    hits = correlate(source, runtime)
    assert len(hits) == 1
    assert hits[0]["sink"] == "sqli" and hits[0]["specialist"] == "injection"
    assert hits[0]["score"] == 3 and "param 'id'" in hits[0]["via"]
    assert "[CORRELATED]" in hits[0]["text"]


def test_no_false_correlation_on_unrelated():
    source = [{"agent": "code-audit", "text": "config.py reads settings.yaml (no user input)"}]
    runtime = [{"agent": "runtime-recon", "text": "GET http://t/about (static)"}]
    assert correlate(source, runtime) == []


def test_route_only_needs_a_sink():
    # shared route but NO param and NO sink -> not correlated (too weak)
    source = [{"agent": "code-audit", "text": "search.php is large"}]
    runtime = [{"agent": "runtime-recon", "text": "GET http://t/search (200)"}]
    assert correlate(source, runtime) == []
    # shared route WITH a sink -> correlated (score 1)
    source2 = [{"agent": "code-audit", "text": "search.php calls mysql_query on the term"}]
    hits = correlate(source2, runtime)
    assert len(hits) == 1 and hits[0]["score"] == 1


def test_correlate_blackboard_posts_leads():
    bb = Blackboard("t", "o")
    bb.surface_item("code-audit", "search.php param 'id' -> mysql_query (SQLi)")
    bb.surface_item("runtime-recon", "GET http://t/search?id=1 (200)")
    bb.surface_item("runtime-recon", "GET http://t/unrelated (200)")
    posted = correlate_blackboard(bb)
    assert len(posted) == 1
    assert bb.counts()["leads"] == 1
    assert "[CORRELATED]" in bb.leads[0]["text"]


def test_correlate_blackboard_needs_both_sides():
    bb = Blackboard("t", "o")
    bb.surface_item("runtime-recon", "GET http://t/search?id=1")   # runtime only, no source
    assert correlate_blackboard(bb) == []
