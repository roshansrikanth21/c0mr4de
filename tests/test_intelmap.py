"""Intel Map tests - the structured ingest (memory/intelmap.py) and the instant
lookup tool (tools/intelmap.py) it feeds. No network: the ingest tests build an
index from fixture entries in the raw pentester.land schema, and the tool tests
point C0MR4DE_WORKSPACE-independent code at a fixture index via monkeypatch."""
import json

import c0mr4de.memory.intelmap as M
import c0mr4de.tools.intelmap as T


def _raw_entries():
    """Fixture entries in pentester.land's RAW schema (Links/Bugs/Programs/Authors)."""
    return [
        {"Links": [{"Title": "IDOR in payments", "Link": "https://x/1"}],
         "Bugs": ["IDOR", "Broken authorization"], "Programs": ["Acme"],
         "Authors": ["alice"], "PublicationDate": "2024-01-01"},
        {"Links": [{"Title": "Another IDOR", "Link": "https://x/2"}],
         "Bugs": ["IDOR"], "Programs": ["Acme", "Beta"],
         "Authors": ["bob"], "PublicationDate": "2024-06-01"},
        {"Links": [{"Title": "XSS reflected", "Link": "https://x/3"}],
         "Bugs": ["XSS"], "Programs": ["Beta"],
         "Authors": ["carol"], "PublicationDate": "2023-01-01"},
        {"Links": [{"Title": "no link"}], "Bugs": ["XSS"]},          # dropped: no link/title
        {"Links": [{"Title": "untagged", "Link": "https://x/4"}]},   # no Bugs -> Uncategorized
    ]


# ---- memory/intelmap.py (the ingest) ----

def test_compact_drops_incomplete_entries_and_defaults_uncategorized():
    items = M._compact(_raw_entries())
    assert len(items) == 4                      # the no-link/title entry is dropped
    assert any(it["b"] == ["Uncategorized"] for it in items)


def test_build_index_counts_and_ranks_programs():
    items = M._compact(_raw_entries())
    index = M.build_index(items)
    assert index["total_items"] == 4
    assert index["classes"]["IDOR"]["count"] == 2
    # Acme appears in both IDOR writeups -> top program for IDOR
    assert index["classes"]["IDOR"]["top_programs"][0][0] == "Acme"
    assert index["classes"]["IDOR"]["top_programs"][0][1] == 2


def test_write_index_roundtrips(tmp_path):
    items = M._compact(_raw_entries())
    index = M.build_index(items)
    path = M.write_index(index, tmp_path)
    assert path.name == "index.json"
    reloaded = json.loads(path.read_text(encoding="utf-8"))
    assert reloaded["total_items"] == index["total_items"]


def test_summary_doc_lists_top_classes():
    items = M._compact(_raw_entries())
    index = M.build_index(items)
    doc = M.build_summary_doc(index)
    assert "IDOR" in doc and "2 disclosed writeups" in doc


# ---- tools/intelmap.py (the instant lookup) ----

def _fixture_index():
    return {
        "source": "test", "total_items": 3, "total_classes": 2,
        "classes": {
            "IDOR": {"count": 2, "top_programs": [["Acme", 2]]},
            "XSS": {"count": 1, "top_programs": [["Beta", 1]]},
        },
        "items": [
            {"t": "IDOR in payments", "l": "https://x/1", "b": ["IDOR"], "p": ["Acme"], "a": "alice", "d": "2024-01-01"},
            {"t": "Another IDOR", "l": "https://x/2", "b": ["IDOR"], "p": ["Acme", "Beta"], "a": "bob", "d": "2024-06-01"},
            {"t": "XSS reflected", "l": "https://x/3", "b": ["XSS"], "p": ["Beta"], "a": "carol", "d": "2023-01-01"},
        ],
    }


def test_missing_index_degrades_with_build_instructions(monkeypatch, tmp_path):
    monkeypatch.setattr(T, "_INDEX", tmp_path / "does_not_exist.json")
    T._cache = None
    out = T.bug_class_intel("IDOR")
    assert "intel-map --ingest" in out
    out2 = T.top_bug_classes()
    assert "intel-map --ingest" in out2


def _seed(monkeypatch, tmp_path, index):
    p = tmp_path / "index.json"
    p.write_text(json.dumps(index), encoding="utf-8")
    monkeypatch.setattr(T, "_INDEX", p)
    T._cache = None


def test_bug_class_intel_exact_and_fuzzy_match(monkeypatch, tmp_path):
    _seed(monkeypatch, tmp_path, _fixture_index())
    out = T.bug_class_intel("IDOR")
    assert "2 disclosed writeups" in out and "Acme (2)" in out
    assert "Another IDOR" in out and "IDOR in payments" in out
    # fuzzy / case-insensitive substring match
    out2 = T.bug_class_intel("idor")
    assert "2 disclosed writeups" in out2


def test_bug_class_intel_sorts_newest_first(monkeypatch, tmp_path):
    _seed(monkeypatch, tmp_path, _fixture_index())
    out = T.bug_class_intel("IDOR", limit=2)
    assert out.index("Another IDOR") < out.index("IDOR in payments")   # 2024-06 before 2024-01


def test_bug_class_intel_unknown_class_suggests_alternatives(monkeypatch, tmp_path):
    _seed(monkeypatch, tmp_path, _fixture_index())
    out = T.bug_class_intel("totally-made-up")
    assert "No bug class matching" in out and "IDOR" in out


def test_top_bug_classes_ranked_and_filtered(monkeypatch, tmp_path):
    _seed(monkeypatch, tmp_path, _fixture_index())
    out = T.top_bug_classes()
    assert out.index("IDOR: 2") < out.index("XSS: 1")       # ranked by count desc
    out2 = T.top_bug_classes(contains="xss")
    assert "XSS: 1" in out2 and "IDOR" not in out2


def test_registered():
    from c0mr4de.tools import build_default_registry
    reg = build_default_registry()
    assert reg.get("bug_class_intel") and reg.get("top_bug_classes")
