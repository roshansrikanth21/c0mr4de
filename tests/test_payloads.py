"""Payload-bank tests. Uses a tiny fake PayloadsAllTheThings tree (via
C0MR4DE_PATT_DIR) so they're deterministic and CI-safe without the real clone.
Asserts: real payloads served per class, `contains` filters, dedup, prose is
filtered out, and graceful degradation when PATT or a category is absent."""
import c0mr4de.tools.payloads as P


def _fake_patt(tmp_path):
    base = tmp_path / "PayloadsAllTheThings"
    sqli = base / "SQL Injection" / "Intruder"
    sqli.mkdir(parents=True)
    (sqli / "payloads-sql-blind.txt").write_text(
        "# a comment line\n' OR SLEEP(5)-- -\n' OR SLEEP(5)-- -\n\" OR pg_sleep(5)--\n"
        "This is a prose sentence that should be filtered out because it is long english text.\n",
        encoding="utf-8")
    # a class with no Intruder/ or .txt -> must mine README fenced code
    ssti = base / "Server Side Template Injection"
    ssti.mkdir(parents=True)
    (ssti / "README.md").write_text("# SSTI\nTry:\n```\n{{7*7}}\n${7*7}\n```\nsome prose here\n", encoding="utf-8")
    return base


def test_serves_real_payloads_and_dedups(tmp_path, monkeypatch):
    monkeypatch.setenv("C0MR4DE_PATT_DIR", str(_fake_patt(tmp_path)))
    out = P.payloads("sqli")
    assert "SLEEP(5)" in out and "pg_sleep(5)" in out
    assert out.count("' OR SLEEP(5)-- -") == 1              # deduped
    assert "prose sentence" not in out                      # prose filtered
    assert "# a comment" not in out                         # comments filtered


def test_contains_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("C0MR4DE_PATT_DIR", str(_fake_patt(tmp_path)))
    out = P.payloads("sqli", contains="pg_sleep")
    assert "pg_sleep(5)" in out and "SLEEP(5)-- -" not in out


def test_readme_fenced_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("C0MR4DE_PATT_DIR", str(_fake_patt(tmp_path)))
    out = P.payloads("ssti")
    assert "{{7*7}}" in out and "${7*7}" in out
    assert "some prose here" not in out


def test_unknown_category_lists_options(tmp_path, monkeypatch):
    monkeypatch.setenv("C0MR4DE_PATT_DIR", str(_fake_patt(tmp_path)))
    out = P.payloads("nonsense")
    assert "unknown category" in out and "sqli" in out


def test_missing_patt_gives_clone_instructions(tmp_path, monkeypatch):
    monkeypatch.setenv("C0MR4DE_PATT_DIR", str(tmp_path / "does_not_exist"))
    out = P.payloads("sqli")
    assert "git clone" in out and "PayloadsAllTheThings" in out


def test_category_present_but_not_in_clone(tmp_path, monkeypatch):
    monkeypatch.setenv("C0MR4DE_PATT_DIR", str(_fake_patt(tmp_path)))
    out = P.payloads("graphql")              # known alias, folder absent in fake clone
    assert "not in your PATT clone" in out


def test_registered():
    from c0mr4de.tools import build_default_registry
    assert build_default_registry().get("payloads")
