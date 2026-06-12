"""v0.3.0: finding fingerprints + --allowlist suppression. All offline."""
from __future__ import annotations

import json
from pathlib import Path

from ghostprobe.cli import load_allowlist, main
from ghostprobe.findings import Finding
from ghostprobe.report import apply_allowlist

FIXTURE = Path(__file__).parent / "fixtures" / "poisoned_server.json"


def test_fingerprint_is_stable_and_short():
    f = Finding("MCP01", "high", "send_email", "Tool description contains an X", "d")
    fp = f.fingerprint
    assert len(fp) == 8
    # Same identity -> same fingerprint; evidence and digits do not affect it.
    f2 = Finding("MCP01", "high", "send_email", "Tool description contains an X", "different", evidence="x")
    assert f2.fingerprint == fp


def test_fingerprint_ignores_digit_changes():
    a = Finding("MCP04", "info", "<server>", "Capability inventory (14 tools)", "d")
    b = Finding("MCP04", "info", "<server>", "Capability inventory (15 tools)", "d")
    assert a.fingerprint == b.fingerprint


def test_fingerprint_differs_by_tool_and_category():
    a = Finding("MCP01", "high", "a", "t", "d")
    b = Finding("MCP01", "high", "b", "t", "d")
    c = Finding("MCP05", "high", "a", "t", "d")
    assert len({a.fingerprint, b.fingerprint, c.fingerprint}) == 3


def test_apply_allowlist_filters():
    fs = [Finding("MCP01", "high", "a", "t", "d"), Finding("MCP05", "medium", "b", "u", "d")]
    keep_id = fs[1].fingerprint
    kept, suppressed = apply_allowlist(fs, {fs[0].fingerprint})
    assert suppressed == 1
    assert [f.fingerprint for f in kept] == [keep_id]


def test_apply_allowlist_empty_is_noop():
    fs = [Finding("MCP01", "high", "a", "t", "d")]
    kept, suppressed = apply_allowlist(fs, set())
    assert suppressed == 0 and kept == fs


def test_load_allowlist_list_and_object(tmp_path):
    p1 = tmp_path / "a.json"
    p1.write_text(json.dumps(["abc12345", "def67890"]))
    assert load_allowlist(str(p1)) == {"abc12345", "def67890"}

    p2 = tmp_path / "b.json"
    p2.write_text(json.dumps({"suppress": ["abc12345"]}))
    assert load_allowlist(str(p2)) == {"abc12345"}

    assert load_allowlist(None) == set()


def test_cli_allowlist_suppresses_and_flips_exit(tmp_path, capsys):
    # First run: capture the critical finding's id from JSON output.
    main(["scan-file", str(FIXTURE), "--json"])
    payload = json.loads(capsys.readouterr().out)
    crit = next(f for f in payload["findings"] if f["severity"] == "critical")
    crit_id = crit["id"]

    # Allowlisting every finding id should drop them all.
    ids = [f["id"] for f in payload["findings"]]
    allow = tmp_path / "allow.json"
    allow.write_text(json.dumps(ids))

    rc = main(["scan-file", str(FIXTURE), "--allowlist", str(allow), "--fail-on", "critical"])
    out = capsys.readouterr().out
    assert "No findings" in out
    assert rc == 0  # the critical that would have failed CI is suppressed
    assert crit_id in ids
