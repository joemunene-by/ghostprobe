"""Report rendering, exit-gate, and CLI scan-file tests. All offline."""
from __future__ import annotations

import json
from pathlib import Path

from ghostprobe.cli import load_tools_file, main
from ghostprobe.findings import Finding
from ghostprobe.report import exit_code, render_json, render_text, summarize

FIXTURE = Path(__file__).parent / "fixtures" / "poisoned_server.json"


def _f(sev, owasp="MCP01"):
    return Finding(owasp=owasp, severity=sev, tool="t", title="x", detail="y")


def test_summarize_counts():
    counts = summarize([_f("high"), _f("high"), _f("low")])
    assert counts["high"] == 2
    assert counts["low"] == 1


def test_render_text_no_findings_is_honest():
    out = render_text([], "server")
    assert "No findings" in out
    assert "not proof of safety" in out


def test_render_text_includes_category_and_evidence():
    f = Finding("MCP01", "high", "send_email", "bad", "details", evidence="ev123")
    out = render_text([f], "server")
    assert "Tool Poisoning" in out
    assert "ev123" in out


def test_render_json_is_valid_and_structured():
    payload = json.loads(render_json([_f("critical")], "server"))
    assert payload["target"] == "server"
    assert payload["summary"]["critical"] == 1
    assert payload["findings"][0]["owasp"] == "MCP01"


def test_exit_code_gate():
    findings = [_f("medium")]
    assert exit_code(findings, None) == 0
    assert exit_code(findings, "high") == 0      # nothing reaches high
    assert exit_code(findings, "medium") == 1    # medium meets threshold
    assert exit_code([_f("critical")], "high") == 1


def test_load_tools_file_accepts_wrapped_and_bare(tmp_path):
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps([{"name": "a", "description": "d"}]))
    assert len(load_tools_file(str(bare))) == 1

    envelope = tmp_path / "env.json"
    envelope.write_text(json.dumps({"result": {"tools": [{"name": "a", "description": "d"}]}}))
    assert len(load_tools_file(str(envelope))) == 1


def test_cli_scan_file_fails_on_critical(capsys):
    rc = main(["scan-file", str(FIXTURE), "--fail-on", "high"])
    captured = capsys.readouterr()
    assert "ghostprobe report" in captured.out
    assert rc == 1  # the poisoned fixture has critical findings


def test_cli_scan_file_json_mode(capsys):
    rc = main(["scan-file", str(FIXTURE), "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["summary"]["critical"] >= 1
    assert rc == 0  # no --fail-on, so always 0


def test_cli_missing_file_is_clean_error(capsys):
    rc = main(["scan-file", "/no/such/file.json"])
    assert rc == 2
    assert "cannot read tools" in capsys.readouterr().err
