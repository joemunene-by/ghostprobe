"""ghostprobe command line.

  ghostprobe scan-file tools.json           analyse a saved tools/list dump
  ghostprobe stdio -- npx -y some-mcp        probe a live stdio MCP server
  ghostprobe ... --json                      machine-readable output
  ghostprobe ... --fail-on high              exit 1 if a finding >= severity
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze_server
from .report import exit_code, render_json, render_text


def load_tools_file(path: str) -> list[dict]:
    """Load a tools list from JSON. Accepts a bare list, an MCP `tools/list`
    result ({"tools": [...]}), or a raw JSON-RPC envelope ({"result": {...}})."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        if "tools" in data:
            data = data["tools"]
        elif "result" in data and isinstance(data["result"], dict):
            data = data["result"].get("tools", [])
    if not isinstance(data, list):
        raise ValueError("could not find a list of tools in the file")
    return data


def _emit(findings, target, as_json: bool) -> None:
    out = render_json(findings, target) if as_json else render_text(findings, target)
    print(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="ghostprobe",
        description="Dynamic red-team probe for MCP servers (OWASP MCP Top 10).",
    )
    ap.add_argument("--version", action="version", version=f"ghostprobe {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sf = sub.add_parser("scan-file", help="analyse a saved tools/list JSON dump")
    sf.add_argument("path")
    sf.add_argument("--json", action="store_true", dest="as_json")
    sf.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])

    st = sub.add_parser("stdio", help="probe a live stdio MCP server (needs: pip install mcp)")
    st.add_argument("command", help="server command, e.g. npx")
    st.add_argument("args", nargs=argparse.REMAINDER, help="server args (use -- to separate)")
    st.add_argument("--json", action="store_true", dest="as_json")
    st.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])

    ns = ap.parse_args(argv)

    if ns.cmd == "scan-file":
        try:
            tools = load_tools_file(ns.path)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"ghostprobe: cannot read tools from {ns.path}: {e}", file=sys.stderr)
            return 2
        findings = analyze_server(tools)
        _emit(findings, ns.path, ns.as_json)
        return exit_code(findings, ns.fail_on)

    if ns.cmd == "stdio":
        args = [a for a in ns.args if a != "--"]
        try:
            from .client import fetch_tools_stdio
            tools = fetch_tools_stdio(ns.command, args)
        except ImportError:
            print("ghostprobe: live probing needs the MCP SDK. Run: pip install mcp", file=sys.stderr)
            return 2
        except Exception as e:  # connection/handshake failures are varied
            print(f"ghostprobe: could not probe server: {e}", file=sys.stderr)
            return 2
        target = " ".join([ns.command, *args])
        findings = analyze_server(tools)
        _emit(findings, target, ns.as_json)
        return exit_code(findings, ns.fail_on)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
