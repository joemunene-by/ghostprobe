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
from .analyzer import analyze_server, analyze_tool_output, diff_tools
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


def _format_exc(e: BaseException) -> str:
    """Flatten an exception (unwrapping anyio/asyncio ExceptionGroups) into a
    legible 'Type: message; Type: message' string, so an empty-message error
    like a cancel-scope failure still names its type instead of printing blank."""
    parts: list[str] = []

    def walk(ex: BaseException) -> None:
        if isinstance(ex, BaseExceptionGroup):
            for sub in ex.exceptions:
                walk(sub)
            return
        msg = str(ex).strip()
        parts.append(f"{type(ex).__name__}: {msg}" if msg else type(ex).__name__)

    walk(e)
    seen = list(dict.fromkeys(parts))
    return "; ".join(seen) if seen else repr(e)


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
    st.add_argument("--timeout", type=float, default=60.0, help="seconds for the MCP handshake (default 60)")
    st.add_argument("--debug", action="store_true", help="print the full traceback on failure")

    so = sub.add_parser("scan-output", help="scan a tool's returned text for injection (MCP03)")
    so.add_argument("path", help="file containing the tool output text (or - for stdin)")
    so.add_argument("--tool", default="<output>", help="tool name, for the report")
    so.add_argument("--json", action="store_true", dest="as_json")
    so.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])

    df = sub.add_parser("diff", help="diff two tools/list snapshots for rug pulls (MCP02)")
    df.add_argument("old", help="earlier tools/list JSON")
    df.add_argument("new", help="later tools/list JSON")
    df.add_argument("--json", action="store_true", dest="as_json")
    df.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])

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
            tools = fetch_tools_stdio(ns.command, args, timeout=ns.timeout)
        except ImportError:
            print("ghostprobe: live probing needs the MCP SDK. Run: pip install mcp", file=sys.stderr)
            return 2
        except BaseException as e:  # anyio/subprocess failures are varied
            if ns.debug:
                import traceback
                traceback.print_exc()
            print(f"ghostprobe: could not probe server: {_format_exc(e)}", file=sys.stderr)
            print(
                "  hints: the first npx run downloads the server (slow); a wrong "
                "command or missing args also lands here. Re-run with --debug for "
                "the full traceback, or --timeout 120.",
                file=sys.stderr,
            )
            return 2
        target = " ".join([ns.command, *args])
        findings = analyze_server(tools)
        _emit(findings, target, ns.as_json)
        return exit_code(findings, ns.fail_on)

    if ns.cmd == "scan-output":
        try:
            text = sys.stdin.read() if ns.path == "-" else Path(ns.path).read_text(encoding="utf-8")
        except OSError as e:
            print(f"ghostprobe: cannot read {ns.path}: {e}", file=sys.stderr)
            return 2
        findings = analyze_tool_output(ns.tool, text)
        _emit(findings, f"output of {ns.tool}", ns.as_json)
        return exit_code(findings, ns.fail_on)

    if ns.cmd == "diff":
        try:
            old_tools = load_tools_file(ns.old)
            new_tools = load_tools_file(ns.new)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"ghostprobe: cannot read snapshots: {e}", file=sys.stderr)
            return 2
        findings = diff_tools(old_tools, new_tools)
        _emit(findings, f"{ns.old} -> {ns.new}", ns.as_json)
        return exit_code(findings, ns.fail_on)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
