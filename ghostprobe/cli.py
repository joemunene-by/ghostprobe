"""ghostprobe command line.

  ghostprobe scan-file tools.json           analyse a saved tools/list dump
  ghostprobe stdio -- npx -y some-mcp        probe a live stdio MCP server
  ghostprobe canary -- npx -y some-mcp       call read-only tools, scan real output
  ghostprobe canary-http https://host/mcp    same canary probe over HTTP/SSE
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
from .report import apply_allowlist, exit_code, render_json, render_text


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
    if not all(isinstance(t, dict) for t in data):
        raise ValueError("tools list contains a non-object entry; expected MCP tool objects")
    return data


def load_allowlist(path: str | None) -> set[str]:
    """Load finding fingerprints to suppress. The file is a JSON list of id
    strings, or an object with a "suppress" list. Empty set if no path."""
    if not path:
        return set()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("suppress", [])
    return {str(x) for x in data}


def _emit(findings, target, as_json: bool) -> None:
    out = render_json(findings, target) if as_json else render_text(findings, target)
    print(out)


def _finish(findings, target, ns) -> int:
    """Apply the allowlist, emit, and return the CI exit code. Shared by every
    command so --allowlist and --fail-on behave identically everywhere."""
    try:
        allow = load_allowlist(getattr(ns, "allowlist", None))
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"ghostprobe: cannot read allowlist: {e}", file=sys.stderr)
        return 2
    findings, suppressed = apply_allowlist(findings, allow)
    if suppressed and not ns.as_json:
        print(f"({suppressed} finding(s) suppressed by allowlist)", file=sys.stderr)
    _emit(findings, target, ns.as_json)
    return exit_code(findings, ns.fail_on)


def _parse_headers(items: list[str] | None) -> dict[str, str]:
    """Parse repeated --header "Name: value" strings into a dict."""
    headers: dict[str, str] = {}
    for item in items or []:
        name, sep, value = item.partition(":")
        if not sep:
            raise ValueError(f"bad header '{item}', expected 'Name: value'")
        headers[name.strip()] = value.strip()
    return headers


def _finish_canary(results, target, ns) -> int:
    """Report what a canary probe called and skipped, then analyse and finish.
    Shared by the stdio and HTTP canary commands so both behave identically."""
    from .analyzer import analyze_canary

    called = [r["tool"] for r in results if r["called"]]
    skipped = [(r["tool"], r["reason"]) for r in results if not r["called"]]
    print(f"ghostprobe: called {len(called)}, skipped {len(skipped)} of {len(results)} tools", file=sys.stderr)
    for name, reason in skipped:
        print(f"  skipped {name}: {reason}", file=sys.stderr)
    return _finish(analyze_canary(results), target, ns)


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
    sf.add_argument("--allowlist", metavar="FILE", help="JSON list of finding ids to suppress")

    st = sub.add_parser("stdio", help="probe a live stdio MCP server (needs: pip install mcp)")
    st.add_argument("command", help="server command, e.g. npx")
    st.add_argument("args", nargs=argparse.REMAINDER, help="server args (use -- to separate)")
    st.add_argument("--json", action="store_true", dest="as_json")
    st.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])
    st.add_argument("--timeout", type=float, default=60.0, help="seconds for the MCP handshake (default 60)")
    st.add_argument("--debug", action="store_true", help="print the full traceback on failure")
    st.add_argument("--allowlist", metavar="FILE", help="JSON list of finding ids to suppress")

    so = sub.add_parser("scan-output", help="scan a tool's returned text for injection (MCP03)")
    so.add_argument("path", help="file containing the tool output text (or - for stdin)")
    so.add_argument("--tool", default="<output>", help="tool name, for the report")
    so.add_argument("--json", action="store_true", dest="as_json")
    so.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])
    so.add_argument("--allowlist", metavar="FILE", help="JSON list of finding ids to suppress")

    cn = sub.add_parser(
        "canary",
        help="actively call a live server's read-only tools with a planted marker (needs: pip install mcp)",
    )
    cn.add_argument("command", help="server command, e.g. npx")
    cn.add_argument("args", nargs=argparse.REMAINDER, help="server args (use -- to separate)")
    cn.add_argument("--json", action="store_true", dest="as_json")
    cn.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])
    cn.add_argument("--timeout", type=float, default=60.0, help="seconds per MCP operation (default 60)")
    cn.add_argument("--debug", action="store_true", help="print the full traceback on failure")
    cn.add_argument("--allowlist", metavar="FILE", help="JSON list of finding ids to suppress")

    ch = sub.add_parser(
        "canary-http",
        help="canary-probe a remote MCP server over HTTP/SSE (needs: pip install mcp)",
    )
    ch.add_argument("url", help="server URL, e.g. https://host/mcp")
    ch.add_argument(
        "--header", "-H", action="append", metavar="'Name: value'",
        help="extra HTTP header (repeatable), e.g. -H 'Authorization: Bearer ...'",
    )
    ch.add_argument(
        "--transport", choices=["auto", "http", "sse"], default="auto",
        help="auto tries Streamable HTTP then SSE (default); force one with http or sse",
    )
    ch.add_argument("--json", action="store_true", dest="as_json")
    ch.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])
    ch.add_argument("--timeout", type=float, default=60.0, help="seconds per MCP operation (default 60)")
    ch.add_argument("--debug", action="store_true", help="print the full traceback on failure")
    ch.add_argument("--allowlist", metavar="FILE", help="JSON list of finding ids to suppress")

    df = sub.add_parser("diff", help="diff two tools/list snapshots for rug pulls (MCP02)")
    df.add_argument("old", help="earlier tools/list JSON")
    df.add_argument("new", help="later tools/list JSON")
    df.add_argument("--json", action="store_true", dest="as_json")
    df.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"])
    df.add_argument("--allowlist", metavar="FILE", help="JSON list of finding ids to suppress")

    ns = ap.parse_args(argv)

    if ns.cmd == "scan-file":
        try:
            tools = load_tools_file(ns.path)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"ghostprobe: cannot read tools from {ns.path}: {e}", file=sys.stderr)
            return 2
        findings = analyze_server(tools)
        return _finish(findings, ns.path, ns)

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
        return _finish(findings, target, ns)

    if ns.cmd == "canary":
        args = [a for a in ns.args if a != "--"]
        target = " ".join([ns.command, *args])
        print(
            f"ghostprobe: canary probe will CALL the read-only tools on '{target}'. "
            "Tools that send data out or run code are skipped.",
            file=sys.stderr,
        )
        try:
            from .client import probe_live_stdio
            results = probe_live_stdio(ns.command, args, timeout=ns.timeout)
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
        return _finish_canary(results, target, ns)

    if ns.cmd == "canary-http":
        headers = _parse_headers(ns.header)
        print(
            f"ghostprobe: canary probe will CALL the read-only tools on '{ns.url}'. "
            "Tools that send data out or run code are skipped.",
            file=sys.stderr,
        )
        try:
            from .client import probe_live_http
            results = probe_live_http(ns.url, headers=headers, timeout=ns.timeout, transport=ns.transport)
        except ImportError:
            print("ghostprobe: live probing needs the MCP SDK. Run: pip install mcp", file=sys.stderr)
            return 2
        except BaseException as e:  # anyio/httpx failures are varied
            if ns.debug:
                import traceback
                traceback.print_exc()
            print(f"ghostprobe: could not probe server: {_format_exc(e)}", file=sys.stderr)
            print(
                "  hints: check the URL and that the server is reachable; a server that "
                "speaks only SSE needs --transport sse (auto tries it second). Re-run "
                "with --debug for the full traceback, or --timeout 120.",
                file=sys.stderr,
            )
            return 2
        return _finish_canary(results, ns.url, ns)

    if ns.cmd == "scan-output":
        try:
            text = sys.stdin.read() if ns.path == "-" else Path(ns.path).read_text(encoding="utf-8")
        except OSError as e:
            print(f"ghostprobe: cannot read {ns.path}: {e}", file=sys.stderr)
            return 2
        findings = analyze_tool_output(ns.tool, text)
        return _finish(findings, f"output of {ns.tool}", ns)

    if ns.cmd == "diff":
        try:
            old_tools = load_tools_file(ns.old)
            new_tools = load_tools_file(ns.new)
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"ghostprobe: cannot read snapshots: {e}", file=sys.stderr)
            return 2
        findings = diff_tools(old_tools, new_tools)
        return _finish(findings, f"{ns.old} -> {ns.new}", ns)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
