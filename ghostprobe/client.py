"""Thin live-connection layer: spin up an MCP server over stdio, complete the
handshake, and return its advertised tools as plain dicts for the analyzer.

The `mcp` SDK is imported lazily so the analysis engine, the report layer, and
`ghostprobe scan-file` all work with zero third-party dependencies. You only
need `pip install mcp` to probe a live server.
"""
from __future__ import annotations


def fetch_tools_stdio(
    command: str, args: list[str], env: dict | None = None, timeout: float = 60.0
) -> list[dict]:
    """Connect to a stdio MCP server, list its tools, and normalise each into
    {"name", "description", "inputSchema"}. Raises on connection failure.

    The timeout bounds the MCP handshake and tools/list, applied with anyio's
    own ``fail_after`` rather than ``asyncio.wait_for``. Wrapping the SDK's
    anyio task groups in ``wait_for`` raises a cross-task cancel-scope error
    on timeout (with an empty message), so we let the one-time server spawn /
    download run unbounded and time-box only the protocol operations.
    """
    import asyncio

    async def _run() -> list[dict]:
        from contextlib import AsyncExitStack

        import anyio
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async with AsyncExitStack() as stack:
            params = StdioServerParameters(command=command, args=args, env=env)
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            with anyio.fail_after(timeout):
                await session.initialize()
                result = await session.list_tools()
            return [_normalize(t) for t in result.tools]

    return asyncio.run(_run())


def _normalize(tool) -> dict:
    """Accept either an SDK Tool object or a plain dict and return a plain dict."""
    if isinstance(tool, dict):
        return {
            "name": tool.get("name"),
            "description": tool.get("description"),
            "inputSchema": tool.get("inputSchema") or tool.get("input_schema"),
        }
    return {
        "name": getattr(tool, "name", None),
        "description": getattr(tool, "description", None),
        "inputSchema": getattr(tool, "inputSchema", None),
    }


def make_canary() -> str:
    """A unique marker to plant in a tool's input, distinctive enough that it
    cannot occur by chance in unrelated output."""
    import secrets

    return "GHOSTPROBE-CANARY-" + secrets.token_hex(8)


def _safe_to_call(tool: dict) -> tuple[bool, str]:
    """A canary probe only calls tools that read. A tool that sends to an
    external medium or runs code is skipped: calling it could act in the world,
    and its risk is already covered by the static surface scan."""
    from .analyzer import classify_capabilities

    caps = classify_capabilities(tool)
    if "exec" in caps:
        return False, "runs code or shell"
    if "sink" in caps:
        return False, "sends data to an external medium"
    return True, ""


def _build_args(tool: dict, canary: str) -> tuple[dict | None, str, bool]:
    """Fill a tool's required parameters so the call is valid, planting the
    canary in string inputs. Skip a tool that requires a non-string argument we
    cannot safely synthesise, rather than guess a value. Returns (args, reason,
    planted) where planted says whether the canary actually landed in the input."""
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    required = schema.get("required") or []
    args: dict = {}
    for name in required:
        spec = props.get(name, {})
        if spec.get("enum"):
            args[name] = spec["enum"][0]
        elif spec.get("type") in (None, "string"):
            args[name] = canary
        elif "default" in spec:
            args[name] = spec["default"]
        else:
            return None, f"requires non-string argument '{name}'", False
    planted = any(v == canary for v in args.values())
    return args, "", planted


def _result_text(res) -> str:
    """Flatten an MCP call result (SDK object or dict) into its text content."""
    content = getattr(res, "content", None)
    if content is None and isinstance(res, dict):
        content = res.get("content")
    parts: list[str] = []
    for item in content or []:
        text = item.get("text") if isinstance(item, dict) else getattr(item, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


def probe_live_stdio(
    command: str, args: list[str], env: dict | None = None, timeout: float = 60.0
) -> list[dict]:
    """Connect to a stdio MCP server, then actively call its read-only tools with
    a planted canary and collect what each returns. One dict per tool with keys
    ``tool``, ``called``, ``reason``, ``canary`` and ``output``, ready for
    ``analyze_canary``. Raises on connection failure, like fetch_tools_stdio."""
    import asyncio

    async def _run() -> list[dict]:
        from contextlib import AsyncExitStack

        import anyio
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        results: list[dict] = []
        async with AsyncExitStack() as stack:
            params = StdioServerParameters(command=command, args=args, env=env)
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            with anyio.fail_after(timeout):
                await session.initialize()
                listed = await session.list_tools()
            for tool in (_normalize(t) for t in listed.tools):
                name = tool.get("name") or "<tool>"
                ok, reason = _safe_to_call(tool)
                if not ok:
                    results.append({"tool": name, "called": False, "reason": reason, "canary": None, "output": ""})
                    continue
                canary = make_canary()
                built, why, planted = _build_args(tool, canary)
                if built is None:
                    results.append({"tool": name, "called": False, "reason": why, "canary": None, "output": ""})
                    continue
                try:
                    with anyio.fail_after(timeout):
                        res = await session.call_tool(name, built)
                    results.append({
                        "tool": name, "called": True, "reason": "",
                        "canary": canary if planted else None, "output": _result_text(res),
                    })
                except Exception as e:
                    results.append({
                        "tool": name, "called": False,
                        "reason": f"call failed: {type(e).__name__}", "canary": None, "output": "",
                    })
        return results

    return asyncio.run(_run())
