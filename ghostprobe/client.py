"""Thin live-connection layer: spin up an MCP server over stdio, complete the
handshake, and return its advertised tools as plain dicts for the analyzer.

The `mcp` SDK is imported lazily so the analysis engine, the report layer, and
`ghostprobe scan-file` all work with zero third-party dependencies. You only
need `pip install mcp` to probe a live server.
"""
from __future__ import annotations


def fetch_tools_stdio(
    command: str, args: list[str], env: dict | None = None, timeout: float = 20.0
) -> list[dict]:
    """Connect to a stdio MCP server, list its tools, and normalise each into
    {"name", "description", "inputSchema"}. Raises on connection failure."""
    import asyncio

    async def _run() -> list[dict]:
        from contextlib import AsyncExitStack

        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        async with AsyncExitStack() as stack:
            params = StdioServerParameters(command=command, args=args, env=env)
            read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            result = await session.list_tools()
            return [_normalize(t) for t in result.tools]

    return asyncio.run(asyncio.wait_for(_run(), timeout=timeout))


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
