"""The ghostprobe analysis engine.

Pure functions over MCP tool definitions (plain dicts with name / description /
inputSchema). No network, no SDK, so the whole engine is testable offline and
can analyse a saved `tools/list` dump as easily as a live server.

The core threat: an MCP tool's description and parameter docs land directly in
the model's context with prompt-level authority. A malicious or careless server
can therefore smuggle instructions to the agent (tool poisoning, CVE-2025-54136),
and a server that combines private-data access, an external-comms sink, and
exposure to untrusted content gives an attacker the "lethal trifecta" needed to
exfiltrate data.
"""
from __future__ import annotations

import re
import unicodedata

from .findings import Finding

# --------------------------------------------------------------------------
# Tool poisoning: imperative instructions aimed at the *model*, hidden inside
# text that a human skims as a harmless tool description.
# --------------------------------------------------------------------------
_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    (r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above)", "high", "instruction override"),
    (r"disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|earlier|instructions)", "high", "instruction override"),
    (r"do\s+not\s+(tell|inform|mention|reveal|notify|disclose)", "high", "concealment instruction"),
    (r"without\s+(telling|informing|notifying|alerting)\s+the\s+user", "high", "concealment instruction"),
    (r"\bsecretly\b", "high", "concealment instruction"),
    (r"before\s+(using|calling|running|invoking)\s+this\s+tool,?\s+you\s+(must|should|need|have)", "high", "preconditioning instruction"),
    (r"always\s+(include|send|append|forward|cc|copy)", "high", "forced-action instruction"),
    (r"(send|forward|exfiltrate|leak|post|upload)\b.{0,40}\b(to|at)\s+\S+@|https?://", "critical", "exfiltration instruction"),
    (r"<\s*(system|important|secret|instructions?|admin)\s*>", "high", "embedded instruction tag"),
    (r"(you\s+are\s+(an?|now)\s+|act\s+as\s+)(an?\s+)?(ai|assistant|agent|system)", "medium", "role reassignment"),
    (r"\b(important|attention|system|note)\s*:\s*\S", "low", "embedded directive"),
]

# Capability classification. Verb-aware on purpose: the danger from "untrusted
# content" is *ingesting* attacker-influenceable text (a read action), so a
# noun alone is not enough. "send_email" is a sink, not an untrusted-input leg,
# even though the word "email" appears in it. Getting this wrong turns the
# lethal-trifecta check into a false-positive machine.
_READ_VERBS = r"\b(read|reads|get|gets|list|lists|fetch|fetches|load|loads|open|opens|cat|search|searches|query|queries|browse|browses|scrape|scrapes|crawl|crawls|receive|receives|pull|pulls|view|views|dump|dumps|export|exports|download|downloads|retrieve|retrieves)\b"
_SEND_VERBS = r"\b(send|sends|post|posts|put|puts|upload|uploads|push|pushes|publish|publishes|notify|notifies|forward|forwards|share|shares|tweet|tweets|deliver|delivers|transmit|transmits|emit|emits|email|emails|message|messages)\b"
_EXTERNAL_MEDIUM = r"\b(http|https|url|urls|web|webhook|email|emails|mail|smtp|sms|slack|discord|telegram|api|remote|external|outbound|internet|network)\b"
_PRIVATE_DATA = r"\b(file|files|directory|directories|folder|folders|note|notes|document|documents|docs|db|database|databases|sql|secret|secrets|credential|credentials|token|tokens|key|keys|keychain|env|environment|password|passwords|inbox|contact|contacts|calendar|history|local|disk|filesystem|home)\b"
_UNTRUSTED_SOURCE = r"\b(web|url|urls|http|https|browse|browser|scrape|crawl|rss|feed|feeds|comment|comments|issue|issues|review|reviews|inbox|email|emails|mail|message|messages|webhook|incoming|external|untrusted|page|pages|remote|internet)\b"
_EXEC_PATTERN = r"\b(exec|execute|executes|run|runs|shell|bash|sh|command|commands|cmd|eval|spawn|subprocess|python|node|script|scripts|system|terminal)\b"


def _tool_text(tool: dict) -> str:
    """All human-language text a tool contributes to the model's context:
    its description plus every parameter description in the input schema."""
    parts = [str(tool.get("description") or "")]
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    if isinstance(schema, dict):
        props = schema.get("properties") or {}
        if isinstance(props, dict):
            for p in props.values():
                if isinstance(p, dict) and p.get("description"):
                    parts.append(str(p["description"]))
    return "\n".join(x for x in parts if x)


def _hidden_unicode(text: str) -> list[tuple[str, int]]:
    """Invisible / tag characters used to smuggle instructions past human
    review while still reaching the model. Returns (kind, codepoint) hits."""
    hits: list[tuple[str, int]] = []
    for ch in text:
        o = ord(ch)
        if 0xE0000 <= o <= 0xE007F:
            hits.append(("unicode-tag", o))
        elif ch in ("​", "‌", "‍", "⁠", "﻿"):
            hits.append(("zero-width", o))
        elif unicodedata.category(ch) == "Cf" and ch not in "\n\r\t":
            hits.append(("format-control", o))
    return hits


def classify_capabilities(tool: dict) -> set[str]:
    """Which capability buckets a tool plausibly touches, from name + text.

    - data: exposes private/local data (noun is enough; access is the risk).
    - sink: a send action over an external medium (verb + medium required).
    - untrusted: ingests attacker-influenceable content (read verb + external
      source required, so a pure send is not misread as input).
    - exec: runs code or shell.
    """
    blob = (str(tool.get("name") or "") + " " + _tool_text(tool)).lower()
    caps: set[str] = set()
    if re.search(_PRIVATE_DATA, blob):
        caps.add("data")
    if re.search(_SEND_VERBS, blob) and re.search(_EXTERNAL_MEDIUM, blob):
        caps.add("sink")
    if re.search(_READ_VERBS, blob) and re.search(_UNTRUSTED_SOURCE, blob):
        caps.add("untrusted")
    if re.search(_EXEC_PATTERN, blob):
        caps.add("exec")
    return caps


def analyze_tool(tool: dict) -> list[Finding]:
    """All findings for a single tool definition."""
    name = str(tool.get("name") or "<unnamed>")
    text = _tool_text(tool)
    out: list[Finding] = []

    for pat, severity, label in _INJECTION_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            out.append(Finding(
                owasp="MCP01",
                severity=severity,
                tool=name,
                title=f"Tool description contains an {label}",
                detail=(
                    "This tool's description or parameter docs are injected into "
                    "the agent's context with prompt-level authority. The matched "
                    "phrasing reads as an instruction to the model, not a "
                    "description for the user. This is the tool-poisoning pattern "
                    "behind CVE-2025-54136."
                ),
                evidence=_snippet(text, m.start(), m.end()),
            ))

    hidden = _hidden_unicode(text)
    if hidden:
        kinds = sorted({k for k, _ in hidden})
        out.append(Finding(
            owasp="MCP01",
            severity="critical",
            tool=name,
            title="Tool text contains hidden / invisible characters",
            detail=(
                "Invisible Unicode (" + ", ".join(kinds) + ") in tool text is a "
                "classic instruction-smuggling vector: a human reviewer sees a "
                "clean description while the model receives concealed content. "
                f"{len(hidden)} hidden character(s) found."
            ),
            evidence=", ".join(f"U+{cp:04X}" for _, cp in hidden[:8]),
        ))

    if "exec" in classify_capabilities(tool):
        out.append(Finding(
            owasp="MCP05",
            severity="medium",
            tool=name,
            title="Tool exposes code or command execution",
            detail=(
                "This tool appears to run shell commands or arbitrary code. "
                "Combined with any prompt-injection path it becomes remote code "
                "execution on the host. Confirm it is sandboxed and not reachable "
                "from untrusted content."
            ),
            evidence="",
        ))

    return out


def lethal_trifecta(tools: list[dict]) -> Finding | None:
    """Server-level check. If the toolset together covers private-data access,
    an external-comms sink, and exposure to untrusted content, an attacker who
    lands a single injection can read secrets and exfiltrate them. (Simon
    Willison's "lethal trifecta".)"""
    contributors: dict[str, list[str]] = {"data": [], "sink": [], "untrusted": []}
    for t in tools:
        caps = classify_capabilities(t)
        name = str(t.get("name") or "<unnamed>")
        for leg in contributors:
            if leg in caps:
                contributors[leg].append(name)
    if all(contributors[leg] for leg in contributors):
        ev = "; ".join(
            f"{leg}: {', '.join(sorted(set(names))[:4])}"
            for leg, names in contributors.items()
        )
        return Finding(
            owasp="MCP04",
            severity="critical",
            tool="<server>",
            title="Lethal trifecta: data access + external sink + untrusted input",
            detail=(
                "The server's tools together provide all three capabilities an "
                "attacker needs to exfiltrate data: access to private data, a way "
                "to send data out, and a path for untrusted content to reach the "
                "agent. A single successful prompt injection can chain these into "
                "a data leak. Split these capabilities across isolated servers or "
                "gate the sink behind human approval."
            ),
            evidence=ev,
        )
    return None


def analyze_server(tools: list[dict]) -> list[Finding]:
    """Full analysis of a server's advertised toolset."""
    findings: list[Finding] = []
    for t in tools:
        findings.extend(analyze_tool(t))
    lt = lethal_trifecta(tools)
    if lt:
        findings.append(lt)
    findings.sort(key=lambda f: (-f.rank, f.owasp, f.tool))
    return findings


def _snippet(text: str, start: int, end: int, pad: int = 30) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    s = text[a:b].replace("\n", " ").strip()
    return ("..." if a > 0 else "") + s + ("..." if b < len(text) else "")
