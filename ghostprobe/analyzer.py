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
# A second kind of sink: writing to a shared / remote collaborative service
# (open a GitHub issue, post a comment, push to a repo, create a Notion page)
# is an exfiltration channel. This is distinct from writing a local file, so it
# needs a collaborative medium, not just any write verb. Catching this is what
# turns the GitHub server's read-private + read-issues + post-comment from
# "no findings" into the lethal trifecta it actually is.
_COLLAB_WRITE_VERBS = r"\b(create|creates|add|adds|post|posts|update|updates|write|writes|push|pushes|comment|comments|open|opens|submit|submits|publish|publishes|merge|merges|upload|uploads|reply|replies)\b"
_COLLAB_MEDIUM = r"\b(issue|issues|comment|comments|pull request|pull requests|pullrequest|pr|prs|review|reviews|gist|gists|repository|repositories|repo|repos|discussion|discussions|wiki|wikis|ticket|tickets|message|messages|channel|channels|page|pages|board|boards|card|cards|thread|threads)\b"
_PRIVATE_DATA = r"\b(file|files|directory|directories|folder|folders|note|notes|document|documents|docs|db|database|databases|sql|secret|secrets|credential|credentials|token|tokens|keychain|env|environment|password|passwords|inbox|contact|contacts|calendar|disk|filesystem)\b"
_UNTRUSTED_SOURCE = r"\b(web|url|urls|http|https|browse|browser|scrape|crawl|rss|feed|feeds|comment|comments|issue|issues|review|reviews|inbox|email|emails|mail|message|messages|webhook|incoming|external|untrusted|page|pages|remote|internet)\b"
# Exec needs a real execution verb plus an object, not a stray noun. "file
# system" must not read as code execution (a real false positive from the
# official filesystem server), so bare "system" / "terminal" are gone.
_EXEC_PATTERN = (
    r"\b(exec|execute|executes|executing|eval|subprocess|spawn|shell|bash|zsh|powershell)\b"
    r"|/bin/sh\b"
    r"|\b(run|runs|execute|executes|invoke|invokes)\s+(a\s+|an\s+|the\s+|arbitrary\s+)?"
    r"(shell\s+|terminal\s+|system\s+|os\s+)?(command|commands|code|script|scripts|binary)\b"
    r"|\barbitrary\s+code\b|\bcommand\s+(execution|injection)\b"
)

# --------------------------------------------------------------------------
# MCP06-10 static signals.
#
# Honesty note: the OWASP MCP standard frames MCP06 (auth/token), MCP07
# (transport), MCP08 (consent), MCP09 (supply chain) and MCP10 (DoS) as mostly
# RUNTIME properties: OAuth flow inspection, TLS probing, host consent UX,
# package provenance, and live resource measurement. ghostprobe is a black-box
# probe of an advertised tool surface, so it cannot observe those directly.
#
# What it CAN do, and all it claims to do here, is flag the statically
# observable footprints of each risk inside the surface a server advertises:
# the tool name, descriptions, parameter docs, and schema values (defaults,
# formats, enums) plus any top-level metadata keys the server attaches. Each
# detector below documents the residual runtime-only gap it does not cover.
# --------------------------------------------------------------------------

# MCP06: a literal secret/token/credential baked into advertised text or a
# schema default. A hardcoded credential a server hands the model is leaked the
# moment the tool list is fetched, and signals tokens are not handled through a
# proper auth flow. We match well-known token shapes plus credential-bearing
# default values, not the bare word "token" (which is normal in auth tooling).
_SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"\b(sk-[A-Za-z0-9]{16,}|sk-proj-[A-Za-z0-9_-]{16,})\b", "OpenAI-style API key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "GitHub token"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token"),
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id"),
    (r"\bAIza[0-9A-Za-z_-]{20,}\b", "Google API key"),
    (r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b", "JWT"),
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "private key"),
    (r"(?i)\b(api[_-]?key|secret|password|passwd|token|bearer|access[_-]?key)\b\s*[:=]\s*['\"]?[A-Za-z0-9._\-/+]{12,}", "credential assignment"),
]

# MCP07: an insecure transport endpoint advertised in tool text or schema. A
# plaintext http:// or ws:// URL (not pointing at localhost) is interception-
# and impersonation-exposed. localhost/127.0.0.1 over http is normal for a
# local server, so it is excluded.
_INSECURE_TRANSPORT = re.compile(
    r"\b(?:http|ws)://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[\w.-]+",
    re.IGNORECASE,
)

# MCP08: consent-bypass language. Text that tells the agent to act on the
# user's behalf automatically, skip confirmation, or remember an approval is a
# confused-deputy footprint: a sensitive action proceeds with no fresh consent.
_CONSENT_BYPASS: list[tuple[str, str]] = [
    (r"\bauto[-\s]?(approve|approv\w*|confirm\w*|accept\w*|execute\w*|run\w*)\b", "auto-approval language"),
    (r"\bwithout\s+(asking|confirming|confirmation|prompting|user\s+(approval|consent|confirmation))\b", "consent-skip language"),
    (r"\bno\s+(confirmation|approval|consent|prompt)\s+(is\s+)?(required|needed|necessary)\b", "consent-skip language"),
    (r"\b(skip|bypass|suppress)\s+(the\s+)?(confirmation|approval|consent|permission)\b", "consent-skip language"),
    (r"\b(remember|persist|save)\s+(this\s+|the\s+)?(approval|consent|permission)\b", "remembered-approval language"),
    (r"\bon\s+behalf\s+of\s+the\s+user\b", "act-on-behalf language"),
    (r"\bdo(es)?\s+not\s+require\s+(user\s+)?(approval|confirmation|consent)\b", "consent-skip language"),
]
# A consent marker nearby means the server is being explicit about asking; if
# present we stand down, to avoid flagging tools that document their own gating.
_CONSENT_MARKER = re.compile(
    r"\b(require[s]?\s+(user\s+)?(approval|confirmation|consent)|"
    r"ask[s]?\s+the\s+user|human[-\s]in[-\s]the[-\s]loop|prompt[s]?\s+for\s+(approval|confirmation|consent))\b",
    re.IGNORECASE,
)

# MCP09 (supply chain): an unpinned version reference in advertised metadata.
# "latest" / "*" / a caret/tilde range means the server can silently update.
_UNPINNED_VERSION = re.compile(
    r"(?i)\b(?:version|tag|ref)\s*[:=]\s*['\"]?(latest|\*|main|master|\^|~)|"
    r"@(?:latest|\*)\b|:latest\b"
)
# Names that look like a typosquat of an official reference server. The list is
# the @modelcontextprotocol reference servers; a name that is close-but-not-equal
# (edit distance 1-2, or a confusable suffix) is a provenance red flag.
_OFFICIAL_REF_SERVERS = (
    "filesystem", "fetch", "git", "github", "gitlab", "memory",
    "everything", "sequentialthinking", "time", "sqlite", "postgres",
    "puppeteer", "brave-search", "google-maps", "slack", "sentry",
)

# MCP10 (DoS): a tool that advertises an unbounded / large fan-out operation
# with no bound, limit, max, or timeout anywhere in its surface.
_UNBOUNDED_OP = re.compile(
    r"\b(all\s+(files|records|rows|pages|results|items|entries|users|repositories|repos|messages)"
    r"|every\s+(file|record|row|page|result|item|entry)"
    r"|entire\s+(database|filesystem|repository|repo|directory|tree|disk|history)"
    r"|recursive(ly)?|unlimited|unbounded|no\s+limit|without\s+(a\s+)?limit"
    r"|whole\s+(database|repository|repo|disk|filesystem))\b",
    re.IGNORECASE,
)
_BOUND_MARKER = re.compile(
    r"\b(limit|max|maximum|page[_\s-]?size|per[_\s-]?page|timeout|rate[_\s-]?limit"
    r"|count|top|batch[_\s-]?size|cap|bound|offset|cursor|first|last|head|tail)\b",
    re.IGNORECASE,
)


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


def _schema_props(tool: dict) -> dict:
    """The inputSchema properties dict, normalised, or {}."""
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict):
            return props
    return {}


def _tool_surface(tool: dict) -> str:
    """Every static string a tool advertises that the MCP06-10 detectors read:
    name, all description text, plus property names, defaults, enum values and
    formats from the input schema. Distinct from `_tool_text` (model-context
    text only) because supply-chain / transport / token signals live in schema
    values and metadata, not just human-language descriptions."""
    parts = [str(tool.get("name") or ""), _tool_text(tool)]
    # Top-level metadata keys some servers attach alongside the three core
    # fields (version, transport, url, endpoint, homepage, ...). We stringify
    # them so an http:// endpoint or an unpinned version is visible statically.
    for k, v in tool.items():
        if k in ("name", "description", "inputSchema", "input_schema"):
            continue
        parts.append(f"{k}={v!r}")
    for pname, p in _schema_props(tool).items():
        parts.append(str(pname))
        if isinstance(p, dict):
            for key in ("default", "format", "pattern", "examples", "enum", "const"):
                if key in p:
                    parts.append(f"{key}={p[key]!r}")
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
    # Split underscores/hyphens so tool names like create_pull_request_review
    # tokenize ("create pull request review") and the \b-anchored patterns match.
    blob = (str(tool.get("name") or "") + " " + _tool_text(tool)).lower()
    blob = blob.replace("_", " ").replace("-", " ")
    caps: set[str] = set()
    if re.search(_PRIVATE_DATA, blob):
        caps.add("data")
    send_external = re.search(_SEND_VERBS, blob) and re.search(_EXTERNAL_MEDIUM, blob)
    collab_write = re.search(_COLLAB_WRITE_VERBS, blob) and re.search(_COLLAB_MEDIUM, blob)
    if send_external or collab_write:
        caps.add("sink")
    if re.search(_READ_VERBS, blob) and re.search(_UNTRUSTED_SOURCE, blob):
        caps.add("untrusted")
    if re.search(_EXEC_PATTERN, blob):
        caps.add("exec")
    return caps


def _scan_phrases(text: str) -> list[tuple[str, str, str]]:
    """Every instruction-injection phrase in text as (severity, label, evidence).
    Shared by the tool-description analyzer (MCP01) and the tool-output
    analyzer (MCP03) so both detect the same poisoning patterns."""
    out: list[tuple[str, str, str]] = []
    for pat, severity, label in _INJECTION_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            out.append((severity, label, _snippet(text, m.start(), m.end())))
    return out


def analyze_tool(tool: dict) -> list[Finding]:
    """All findings for a single tool definition."""
    name = str(tool.get("name") or "<unnamed>")
    text = _tool_text(tool)
    out: list[Finding] = []

    for severity, label, evidence in _scan_phrases(text):
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
            evidence=evidence,
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

    # MCP06-10: statically observable footprints on this tool's surface.
    out.extend(detect_insecure_token_handling(tool))
    out.extend(detect_insecure_transport(tool))
    out.extend(detect_consent_bypass(tool))
    out.extend(detect_supply_chain(tool))
    out.extend(detect_resource_exhaustion(tool))

    return out


def _edit_distance_le(a: str, b: str, k: int) -> bool:
    """True iff Levenshtein(a, b) <= k. Short-circuits on length gap. Used to
    spot typosquats of the official reference-server names."""
    if abs(len(a) - len(b)) > k:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1] <= k


def detect_insecure_token_handling(tool: dict) -> list[Finding]:
    """MCP06 (static subset): a literal secret/token/credential exposed in a
    tool's advertised text or a schema default.

    Runtime gap: ghostprobe does NOT inspect OAuth scopes, token audience,
    token binding, or storage. Those need live auth-flow inspection. This only
    catches a credential a server hardcodes into its advertised surface, which
    is leaked to the model the instant the tool list is fetched."""
    name = str(tool.get("name") or "<unnamed>")
    surface = _tool_surface(tool)
    out: list[Finding] = []
    seen: set[str] = set()
    for pat, label in _SECRET_PATTERNS:
        m = re.search(pat, surface)
        if m and label not in seen:
            seen.add(label)
            out.append(Finding(
                owasp="MCP06", severity="critical", tool=name,
                title=f"Hardcoded secret in tool surface ({label})",
                detail=(
                    "A credential is baked into this tool's advertised text or a "
                    "schema default. It is exposed to the agent the moment the "
                    "tool list is fetched, and signals tokens are not brokered "
                    "through a proper auth flow. Rotate the secret and move it to "
                    "a runtime auth handshake. (Static check: ghostprobe does not "
                    "inspect OAuth scopes, audience, or binding.)"
                ),
                evidence=_snippet(surface, m.start(), m.end()),
            ))
    return out


def detect_insecure_transport(tool: dict) -> list[Finding]:
    """MCP07 (static subset): a plaintext http:// or ws:// endpoint advertised
    in tool text or schema (excluding localhost).

    Runtime gap: ghostprobe connects to stdio servers and does not probe TLS,
    server authentication, origin-header validation, or DNS-rebinding defenses
    on a live HTTP/SSE transport. This only flags an insecure endpoint a server
    advertises statically in its tool surface."""
    name = str(tool.get("name") or "<unnamed>")
    surface = _tool_surface(tool)
    m = _INSECURE_TRANSPORT.search(surface)
    if not m:
        return []
    return [Finding(
        owasp="MCP07", severity="high", tool=name,
        title="Insecure transport endpoint advertised",
        detail=(
            "This tool advertises a plaintext http:// or ws:// endpoint. Without "
            "TLS the transport is open to interception and the server cannot be "
            "authenticated, so the toolset an agent receives can be tampered "
            "with. Use https/wss and validate the origin. (Static check: "
            "ghostprobe does not actively probe TLS or origin validation.)"
        ),
        evidence=_snippet(surface, m.start(), m.end()),
    )]


def detect_consent_bypass(tool: dict) -> list[Finding]:
    """MCP08 (static subset): auto-approve / act-on-behalf language with no
    consent marker, the confused-deputy footprint.

    Runtime gap: ghostprobe does not evaluate the HOST's consent UX, whether a
    prompt shows the concrete action, or how remembered approvals are scoped.
    This only flags a tool that advertises skipping consent in its own text."""
    name = str(tool.get("name") or "<unnamed>")
    text = _tool_text(tool)
    if _CONSENT_MARKER.search(text):
        return []
    for pat, label in _CONSENT_BYPASS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return [Finding(
                owasp="MCP08", severity="high", tool=name,
                title=f"Consent-bypass language in tool description ({label})",
                detail=(
                    "This tool's text tells the agent to act without a fresh "
                    "consent prompt. The agent holds the user's authority, so a "
                    "tool that auto-approves or acts on the user's behalf is a "
                    "confused-deputy path: a later malicious call proceeds with "
                    "no human in the loop. Require per-call approval for "
                    "sensitive actions. (Static check: ghostprobe does not see "
                    "the host's actual consent flow.)"
                ),
                evidence=_snippet(text, m.start(), m.end()),
            )]
    return []


def detect_supply_chain(tool: dict) -> list[Finding]:
    """MCP09 (static subset): unpinned version metadata and typosquat-like
    names versus the official reference servers.

    Runtime gap: ghostprobe does not verify package signatures, provenance, or
    the dependency tree, and does not confirm the launch command. Post-install
    tool mutation is covered separately by MCP02 diffing. This only flags
    static provenance smells in the advertised surface."""
    name = str(tool.get("name") or "<unnamed>")
    out: list[Finding] = []
    surface = _tool_surface(tool)

    m = _UNPINNED_VERSION.search(surface)
    if m:
        out.append(Finding(
            owasp="MCP09", severity="medium", tool=name,
            title="Unpinned version reference in tool metadata",
            detail=(
                "An unpinned version (latest / * / a floating range) lets the "
                "server silently update to code you never reviewed, a supply-"
                "chain risk. Pin to an exact version or digest. (Static check: "
                "ghostprobe does not verify package signatures or provenance.)"
            ),
            evidence=_snippet(surface, m.start(), m.end()),
        ))

    low = name.lower().replace("_", "-")
    base = low.rsplit("-", 1)[-1] if "-" in low else low
    for ref in _OFFICIAL_REF_SERVERS:
        for cand in {low, base}:
            if cand and cand != ref and _edit_distance_le(cand, ref, 2 if len(ref) > 6 else 1):
                out.append(Finding(
                    owasp="MCP09", severity="medium", tool=name,
                    title="Tool name resembles an official reference server (possible typosquat)",
                    detail=(
                        f"This tool's name is one or two edits from the official "
                        f"'{ref}' reference server. Typosquatting an established "
                        "name is a distribution attack that rides the trust of "
                        "the original. Confirm provenance before installing. "
                        "(Static check: name-similarity heuristic, not a "
                        "registry/provenance lookup.)"
                    ),
                    evidence=f"{name!r} vs official {ref!r}",
                ))
                return out  # one typosquat finding per tool is enough
    return out


def detect_resource_exhaustion(tool: dict) -> list[Finding]:
    """MCP10 (static subset): an unbounded / large fan-out operation advertised
    with no bound, limit, or timeout anywhere in its surface.

    Runtime gap: ghostprobe does not MEASURE output size, execution time, or
    rate limits. Enforcement of bounds is a runtime policy property. This only
    flags a tool that advertises an unbounded operation and exposes no bounding
    parameter to rein it in."""
    name = str(tool.get("name") or "<unnamed>")
    surface = _tool_surface(tool)
    m = _UNBOUNDED_OP.search(surface)
    if not m or _BOUND_MARKER.search(surface):
        return []
    return [Finding(
        owasp="MCP10", severity="medium", tool=name,
        title="Unbounded operation with no advertised limit",
        detail=(
            "This tool advertises an unbounded or large fan-out operation "
            "(scan-all / recursive / entire-store) and exposes no limit, max, "
            "page-size, or timeout parameter to bound it. An agent can exhaust "
            "host resources, flood its own context, and run up cost. Add an "
            "enforced per-call cap and a timeout. (Static check: ghostprobe "
            "does not measure runtime output size or rate limits.)"
        ),
        evidence=_snippet(surface, m.start(), m.end()),
    )]


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


_CAP_LABELS = {
    "data": "private-data access",
    "sink": "external sink",
    "untrusted": "untrusted-input ingress",
    "exec": "code/shell execution",
}


def capability_inventory(tools: list[dict]) -> Finding | None:
    """An info-level map of the attack surface a server exposes to an agent.
    None of these is a vulnerability by itself; the value is seeing the surface
    so a quiet scan still tells you what an injection could reach."""
    buckets: dict[str, list[str]] = {k: [] for k in _CAP_LABELS}
    for t in tools:
        name = str(t.get("name") or "<unnamed>")
        for cap in classify_capabilities(t):
            buckets[cap].append(name)
    present = {k: v for k, v in buckets.items() if v}
    if not present:
        return None
    evidence = "  |  ".join(
        f"{_CAP_LABELS[k]}: {', '.join(sorted(set(v))[:6])}" for k, v in present.items()
    )
    return Finding(
        owasp="MCP04",
        severity="info",
        tool="<server>",
        title=f"Capability inventory ({len(tools)} tools)",
        detail=(
            "The attack surface this server exposes to an agent. None of these is "
            "a vulnerability on its own; the risk is in the combination and in what "
            "untrusted content can reach them."
        ),
        evidence=evidence,
    )


def analyze_server(tools: list[dict]) -> list[Finding]:
    """Full analysis of a server's advertised toolset."""
    findings: list[Finding] = []
    for t in tools:
        findings.extend(analyze_tool(t))
    lt = lethal_trifecta(tools)
    if lt:
        findings.append(lt)
    inv = capability_inventory(tools)
    if inv:
        findings.append(inv)
    findings.sort(key=lambda f: (-f.rank, f.owasp, f.tool))
    return findings


def analyze_tool_output(tool_name: str, output_text: str) -> list[Finding]:
    """MCP03: prompt injection via tool output. A tool that returns content
    carrying instructions is an indirect-injection path: if any part of that
    output is attacker-influenced (a fetched web page, an email body, an issue
    comment), the agent reads the attacker's instructions as if they were the
    user's. The detection patterns are the same as for poisoning."""
    out: list[Finding] = []
    detail = (
        "This tool returned content that reads as an instruction to the agent. "
        "If any part of this output is attacker-influenced (a fetched page, an "
        "email, a comment), it is an indirect prompt-injection path into the "
        "agent, which is the most common way tool-using agents get hijacked."
    )
    for severity, label, evidence in _scan_phrases(output_text):
        out.append(Finding(
            owasp="MCP03", severity=severity, tool=tool_name,
            title=f"Tool output contains an {label}",
            detail=detail, evidence=evidence,
        ))
    hidden = _hidden_unicode(output_text)
    if hidden:
        kinds = sorted({k for k, _ in hidden})
        out.append(Finding(
            owasp="MCP03", severity="critical", tool=tool_name,
            title="Tool output contains hidden / invisible characters",
            detail=(
                "Invisible Unicode (" + ", ".join(kinds) + ") in tool output "
                "smuggles instructions to the agent that a human watching the "
                "transcript cannot see."
            ),
            evidence=", ".join(f"U+{cp:04X}" for _, cp in hidden[:8]),
        ))
    out.sort(key=lambda f: (-f.rank, f.owasp))
    return out


def diff_tools(old_tools: list[dict], new_tools: list[dict]) -> list[Finding]:
    """MCP02: rug pull / tool mutation. A server can behave until it is trusted,
    then silently change a tool's description (to inject instructions) or add new
    capabilities. Snapshot the toolset and diff it across time to catch this."""
    out: list[Finding] = []
    old_by = {str(t.get("name")): t for t in old_tools}
    new_by = {str(t.get("name")): t for t in new_tools}

    for name in sorted(new_by.keys() - old_by.keys()):
        out.append(Finding(
            owasp="MCP02", severity="medium", tool=name,
            title="New tool appeared since the snapshot",
            detail=(
                "A server that adds tools after gaining trust can introduce "
                "capabilities or instructions you never reviewed. Re-audit the "
                "new tool before allowing it."
            ),
        ))
    for name in sorted(old_by.keys() - new_by.keys()):
        out.append(Finding(
            owasp="MCP02", severity="low", tool=name,
            title="Tool removed since the snapshot",
            detail="A previously advertised tool is gone. Confirm this is expected.",
        ))
    for name in sorted(old_by.keys() & new_by.keys()):
        o_text, n_text = _tool_text(old_by[name]), _tool_text(new_by[name])
        if o_text != n_text:
            introduced = len(_scan_phrases(n_text)) > len(_scan_phrases(o_text)) or (
                _hidden_unicode(n_text) and not _hidden_unicode(o_text)
            )
            out.append(Finding(
                owasp="MCP02",
                severity="critical" if introduced else "medium",
                tool=name,
                title=(
                    "Tool description mutated and introduced an injection pattern"
                    if introduced
                    else "Tool description changed since the snapshot"
                ),
                detail=(
                    "The tool's description changed between snapshots. Silent "
                    "mutation of a trusted tool's text is the rug-pull attack: "
                    "the server behaves until trusted, then changes what the "
                    "agent sees."
                ),
                evidence=f"was: {o_text[:70]!r} | now: {n_text[:70]!r}",
            ))
        if (old_by[name].get("inputSchema") or {}) != (new_by[name].get("inputSchema") or {}):
            out.append(Finding(
                owasp="MCP02", severity="low", tool=name,
                title="Tool input schema changed since the snapshot",
                detail="The parameter set changed; review for new injection sinks.",
            ))
    out.sort(key=lambda f: (-f.rank, f.owasp, f.tool))
    return out


def _snippet(text: str, start: int, end: int, pad: int = 30) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    s = text[a:b].replace("\n", " ").strip()
    return ("..." if a > 0 else "") + s + ("..." if b < len(text) else "")
