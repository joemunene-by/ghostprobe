"""Render findings as a human report or JSON, and compute a CI exit gate."""
from __future__ import annotations

import json

from .findings import Finding, SEVERITY_ORDER

_ICON = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED ]",
    "low": "[LOW ]",
    "info": "[INFO]",
}


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_text(findings: list[Finding], target: str) -> str:
    lines = [f"ghostprobe report for {target}", "=" * 60, ""]
    if not findings:
        lines.append("No findings. (Absence of findings is not proof of safety.)")
        return "\n".join(lines)
    counts = summarize(findings)
    summary = "  ".join(
        f"{s}:{counts[s]}" for s in ("critical", "high", "medium", "low", "info")
        if counts[s]
    )
    lines.append(f"{len(findings)} finding(s)   {summary}")
    lines.append("")
    for f in findings:
        lines.append(
            f"{_ICON.get(f.severity, '[????]')} {f.owasp} {f.category}  "
            f"({f.tool})  [id {f.fingerprint}]"
        )
        lines.append(f"    {f.title}")
        lines.append(f"    {f.detail}")
        if f.evidence:
            lines.append(f"    evidence: {f.evidence}")
        lines.append("")
    return "\n".join(lines)


def apply_allowlist(findings: list[Finding], allow: set[str]) -> tuple[list[Finding], int]:
    """Drop findings whose fingerprint is in ``allow``. Returns the kept
    findings and how many were suppressed, so teams can tune once in CI and
    stop seeing expected findings."""
    if not allow:
        return findings, 0
    kept = [f for f in findings if f.fingerprint not in allow]
    return kept, len(findings) - len(kept)


def render_json(findings: list[Finding], target: str) -> str:
    return json.dumps(
        {
            "target": target,
            "summary": summarize(findings),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )


def exit_code(findings: list[Finding], fail_on: str | None) -> int:
    """0 unless any finding is at or above the fail_on severity. Lets you run
    ghostprobe in CI against your own server and fail the build on a regression."""
    if not fail_on:
        return 0
    threshold = SEVERITY_ORDER.get(fail_on, 99)
    return 1 if any(f.rank >= threshold for f in findings) else 0
