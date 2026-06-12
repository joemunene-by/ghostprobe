"""Findings model and the OWASP MCP Top 10 mapping ghostprobe reports against."""
from __future__ import annotations

from dataclasses import dataclass

# OWASP MCP Top 10 (2026) categories ghostprobe maps its findings to. We cover
# the subset a dynamic black-box probe can actually observe from the outside.
OWASP_MCP = {
    "MCP01": "Tool Poisoning",
    "MCP02": "Rug Pull / Tool Mutation",
    "MCP03": "Prompt Injection via Tool Output",
    "MCP04": "Excessive Capability / Lethal Trifecta",
    "MCP05": "Sensitive Capability Exposure",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """One issue ghostprobe found, mapped to an OWASP MCP Top 10 category."""

    owasp: str        # e.g. "MCP01"
    severity: str     # info | low | medium | high | critical
    tool: str         # the tool name, or "<server>" for server-wide findings
    title: str
    detail: str
    evidence: str = ""

    @property
    def category(self) -> str:
        return OWASP_MCP.get(self.owasp, "Unknown")

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict:
        return {
            "owasp": self.owasp,
            "category": self.category,
            "severity": self.severity,
            "tool": self.tool,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }
