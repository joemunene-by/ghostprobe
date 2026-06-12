# Changelog

## v0.2.0 — rug-pull diffing (MCP02) and output-injection scanning (MCP03)

- `ghostprobe diff old.json new.json` snapshots and diffs a server's toolset.
  Flags new tools, removed tools, schema changes, and silent description
  mutation. A change that introduces an injection pattern is escalated to
  critical, which is the rug-pull attack: behave until trusted, then mutate.
- `ghostprobe scan-output <file>` scans a tool's returned text for instruction
  injection (MCP03), the indirect-injection path that hijacks tool-using agents
  when output is attacker-influenced.
- Shared the injection-pattern scanner across the description (MCP01) and output
  (MCP03) analyzers so both detect the same poisoning.
- 11 new offline tests (31 total).

## v0.1.0 — initial release

Dynamic red-team probe for MCP servers, mapped to the OWASP MCP Top 10. Tool
poisoning detection (instruction injection + hidden-Unicode smuggling,
CVE-2025-54136), verb-aware capability classification, lethal-trifecta
detection, and exec-capability flagging. `scan-file` and `stdio` commands with
`--json` and `--fail-on` gating. 20 tests, dependency-free analyzer.
