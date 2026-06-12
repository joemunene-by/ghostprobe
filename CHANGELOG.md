# Changelog

## v0.2.3 — detect collaborative-write sinks (the GitHub-MCP trifecta)

Running against the GitHub server surfaced a false negative: it read private
repo contents and attacker-controllable issue text but ghostprobe found no
sink, so it missed the trifecta. Writing to a shared remote service (open an
issue, post a PR comment, push to a repo) is an exfiltration channel, distinct
from a local file write. Sink detection now covers collaborative-write verbs
plus a collaborative medium, so the documented GitHub-MCP exfiltration class is
flagged, while local filesystem writes correctly are not. Tool names are also
tokenized on underscores/hyphens so `create_pull_request_review` matches.

4 new tests (40 total).

## v0.2.2 — false-positive fixes from real-server runs

Probing the official reference servers surfaced two false positives, now fixed:

- `read_text_file` on the filesystem server was flagged as code execution
  because "file system" matched a bare "system" keyword. Exec detection now
  requires a real execution verb plus an object (run/execute a command/code/
  shell), so reading a file is no longer mistaken for RCE.
- `sequentialthinking` was flagged as private-data access because "thought
  history" matched "history". Dropped "history" as a data signal.

Added regression tests for both. A security tool's credibility dies on false
positives, so these matter more than features.

## v0.2.1 — capability inventory + reliable live probing

- Every scan now ends with an info-level **capability inventory**: which tools
  give data access, an external sink, untrusted-input ingress, or code
  execution. A quiet scan still tells you the attack surface an injection could
  reach.
- Fixed live `stdio` probing returning an empty error. The MCP SDK's anyio task
  groups were being cancelled by `asyncio.wait_for`, raising a cancel-scope
  error with no message. Now timed out with anyio's `fail_after`, default 60s,
  with `--timeout` and `--debug` flags and exception-group-aware error output.

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
