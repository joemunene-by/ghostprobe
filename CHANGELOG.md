# Changelog

## v0.6.1: false-positive and robustness fixes

Two correctness fixes to the static analyzer and the tools-file loader.

- Supply chain (MCP09): the typosquat check no longer fuzzy-matches the short,
  generic reference names (`git`, `time`, `fetch`, `slack`). A one-edit neighbour
  of a 3-4 character name is almost always an ordinary tool (`get`, `times`), so
  those were false positives. The distinctive 6+ character names (`github`,
  `filesystem`, `postgres`, ...) are still matched, so a real near-miss like
  `gihub` is still caught.
- `scan-file` and `diff`: a tools file that is a JSON list of non-object entries
  now fails with a clean error and exit code 2 instead of an uncaught traceback.

4 new tests (86 total).

## v0.6.0 — canary over HTTP/SSE

The canary behavioral probe is no longer stdio-only. A new `canary-http` command
runs the identical probe against a remote MCP server over HTTP.

- Tries the current Streamable HTTP transport first and falls back to the older
  SSE transport; `--transport {auto,http,sse}` forces a choice.
- `-H 'Name: value'` (repeatable) passes auth and other headers, so a server
  behind a bearer token can be probed.
- The session loop is shared with the stdio probe, so what gets called, what
  gets skipped, and how output is analysed are identical across transports.

4 new tests (82 total).

## v0.5.0 — canary live probe (behavioral, MCP03 + cross-tool capture)

ghostprobe can now probe behavior, not just the advertised surface. The new
`canary` command connects to a live stdio server, calls its read-only tools with
a unique marker planted in their string inputs, and inspects what actually comes
back.

- Runs the MCP03 injection and hidden-character scan on real tool output, not
  only on a saved file via `scan-output`.
- Flags cross-tool capture (MCP04): if the marker planted in one tool's input
  surfaces in another tool's output, the server is persisting or reflecting one
  call into another, an exfiltration and injection surface a static scan cannot
  observe.
- Only calls tools that read. Anything classified as a send-to-external-medium
  (`sink`) or code/shell (`exec`) is skipped, and a tool whose required argument
  is not a string it can safely synthesise is skipped rather than guessed. What
  was called and skipped is printed to stderr.
- stdio transport only for now; HTTP/SSE canary probing is on the roadmap.

10 new tests (78 total).

## v0.4.0 — MCP06-10 coverage (full OWASP MCP Top 10)

ghostprobe now maps to all ten OWASP MCP categories. MCP06-10 are the ones the
standard itself frames as largely runtime properties, so coverage is scoped to
the subset that is statically observable from the advertised tool surface, and
each detector documents the runtime-only gap it does not close.

- MCP06 Auth / Token Handling: flags hardcoded secrets, tokens, API keys, JWTs
  and private keys baked into tool text or a schema default. Stands down for
  tools that document a proper auth handshake instead of embedding a key.
- MCP07 Insecure Transport: flags plaintext http:// or ws:// endpoints
  advertised in tool text or schema, excluding localhost (normal for a local
  server).
- MCP08 Confused Deputy / Consent: flags auto-approve, skip-confirmation, and
  act-on-behalf language, and stands down when a consent marker is present so a
  tool that documents its own gating is not flagged.
- MCP09 Supply Chain: flags unpinned version references (latest / * / floating
  ranges) and tool names within one or two edits of an official reference
  server (typosquat). Post-install tool mutation stays covered by MCP02.
- MCP10 Resource Exhaustion: flags unbounded or large fan-out operations
  (recursive / scan-all / entire-store) that expose no limit, page-size, or
  timeout parameter to rein them in.

The detectors read a wider static surface than the MCP01-05 checks: tool name,
all description text, schema property names, defaults, formats and enums, plus
any top-level metadata keys a server attaches. Honest-by-default: each stands
down on a mitigating signal so it flags footprints, not vocabulary.

21 new tests (68 total).

## v0.3.0 — allowlist suppression + review-driven docs

Acting on external review:

- Every finding now has a stable short `id` (a fingerprint over category, tool,
  and digit-normalised title). Pass `--allowlist <file>` on any command to
  suppress reviewed findings by id, so teams tune once and CI only fails on
  something new. Works across scan-file, stdio, scan-output, and diff.
- README fixes: install is now the correct from-source command (not the
  unpublished `pip install ghostprobe`); classification is stated explicitly as
  keyword/pattern heuristic, not runtime behavior; the OWASP MCP Top 10 is
  linked and noted as a beta framework; the `diff` snapshot workflow is
  documented.
- 7 new tests (47 total).

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
