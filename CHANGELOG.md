# Changelog

## 0.2.0 — 2026-10-17

- `StdioProxyAdapter` (`mcp_defense_bench.adapters.stdio`): scores a stdio MCP proxy as it ships,
  by running each fixture through a fixture server (`python -m mcp_defense_bench.adapters.stdio_server`)
  once directly and once behind the proxy. `wrap=` takes a command prefix or a
  `wrap(server_cmd, workdir) -> (cmd, env)` function; `warn_pattern=` scores matching stderr lines
  as detect. Promoted from the examples, so `pytest --mcp-defense=...` works on a proxy without
  vendoring them.
- `FastMCPAdapter` and `StdioProxyAdapter`: a `malicious-`/`benign-tool-result` fixture that gives
  no `call` is now called with placeholder values for the tool's required arguments (first `enum`
  value, else `"x"`, `0`, `false`, `[]`, `{}`) instead of `{}`. A schema-enforcing gate used to
  refuse both arms of such a case, a spurious matched false positive (dev:
  `indirect-retrieval-injection/002`, `response-injection/001`). Recorded JS results are
  unaffected: no JS adapter sends MCP traffic for result fixtures.
- Examples: mcp-assure with an operator pack built from each served tool's schema; mcp-gate-policy
  and agentx-mcp scored through `StdioProxyAdapter`.

## 0.1.0 — 2026-10-16

First release: a Python port of the mcp-defense-bench scorer.

- Scorer reproducing `bin/run.mjs` byte for byte on the dev and benign corpora (CorpusRobustCoverage,
  Capability, Guaranteed, matched-control and benign false positives, Wilson 95% interval, `scoreCap`,
  `fixtureTypes`).
- Rubric 0.9.0 (37 vectors), dev (66 cases) and benign (337 items) corpora vendored from bench
  `c4a4863` with a sha256 manifest checked on load; held-out corpus recorded as hashes and counts only,
  and scored only from a checkout with `--heldout-confirm`.
- Totals per family and per denominator (published 32 / all 37 / `delegation` 5) and per protocol
  revision, matching the JS leaderboard.
- Adapter contract (`Verdict`, `AdapterMeta`, sync or async `assess`), `load_adapter("module:Attr")`,
  null-baseline and replay adapters.
- `FastMCPAdapter`: runs each fixture through a real in-memory FastMCP 4 server with the middleware mounted.
- CLI `mcp-defense-bench run | check | verify | totals | info`.
- pytest plugin: `--mcp-defense`, baseline file, three regression items, `mcp_defense_results` fixture.
