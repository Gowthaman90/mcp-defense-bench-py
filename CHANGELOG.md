# Changelog

## 0.3.0 — 2026-10-29

Scores against mcp-defense-bench **0.10.0** (tag `v0.10.0`, commit `8f08125`, DOI
10.5281/zenodo.23712070), which adds a pre-registered runtime-authorization family.

- Rubric 0.10.0: 37 → **41 vectors**. The new `authorization` family has four vectors:
  `authz-unentitled-tool`, `authz-argument-overreach`, `authz-delegated-agent-overreach` and
  `authz-asserted-identity`. Dev corpus 66 → **78 cases** (12 `authorized-call`). Benign corpus
  unchanged (337 items). Held-out 63 → 75 cases, still recorded as hashes and counts only.
- `authorized-call` fixtures: scored like every other matched case (no `scoreCap` in this family).
  The adapter contract docs say what an adapter for them must do: translate the fixture's
  `policy` into the defence's own language, map the `caller` to credentials it verifies, and report
  a rule it can't express as a miss with the reason in `signal`. The package scores adapters; it
  does not evaluate policies.
- `meta.unwiredFixtureTypes` (`AdapterMeta(unwired_fixture_types=...)`), as in the bench's
  `bin/run.mjs`: the fixture types an adapter is not wired for yet. Like `fixtureTypes`, cases it
  is not wired for are not run, their vectors stay `unknown` (not a miss), and they leave the
  benign denominator. `scoring.wired()` now matches the JS rule for both fields, and
  `scoring.unwired_counts()` counts the skipped cases per fixture type.
- `ReplayAdapter` takes `fixture_types=` / `unwired_fixture_types=`, or `cases=` to infer the
  fixture types the record holds, so results recorded from a tool wired for some types only
  (agentgateway and ToolHive: `authorized-call` only) replay byte for byte. Its error for a case
  with no recorded verdict now names the fixture type.
- CLI: `run` lists the cases an adapter is not wired for, per fixture type. The totals line now has
  the `authorization` family and says "not wired" for a subset the adapter never ran on, as the
  leaderboard does (it printed 0% before). `info` prints the subset sizes (published 32, all 41,
  delegation 5, authorization 4).
- `FastMCPAdapter` and `StdioProxyAdapter` are not wired for `authorized-call` (an in-memory or
  stdio session has no authenticated caller), so those 4 vectors stay `unknown` for them.
- Parity: the tests now replay all six tools the bench records at v0.10.0. agentgateway and
  ToolHive are new and dev-only. Every dev and benign result is byte-identical to the JS
  `results/*.json`. The tests also check the authorization family against the bench's
  2026-10-27 scoring changelog: mcp-bastion, agentgateway and ToolHive 100%, mcp-firewall 42%
  (1.7/4), pipelock and null-baseline 0%, no false positives on any authorization control.
- Baselines recorded with 0.2.0 (rubric 0.9.0) are rejected with "re-create the baseline", as for
  any rubric change.
- `scripts/vendor_bench.py` also vendors the recorded results of tools with no benign run.

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
