# Changelog

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
