# mcp-defense-bench (Python)

Score any **Python MCP defence** — a FastMCP middleware, a policy gate, a gateway — on the
[mcp-defense-bench](https://github.com/Gowthaman90/mcp-defense-bench) corpus, and get the **same
numbers as the JS leaderboard**: CorpusRobustCoverage per vector, per family and in total, plus
the false-positive rate on 337 benign, real-world tool definitions and results, with a Wilson 95% interval.

Scanners tell you what a server *looks* like, and unit tests tell you whether your server works.
This tells you **how well a runtime defence catches attacks it was not tuned on, and how often it
blocks legitimate traffic** — and fails your CI when either gets worse.

- **Byte-for-byte parity** with the JS scorer (`bin/run.mjs`) on the dev and benign corpora, enforced by tests.
- **Zero runtime dependencies.** The rubric and corpora are vendored at a pinned bench commit and checked against a sha256 manifest on every load.
- **pytest plugin**: `pytest --mcp-defense=my_guard:Guard` fails when coverage drops or false positives rise against a committed baseline.
- **FastMCP adapter**: each fixture runs through a real in-memory FastMCP server with your middleware mounted.
- Python 3.10–3.14. Apache-2.0.

## Install

```bash
pip install mcp-defense-bench            # scorer, CLI, pytest plugin
pip install "mcp-defense-bench[fastmcp]" # + the FastMCP middleware adapter
```

## Score a defence

```bash
mcp-defense-bench run my_package.guard:Guard --corpus all
```

`my_package.guard:Guard` can be any of these:

| What `Guard` is | What happens |
|---|---|
| A FastMCP `Middleware` class, or a factory that returns one | Wrapped in `FastMCPAdapter`; a fresh instance is built for each fixture |
| An adapter class or instance (see below) | Used directly |
| A module with `assess()` and `meta` | Used like a JS `adapter.mjs` |

The output is the JS runner's JSON. `--out-dir results/` writes `results/<tool>.json`,
`results/benign/<tool>.json` and `results/coverage/<tool>.json` in the bench's own layout, so
the files can be submitted to the leaderboard.

From Python:

```python
from mcp_defense_bench import run

dev = run("my_package.guard:Guard")                     # dev corpus (default)
benign = run("my_package.guard:Guard", corpus="benign")
print(dev["summary"]["overall"], benign["summary"]["fpRate95ci"])
```

## Write an adapter

An adapter reports what the defence did with one input. It is the Python form of the bench's
[adapter contract](https://github.com/Gowthaman90/mcp-defense-bench/blob/main/adapters/CONTRACT.md).

```python
from mcp_defense_bench import AdapterMeta, Verdict

class Guard:
    meta = AdapterMeta(tool="my-guard", class_="runtime-proxy", reproducible=True,
                       fixture_types=("malicious-tool-definition", "benign-tool-definition"))

    async def assess(self, input, testcase):            # sync works too
        hit = my_engine.inspect(input)                   # your defence, on what it really sees
        return Verdict(detect=hit, enforce=hit and my_engine.blocks, signal="why")
```

`assess` is called on each case's malicious `fixture` and on its `benignControl`. Then:

- missing the attack scores **none**;
- catching it but also flagging the control scores **none**, with a false-positive flag;
- warning only scores **detect** (0.5);
- blocking scores **enforce** (1).

A vector's **CorpusRobustCoverage** is the mean over all its fixtures, evasion variants included.
`fixture_types` limits the adapter to inputs it can actually see; vectors of other types stay
`unknown` (not counted as misses), and skipped items leave the benign denominator.

**Integrity rule (from the bench):** report only what your defence actually inspects at runtime,
never what its rules *could* catch if pointed at data it never sees.

## FastMCP middleware

```python
from mcp_defense_bench import run
from mcp_defense_bench.adapters.fastmcp import FastMCPAdapter

run(FastMCPAdapter(MyMiddleware, warn_logger="my_guard"), corpus="benign")
```

For each fixture the adapter serves the fixture's tools from a fresh `FastMCP` server, mounts
your middleware, and drives it with `fastmcp.Client` over the in-memory transport. It then
replays the same traffic without the middleware and compares the two runs.

| Fixture type | MCP traffic |
|---|---|
| `malicious-` / `benign-tool-definition` | `tools/list` |
| `tool-call` | `tools/call` with the fixture's arguments |
| `malicious-` / `benign-tool-result` | `tools/call`; the tool returns the fixture's result (no `call` in the fixture: placeholder values for the tool's required arguments) |
| `tool-call-sequence` | each call in order, in one session |
| `definition-change` | `tools/list`, swap the definition, `tools/list` again (rug-pulls) |

The middleware scores **enforce** if it raises, returns an error, stops the call reaching the
tool, hides or rewrites a definition, or rewrites the arguments or the result. It scores
**detect** if it only logs a WARNING (or worse) on `warn_logger`. Other fixture types (HTTP
transport, registries, delegation tokens, …) can't be expressed as FastMCP traffic, so they
stay `unknown`.

See [`examples/keyword_guard.py`](examples/keyword_guard.py), a deliberately naive guard, and
[`examples/mcp_assure_example.py`](examples/mcp_assure_example.py), which scores mcp-assure with
its shipped `baseline` pack and with an operator pack built from each served tool's schema.

## Stdio proxies

Many defences are not middleware but a command you put in front of the server's launch command
(`my-proxy --policy p.yaml -- python server.py`). `StdioProxyAdapter` scores one as it ships:

```python
from mcp_defense_bench.adapters.stdio import StdioProxyAdapter


def my_proxy():
    return StdioProxyAdapter("my-proxy", wrap=["my-proxy", "--policy", "p.yaml", "--"], warn_pattern=r"WARNING")
```

```bash
mcp-defense-bench run my_package.bench:my_proxy --corpus all
pytest --mcp-defense=my_package.bench:my_proxy
```

For each input it starts a fixture server (`python -m mcp_defense_bench.adapters.stdio_server`,
which serves the same tools and results as the FastMCP adapter), drives it with `fastmcp.Client`
over stdio once directly and once through your proxy, and compares the two runs. The verdict
rules are the FastMCP adapter's, except that **detect** is a stderr line matching `warn_pattern`.

`wrap` is either a command prefix (the server command is appended) or a function
`wrap(server_cmd, workdir) -> (cmd, extra_env)` for a proxy that needs per-run files or
environment. `workdir` is a fresh temporary directory per run, so pins, audit logs or a `HOME`
never leak between inputs. Both runs start from the MCP SDK's minimal default environment, so
`mcp-defense-bench` must be installed in the interpreter that runs the bench. Two process starts
per input make a full `--corpus all` run take minutes.

[`examples/mcp_gate_example.py`](examples/mcp_gate_example.py) (mcp-gate-policy) and
[`examples/agentx_mcp_example.py`](examples/agentx_mcp_example.py) (agentx-mcp) score two
shipped proxies this way.

## Fail CI on regressions (pytest)

```bash
pytest --mcp-defense=my_package.guard:Guard --mcp-defense-update-baseline   # once; commit the file
pytest --mcp-defense=my_package.guard:Guard                                 # in CI
```

Or configure it once:

```toml
[tool.pytest.ini_options]
mcp_defense = "my_package.guard:Guard"
mcp_defense_baseline = "tests/mcp-defense-baseline.json"
# mcp_defense_corpus = "all"   # dev, benign or all
# mcp_defense_tolerance = "0"  # allowed CorpusRobustCoverage drop
```

The plugin adds three test items:

- `mcp-defense::dev-coverage` fails if total or any per-vector CorpusRobustCoverage fell.
- `mcp-defense::dev-false-positives` fails if more matched controls are flagged.
- `mcp-defense::benign-false-positives` fails if more benign items are flagged.

The summary prints the headline numbers. A session fixture, `mcp_defense_results`, gives your
own tests the full result documents. Without pytest, `mcp-defense-bench check SPEC --baseline FILE`
applies the same gate and exits 1 on a regression.

## Totals per family and per denominator

```bash
mcp-defense-bench totals results/my-guard.json --markdown
```

This prints the leaderboard's "published vs all vectors" row: the 32 vectors published before
v0.9, all 37, and the 5-vector `delegation` family. `--heldout FILE` adds the held-out totals
from a recorded held-out run.

## The held-out corpus

The bench's held-out set (63 fixtures, 29 vectors) is a **one-shot** generalisation test. Score
a defence on it once, at a frozen version, after all tuning on the dev corpus is done
([protocol](https://github.com/Gowthaman90/mcp-defense-bench/blob/main/docs/HELD-OUT-PROTOCOL.md)).

To protect it:

- The held-out set is **not vendored**. The manifest holds only its file hashes and counts.
- Scoring it needs a bench checkout and an explicit acknowledgement:

```bash
mcp-defense-bench run my.guard:Guard --corpus heldout --bench-path ../mcp-defense-bench --heldout-confirm my-guard
```

`mcp-defense-bench verify --bench-path ../mcp-defense-bench` checks a checkout's hashes and
counts, including the held-out set's, without scoring anything.

## Parity with the JS scorer

The tests replay the verdicts recorded by the JS runner for four tools (`null-baseline`,
`mcp-bastion`, `mcp-firewall` and `pipelock`) through the Python scorer. On both the dev and
benign corpora, the output must equal the recorded `results/*.json` **byte for byte**, apart
from the `measuredAt` timestamp. The suite also checks:

- the per-vector coverage against each `coverage.json`;
- the totals rows against the generated `LEADERBOARD.md`;
- a live Python run of the null baseline.

Three porting traps are handled in `jscompat.py`:

- JS `toFixed` rounds a tie up; Python rounds half to even. `(0.25).toFixed(1)` is `"0.3"`, but `f"{0.25:.1f}"` is `"0.2"`.
- Python 3.12+ `sum()` compensates floating-point error; JS `reduce` is a plain left fold.
- `JSON.stringify` writes numbers differently: `1` for `1.0`, and different exponent cut-offs.

## Pinned versions

| | |
|---|---|
| Bench | mcp-defense-bench 0.9.0 (tag `v0.9.0`, commit `c4a4863`) |
| Rubric | 0.9.0, 37 vectors |
| Dev corpus | 66 cases |
| Benign corpus | 337 items |
| Held-out corpus | 63 cases (hashes only) |
| FastMCP adapter | `fastmcp>=4.0,<5` (MCP SDK v2) |

Run `mcp-defense-bench info` to see these, and `mcp-defense-bench verify` to check the vendored data.

## Licence

Apache-2.0. The vendored rubric and corpora come from mcp-defense-bench (Apache-2.0); see [NOTICE](NOTICE).
