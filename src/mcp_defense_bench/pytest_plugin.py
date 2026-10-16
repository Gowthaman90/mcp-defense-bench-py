"""pytest plugin: fail CI when a defence's coverage drops or its false positives rise.

    pytest --mcp-defense=my_guard:Guard                       # compare with mcp-defense-baseline.json
    pytest --mcp-defense=my_guard:Guard --mcp-defense-update-baseline

or configure it once in ``pyproject.toml``::

    [tool.pytest.ini_options]
    mcp_defense = "my_guard:Guard"
    mcp_defense_baseline = "tests/mcp-defense-baseline.json"

It adds three test items — ``mcp-defense::dev-coverage``, ``mcp-defense::dev-false-positives``
and ``mcp-defense::benign-false-positives`` — and a session fixture ``mcp_defense_results`` with
the full result documents for custom assertions. Inert unless a defence is configured.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from mcp_defense_bench.adapters import load_adapter
from mcp_defense_bench.baseline import Comparison, compare, load_baseline, make_baseline, write_baseline
from mcp_defense_bench.runner import run

CHECKS = {
    "dev-coverage": "dev",
    "dev-false-positives": "dev",
    "benign-false-positives": "benign",
}

_state_key = pytest.StashKey[dict[str, Any]]()


def pytest_addoption(parser: pytest.Parser) -> None:
    g = parser.getgroup("mcp-defense", "MCP defence regression gate (mcp-defense-bench)")
    g.addoption(
        "--mcp-defense",
        dest="mcp_defense",
        metavar="MODULE:ATTR",
        help="defence to score: adapter, factory or FastMCP Middleware",
    )
    g.addoption(
        "--mcp-defense-baseline",
        dest="mcp_defense_baseline",
        metavar="PATH",
        help="baseline file (default mcp-defense-baseline.json in rootdir)",
    )
    g.addoption(
        "--mcp-defense-update-baseline",
        action="store_true",
        dest="mcp_defense_update",
        help="write the baseline from this run instead of comparing",
    )
    g.addoption(
        "--mcp-defense-corpus", dest="mcp_defense_corpus", choices=["dev", "benign", "all"], help="corpora to score (default all)"
    )
    g.addoption(
        "--mcp-defense-tolerance", dest="mcp_defense_tolerance", type=float, help="allowed CorpusRobustCoverage drop (default 0)"
    )
    g.addoption(
        "--mcp-defense-bench-path",
        dest="mcp_defense_bench_path",
        metavar="PATH",
        help="score from a bench checkout instead of the vendored snapshot",
    )
    parser.addini("mcp_defense", "defence spec MODULE:ATTR", default="")
    parser.addini("mcp_defense_baseline", "baseline file path, relative to rootdir", default="mcp-defense-baseline.json")
    parser.addini("mcp_defense_corpus", "dev, benign or all", default="all")
    parser.addini("mcp_defense_tolerance", "allowed coverage drop", default="0")
    parser.addini("mcp_defense_bench_path", "bench checkout path (optional)", default="")


def _opt(config: pytest.Config, name: str) -> Any:
    v = config.getoption(name)
    return v if v not in (None, "") else (config.getini(name) or None)


def _settings(config: pytest.Config) -> dict[str, Any] | None:
    spec = _opt(config, "mcp_defense")
    if not spec:
        return None
    baseline = Path(_opt(config, "mcp_defense_baseline") or "mcp-defense-baseline.json")
    if not baseline.is_absolute():
        baseline = Path(config.rootpath) / baseline
    corpus = _opt(config, "mcp_defense_corpus") or "all"
    return {
        "spec": spec,
        "baseline": baseline,
        "corpora": ["dev", "benign"] if corpus == "all" else [corpus],
        "tolerance": float(_opt(config, "mcp_defense_tolerance") or 0),
        "bench_path": _opt(config, "mcp_defense_bench_path"),
        "update": bool(config.getoption("mcp_defense_update")),
    }


def _state(config: pytest.Config) -> dict[str, Any]:
    """Score once per session; cache results and the baseline comparison."""
    st = config.stash.get(_state_key, None)
    if st is not None:
        return st
    s = _settings(config)
    assert s is not None
    adapter = load_adapter(s["spec"], search_path=config.rootpath)
    results = {c: run(adapter, c, bench_path=s["bench_path"]) for c in s["corpora"]}
    st = {"settings": s, "results": results, "written": False, "comparison": None, "error": None}
    path: Path = s["baseline"]
    if s["update"]:
        write_baseline(path, make_baseline(results.get("dev"), results.get("benign")))
        st["written"] = True
    elif not path.exists():
        st["error"] = (
            f"no baseline at {path}. Create one from the current defence with\n"
            f"    pytest --mcp-defense={s['spec']} --mcp-defense-update-baseline\nand commit it."
        )
    else:
        st["comparison"] = compare(load_baseline(path), results.get("dev"), results.get("benign"), tolerance=s["tolerance"])
    config.stash[_state_key] = st
    return st


class MCPDefenseFailure(Exception):
    pass


class MCPDefenseItem(pytest.Item):
    def __init__(self, *, check: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.check = check
        self.add_marker("mcp_defense")

    def runtest(self) -> None:
        st = _state(self.config)
        if st["written"]:
            return
        if st["error"]:
            raise MCPDefenseFailure(st["error"])
        cmp: Comparison = st["comparison"]
        if cmp.errors:
            raise MCPDefenseFailure("\n".join(cmp.errors))
        msgs = cmp.regressions.get(self.check, [])
        if msgs:
            raise MCPDefenseFailure(f"{self.check} regressed against {st['settings']['baseline'].name}:\n  " + "\n  ".join(msgs))

    def repr_failure(self, excinfo: pytest.ExceptionInfo[BaseException], style: Any = None) -> Any:
        if isinstance(excinfo.value, MCPDefenseFailure):
            return str(excinfo.value)
        return super().repr_failure(excinfo)

    def reportinfo(self) -> tuple[Path, int | None, str]:
        return self.path, None, f"mcp-defense::{self.check}"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "mcp_defense: mcp-defense-bench regression gate items")


def pytest_collection_modifyitems(session: pytest.Session, config: pytest.Config, items: list[pytest.Item]) -> None:
    s = _settings(config)
    if s is None:
        return
    for check, corpus in CHECKS.items():
        if corpus in s["corpora"]:
            items.append(MCPDefenseItem.from_parent(session, name=f"mcp-defense::{check}", check=check))


def pytest_report_header(config: pytest.Config) -> str | None:
    s = _settings(config)
    if s is None:
        return None
    from mcp_defense_bench import BENCH_COMMIT, BENCH_VERSION

    corpora = ", ".join(s["corpora"])
    return f"mcp-defense: {s['spec']} on bench {BENCH_VERSION} @ {BENCH_COMMIT[:7]} ({corpora}); baseline {s['baseline']}"


def pytest_terminal_summary(terminalreporter: Any, exitstatus: int, config: pytest.Config) -> None:
    st = config.stash.get(_state_key, None)
    if st is None:
        return
    tr = terminalreporter
    tr.section("mcp-defense-bench")
    res = st["results"]
    if "dev" in res:
        s = res["dev"]["summary"]
        tr.write_line(f"{s['tool']}: dev {s['overall']}, matched-control FP {s['falsePositives']}/{s['casesRun']}")
    if "benign" in res:
        s = res["benign"]["summary"]
        ci = s["fpRate95ci"]
        tr.write_line(
            f"{s['tool']}: benign FP {s['falsePositives']}/{s['items']} ({s['fpRate'] * 100:.1f}%, "
            f"95% CI {ci['lo'] * 100:.1f}–{ci['hi'] * 100:.1f}%)"
        )
    if st["written"]:
        tr.write_line(f"baseline written: {st['settings']['baseline']}")
    cmp = st.get("comparison")
    if cmp is not None and cmp.improvements:
        tr.write_line("improved over baseline (raise it with --mcp-defense-update-baseline):")
        for m in cmp.improvements:
            tr.write_line(f"  ↑ {m}")


@pytest.fixture(scope="session")
def mcp_defense_results(request: pytest.FixtureRequest) -> dict[str, Any]:
    """``{"dev": <result>, "benign": <result>}`` for the configured defence (skips if none)."""
    if _settings(request.config) is None:
        pytest.skip("no --mcp-defense configured")
    results: dict[str, Any] = _state(request.config)["results"]
    return results
