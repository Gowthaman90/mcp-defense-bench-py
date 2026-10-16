"""The Python scorer reproduces the JS scorer byte for byte (dev + benign corpora only).

The held-out corpus is never scored here: its integrity is checked by hashes and counts only
(tests/test_bench.py).
"""

from __future__ import annotations

import asyncio
import json
import re

import pytest
from conftest import TOOLS, recorded

from mcp_defense_bench.adapters.null import NullBaseline
from mcp_defense_bench.adapters.replay import ReplayAdapter
from mcp_defense_bench.jscompat import stringify
from mcp_defense_bench.scoring import score_benign, score_matched
from mcp_defense_bench.totals import revision_row, two_totals_row


def _bytes(doc: object) -> bytes:
    return (stringify(doc) + "\n").encode("utf8")


@pytest.mark.parametrize("tool", TOOLS)
def test_dev_replay_is_byte_identical(tool, bench, js_fixtures):
    raw, rec = recorded(js_fixtures / "results" / f"{tool}.json")
    res = asyncio.run(
        score_matched(ReplayAdapter(rec), bench.load_cases("dev"), bench.rubric, measured_at=rec["summary"]["measuredAt"])
    )
    assert _bytes(res) == raw


@pytest.mark.parametrize("tool", TOOLS)
def test_benign_replay_is_byte_identical(tool, bench, js_fixtures):
    raw, rec = recorded(js_fixtures / "results" / "benign" / f"{tool}.json")
    res = asyncio.run(
        score_benign(ReplayAdapter(rec), bench.load_cases("benign"), bench.rubric, measured_at=rec["summary"]["measuredAt"])
    )
    assert _bytes(res) == raw


@pytest.mark.parametrize("tool", TOOLS)
def test_dev_coverage_matches_coverage_json(tool, bench, js_fixtures):
    _, rec = recorded(js_fixtures / "results" / f"{tool}.json")
    res = asyncio.run(score_matched(ReplayAdapter(rec), bench.load_cases("dev"), bench.rubric))
    js_cov = json.loads((js_fixtures / "coverage" / f"{tool}.json").read_text("utf8"))
    assert res["coverage"] == js_cov["coverage"]
    assert js_cov["rubricVersion"] == res["summary"]["rubricVersion"] == "0.9.0"


@pytest.mark.parametrize(
    ("corpus", "path"), [("dev", "results/null-baseline.json"), ("benign", "results/benign/null-baseline.json")]
)
def test_null_baseline_live_run_is_byte_identical(corpus, path, bench, js_fixtures):
    raw, rec = recorded(js_fixtures / path)
    scorer = score_matched if corpus == "dev" else score_benign
    res = asyncio.run(scorer(NullBaseline(), bench.load_cases(corpus), bench.rubric, measured_at=rec["summary"]["measuredAt"]))
    assert _bytes(res) == raw


def test_published_headline_numbers(bench, js_fixtures):
    """The figures quoted in the bench README, reproduced from the recorded verdicts."""
    _, dev = recorded(js_fixtures / "results" / "mcp-bastion.json")
    _, ben = recorded(js_fixtures / "results" / "benign" / "mcp-bastion.json")
    d = asyncio.run(score_matched(ReplayAdapter(dev), bench.load_cases("dev"), bench.rubric))["summary"]
    b = asyncio.run(score_benign(ReplayAdapter(ben), bench.load_cases("benign"), bench.rubric))["summary"]
    assert d["overall"] == "66% (24.6/37 CorpusRobustCoverage)"
    assert (d["casesRun"], d["falsePositives"]) == (66, 0)
    assert (b["items"], b["falsePositives"], b["fpRate"], b["fpRate95ci"]) == (337, 14, 0.0415, {"lo": 0.0249, "hi": 0.0685})


def _board_rows(js_fixtures, tool: str) -> list[str]:
    lines = (js_fixtures / "LEADERBOARD.md").read_text("utf8").splitlines()
    return [ln for ln in lines if ln.startswith(f"| **{tool}** |")]


@pytest.mark.parametrize("tool", TOOLS)
def test_two_totals_row_matches_leaderboard(tool, bench, js_fixtures):
    cov = json.loads((js_fixtures / "coverage" / f"{tool}.json").read_text("utf8"))["coverage"]
    # Dev-only parity: strip the held-out suffix the JS board adds from recorded held-out runs.
    rows = [re.sub(r" · held-out [^|]*?(?= \|)", "", r) for r in _board_rows(js_fixtures, tool)]
    assert two_totals_row(tool, bench.rubric, cov) in rows


@pytest.mark.parametrize("tool", TOOLS)
def test_revision_row_matches_leaderboard(tool, bench, js_fixtures):
    cov = json.loads((js_fixtures / "coverage" / f"{tool}.json").read_text("utf8"))["coverage"]
    assert revision_row(tool, bench.rubric, cov) in _board_rows(js_fixtures, tool)
