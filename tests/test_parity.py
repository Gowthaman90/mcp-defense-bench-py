"""The Python scorer reproduces the JS scorer byte for byte (dev + benign corpora only).

Covers every tool with recorded JS results at the pinned commit, including agentgateway and
ToolHive, which are wired for the authorization family only (``meta.fixtureTypes``). The held-out
corpus is never scored here: its integrity is checked by hashes and counts only (tests/test_bench.py).
"""

from __future__ import annotations

import asyncio
import json
import re

import pytest
from conftest import AUTHZ_ONLY, AUTHZ_VECTORS, DEV_TOOLS, TOOLS, recorded

from mcp_defense_bench.adapters.null import NullBaseline
from mcp_defense_bench.adapters.replay import ReplayAdapter
from mcp_defense_bench.jscompat import stringify
from mcp_defense_bench.scoring import score_benign, score_matched
from mcp_defense_bench.totals import revision_row, totals, two_totals_row


def _bytes(doc: object) -> bytes:
    return (stringify(doc) + "\n").encode("utf8")


def _replay(rec: dict, tool: str) -> ReplayAdapter:
    """The recorded verdicts, wired for the same fixture types as the JS adapter."""
    return ReplayAdapter(rec, fixture_types=AUTHZ_ONLY.get(tool))


@pytest.mark.parametrize("tool", DEV_TOOLS)
def test_dev_replay_is_byte_identical(tool, bench, js_fixtures):
    raw, rec = recorded(js_fixtures / "results" / f"{tool}.json")
    res = asyncio.run(
        score_matched(_replay(rec, tool), bench.load_cases("dev"), bench.rubric, measured_at=rec["summary"]["measuredAt"])
    )
    assert _bytes(res) == raw


@pytest.mark.parametrize("tool", DEV_TOOLS)
def test_dev_replay_infers_wiring_from_the_record(tool, bench, js_fixtures):
    raw, rec = recorded(js_fixtures / "results" / f"{tool}.json")
    cases = bench.load_cases("dev")
    adapter = ReplayAdapter(rec, cases=cases)
    if tool in AUTHZ_ONLY:
        assert adapter.meta["fixtureTypes"] == list(AUTHZ_ONLY[tool])
    res = asyncio.run(score_matched(adapter, cases, bench.rubric, measured_at=rec["summary"]["measuredAt"]))
    assert _bytes(res) == raw


@pytest.mark.parametrize("tool", sorted(AUTHZ_ONLY))
def test_replay_without_wiring_refuses_unrecorded_cases(tool, bench, js_fixtures):
    _, rec = recorded(js_fixtures / "results" / f"{tool}.json")
    with pytest.raises(KeyError, match="no recorded verdict for"):
        asyncio.run(score_matched(ReplayAdapter(rec), bench.load_cases("dev"), bench.rubric))


@pytest.mark.parametrize("tool", TOOLS)
def test_benign_replay_is_byte_identical(tool, bench, js_fixtures):
    raw, rec = recorded(js_fixtures / "results" / "benign" / f"{tool}.json")
    res = asyncio.run(
        score_benign(ReplayAdapter(rec), bench.load_cases("benign"), bench.rubric, measured_at=rec["summary"]["measuredAt"])
    )
    assert _bytes(res) == raw


@pytest.mark.parametrize("tool", sorted(AUTHZ_ONLY))
def test_authz_only_tools_have_no_benign_run(tool, bench, js_fixtures):
    """Wired for authorized-call only, and the benign corpus has none: an empty denominator, as in JS."""
    assert not (js_fixtures / "results" / "benign" / f"{tool}.json").exists()
    res = asyncio.run(
        score_benign(
            _replay({"summary": {"corpus": "benign", "tool": tool}, "items": []}, tool), bench.load_cases("benign"), bench.rubric
        )
    )
    assert (res["summary"]["items"], res["items"]) == (0, [])


@pytest.mark.parametrize("tool", DEV_TOOLS)
def test_dev_coverage_matches_coverage_json(tool, bench, js_fixtures):
    _, rec = recorded(js_fixtures / "results" / f"{tool}.json")
    res = asyncio.run(score_matched(_replay(rec, tool), bench.load_cases("dev"), bench.rubric))
    js_cov = json.loads((js_fixtures / "coverage" / f"{tool}.json").read_text("utf8"))
    assert res["coverage"] == js_cov["coverage"]
    assert js_cov["rubricVersion"] == res["summary"]["rubricVersion"] == "0.10.0"


@pytest.mark.parametrize(
    ("corpus", "path"), [("dev", "results/null-baseline.json"), ("benign", "results/benign/null-baseline.json")]
)
def test_null_baseline_live_run_is_byte_identical(corpus, path, bench, js_fixtures):
    raw, rec = recorded(js_fixtures / path)
    scorer = score_matched if corpus == "dev" else score_benign
    res = asyncio.run(scorer(NullBaseline(), bench.load_cases(corpus), bench.rubric, measured_at=rec["summary"]["measuredAt"]))
    assert _bytes(res) == raw


def test_published_headline_numbers(bench, js_fixtures):
    """The figures in the bench's 2026-10-27 scoring changelog, reproduced from the recorded verdicts."""
    _, dev = recorded(js_fixtures / "results" / "mcp-bastion.json")
    _, ben = recorded(js_fixtures / "results" / "benign" / "mcp-bastion.json")
    d = asyncio.run(score_matched(ReplayAdapter(dev), bench.load_cases("dev"), bench.rubric))
    b = asyncio.run(score_benign(ReplayAdapter(ben), bench.load_cases("benign"), bench.rubric))["summary"]
    assert d["summary"]["overall"] == "70% (28.8/41 CorpusRobustCoverage)"
    assert (d["summary"]["casesRun"], d["summary"]["falsePositives"]) == (78, 0)
    t = totals(bench.rubric, d["coverage"])
    assert (t["published"]["percent"], t["all"]["percent"], t["family:authorization"]["percent"]) == ("63%", "70%", "100%")
    assert (b["items"], b["falsePositives"], b["fpRate"], b["fpRate95ci"]) == (337, 15, 0.0445, {"lo": 0.0272, "hi": 0.0721})


# Authorization family, dev RobustCoverage per vector (bench docs/CHANGELOG-scoring.md, 2026-10-27).
AUTHZ_TABLE = {
    "mcp-bastion": (1, 1, 1, 1),
    "agentgateway": (1, 1, 1, 1),
    "toolhive": (1, 1, 1, 1),
    "mcp-firewall": (1, 0, 0, 0.6667),
    "pipelock": (0, 0, 0, 0),
    "null-baseline": (0, 0, 0, 0),
}
AUTHZ_FAMILY = {
    "mcp-bastion": "100% (4.0/4)",
    "agentgateway": "100% (4.0/4)",
    "toolhive": "100% (4.0/4)",
    "mcp-firewall": "42% (1.7/4)",
    "pipelock": "0% (0.0/4)",
    "null-baseline": "0% (0.0/4)",
}


@pytest.mark.parametrize("tool", DEV_TOOLS)
def test_authorization_family_results(tool, bench, js_fixtures):
    _, rec = recorded(js_fixtures / "results" / f"{tool}.json")
    res = asyncio.run(score_matched(_replay(rec, tool), bench.load_cases("dev"), bench.rubric))
    cov = res["coverage"]
    assert tuple(cov[v]["robustCoverage"] for v in AUTHZ_VECTORS) == AUTHZ_TABLE[tool]
    assert all(cov[v]["fixtures"] == 3 and cov[v]["fpCount"] == 0 for v in AUTHZ_VECTORS)
    authz_cases = [c for c in res["cases"] if c["id"].split("/")[0] in AUTHZ_VECTORS]
    assert len(authz_cases) == 12 and not any(c["falsePositive"] or "cappedFrom" in c for c in authz_cases)
    fam = totals(bench.rubric, cov)["family:authorization"]
    assert f"{fam['percent']} ({fam['robustCoverage']:.1f}/{fam['vectors']})" == AUTHZ_FAMILY[tool]
    if tool in AUTHZ_ONLY:  # the other 37 vectors are not wired, not misses
        s = res["summary"]
        assert (s["casesRun"], s["verifiedVectors"], s["covered"]["unknown"]) == (12, 4, 37)
        assert not totals(bench.rubric, cov)["published"]["wired"]


def _board_rows(js_fixtures, tool: str) -> list[str]:
    lines = (js_fixtures / "LEADERBOARD.md").read_text("utf8").splitlines()
    return [ln for ln in lines if ln.startswith(f"| **{tool}** |")]


@pytest.mark.parametrize("tool", DEV_TOOLS)
def test_two_totals_row_matches_leaderboard(tool, bench, js_fixtures):
    cov = json.loads((js_fixtures / "coverage" / f"{tool}.json").read_text("utf8"))["coverage"]
    # Dev-only parity: strip the held-out suffix the JS board adds from recorded held-out runs.
    rows = [re.sub(r" · held-out [^|]*?(?= \|)", "", r) for r in _board_rows(js_fixtures, tool)]
    assert two_totals_row(tool, bench.rubric, cov) in rows


@pytest.mark.parametrize("tool", DEV_TOOLS)
def test_revision_row_matches_leaderboard(tool, bench, js_fixtures):
    cov = json.loads((js_fixtures / "coverage" / f"{tool}.json").read_text("utf8"))["coverage"]
    assert revision_row(tool, bench.rubric, cov) in _board_rows(js_fixtures, tool)
