from __future__ import annotations

import asyncio
from typing import Any

import pytest

from mcp_defense_bench import AdapterMeta, run
from mcp_defense_bench.adapters import meta_dict
from mcp_defense_bench.bench import BenchError
from mcp_defense_bench.scoring import (
    cap_level,
    level_from,
    score_benign,
    score_matched,
    unwired_counts,
    vector_metrics,
    wilson,
    wired,
)


@pytest.mark.parametrize(
    ("mal", "benign", "want"),
    [
        ({"detect": False, "enforce": True}, {"detect": False}, ("none", False)),
        ({"detect": True, "enforce": True}, {"detect": True}, ("none", True)),
        ({"detect": True}, {"detect": False}, ("detect", False)),
        ({"detect": True, "enforce": True}, {}, ("enforce", False)),
    ],
)
def test_level_from(mal, benign, want):
    assert level_from(mal, benign) == want


def test_score_cap():
    assert cap_level("enforce", {"scoreCap": "detect"}) == "detect"
    assert cap_level("none", {"scoreCap": "detect"}) == "none"
    assert cap_level("enforce", {}) == "enforce"


def test_vector_metrics_mean_max_min():
    fx = [
        {"id": "a", "level": "detect", "weight": 0.5, "falsePositive": False},
        {"id": "b", "level": "enforce", "weight": 1, "falsePositive": False},
        {"id": "c", "level": "none", "weight": 0, "falsePositive": True},
    ]
    m = vector_metrics(fx)
    assert (m["level"], m["evidence"], m["capability"], m["robustCoverage"], m["guaranteed"], m["fpCount"]) == (
        "enforce",
        "b",
        1,
        0.5,
        0,
        1,
    )


def test_wilson():
    assert wilson(0, 0) == {"lo": 0, "hi": 0}
    ci = wilson(14, 337)
    assert round(ci["lo"], 4) == 0.0249 and round(ci["hi"], 4) == 0.0685


class _Flags:
    """Detects everything; only wired for tool definitions."""

    meta: dict[str, Any] = {"tool": "flags", "fixtureTypes": ["malicious-tool-definition", "benign-tool-definition"]}

    async def assess(self, input, testcase):
        return {"detect": input["type"] == "malicious-tool-definition", "enforce": True}


def test_fixture_types_leave_other_vectors_unknown(bench):
    res = asyncio.run(score_matched(_Flags(), bench.load_cases("dev"), bench.rubric))
    cov, s = res["coverage"], res["summary"]
    assert cov["tool-poisoning"]["level"] == "enforce"
    assert cov["command-injection"] == {**cov["command-injection"], "level": "unknown", "verified": False}
    assert s["casesRun"] == 3 and s["covered"]["unknown"] == 41 - s["verifiedVectors"]
    ben = asyncio.run(score_benign(_Flags(), bench.load_cases("benign"), bench.rubric))["summary"]
    assert ben["items"] == 256 and ben["falsePositives"] == 0


AUTHZ = {"fixture": {"type": "authorized-call"}}
DEF = {"fixture": {"type": "malicious-tool-definition"}}


@pytest.mark.parametrize(
    ("meta", "authz", "defn"),
    [
        ({}, True, True),
        ({"fixtureTypes": ["authorized-call"]}, True, False),
        ({"unwiredFixtureTypes": ["authorized-call"]}, False, True),
        ({"fixtureTypes": ["authorized-call"], "unwiredFixtureTypes": ["authorized-call"]}, False, False),
        ({"fixtureTypes": "authorized-call"}, True, True),  # not an array: ignored, as in bin/run.mjs
        ({"unwiredFixtureTypes": None}, True, True),
    ],
)
def test_wired_matches_run_mjs(meta, authz, defn):
    assert (wired(meta, AUTHZ), wired(meta, DEF)) == (authz, defn)
    assert wired(meta, {}) == (not isinstance(meta.get("fixtureTypes"), list))


def test_adapter_meta_serialises_both_declarations():
    m = AdapterMeta(tool="t", fixture_types=("tool-call",), unwired_fixture_types=("authorized-call",))
    assert meta_dict(type("A", (), {"meta": m})()) == {
        "tool": "t",
        "class": "unknown",
        "reproducible": False,
        "fixtureTypes": ["tool-call"],
        "unwiredFixtureTypes": ["authorized-call"],
    }


class _Refuses:
    """Blocks every call: catches every attack, so refuses every benign control too."""

    meta: dict[str, Any] = {"tool": "refuses"}

    def assess(self, input, testcase):
        return {"detect": True, "enforce": True}


def test_unwired_fixture_types_leave_authorization_unknown(bench):
    class Unwired(_Refuses):
        meta = {"tool": "unwired", "unwiredFixtureTypes": ["authorized-call"]}

    dev = bench.load_cases("dev")
    res = asyncio.run(score_matched(Unwired(), dev, bench.rubric))
    authz = [v["id"] for v in bench.rubric["vectors"] if v.get("vectorFamily") == "authorization"]
    assert res["summary"]["casesRun"] == 66
    assert all(res["coverage"][v]["level"] == "unknown" and not res["coverage"][v]["verified"] for v in authz)
    assert not any(c["id"].startswith("authz-") for c in res["cases"])
    assert unwired_counts(meta_dict(Unwired()), dev) == {"authorized-call": 12}


def test_refusing_by_tool_name_fails_every_authorization_control(bench):
    """Each control differs from its attack in one thing (usually the caller): a blanket refusal is an FP."""

    class AuthzOnly(_Refuses):
        meta = {"tool": "authz-only", "fixtureTypes": ["authorized-call"]}

    res = asyncio.run(score_matched(AuthzOnly(), bench.load_cases("dev"), bench.rubric))
    s = res["summary"]
    assert (s["casesRun"], s["falsePositives"], s["verifiedVectors"], s["covered"]["unknown"]) == (12, 12, 4, 37)
    assert s["overall"] == "0% (0.0/41 CorpusRobustCoverage)"
    ben = asyncio.run(score_benign(AuthzOnly(), bench.load_cases("benign"), bench.rubric))["summary"]
    assert (ben["items"], ben["falsePositives"], ben["fpRate"]) == (0, 0, 0)


def test_scorecap_applies_and_records_cappedfrom(bench):
    class Always:
        meta = {"tool": "always"}

        def assess(self, input, testcase):
            return {"detect": input is testcase["fixture"], "enforce": True}

    res = asyncio.run(score_matched(Always(), bench.load_cases("dev"), bench.rubric))
    capped = [c for c in res["cases"] if "cappedFrom" in c]
    assert capped and all(c["level"] == "detect" and c["cappedFrom"] == "enforce" for c in capped)


def test_run_refuses_heldout_without_checkout_or_confirmation(tmp_path):
    with pytest.raises(BenchError, match="not vendored"):
        run("mcp_defense_bench.adapters.null:NullBaseline", "heldout")
    with pytest.raises(BenchError, match="heldout_confirm='null-baseline'"):
        run("mcp_defense_bench.adapters.null:NullBaseline", "heldout", bench_path=tmp_path)
