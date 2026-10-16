"""Regression gate: compare a run with a stored baseline, for CI.

A baseline records, for one defence at one bench commit, the dev CorpusRobustCoverage (in total
and per vector), the matched-control false positives and the benign-corpus false positives. A
later run *regresses* when coverage falls (by more than ``tolerance``) or false positives rise.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_defense_bench import BENCH_COMMIT, __version__
from mcp_defense_bench.jscompat import js_number as _n
from mcp_defense_bench.jscompat import stringify

__all__ = ["Comparison", "compare", "load_baseline", "make_baseline", "write_baseline"]

SCHEMA = "mcp-defense-bench/baseline@1"


def make_baseline(dev: Mapping[str, Any] | None, benign: Mapping[str, Any] | None) -> dict[str, Any]:
    src = dev or benign
    if src is None:
        raise ValueError("need at least one of the dev or benign results")
    out: dict[str, Any] = {
        "schema": SCHEMA,
        "tool": src["summary"]["tool"],
        "benchCommit": BENCH_COMMIT,
        "rubricVersion": src["summary"]["rubricVersion"],
        "createdWith": f"mcp-defense-bench {__version__}",
    }
    if dev is not None:
        s = dev["summary"]
        out["dev"] = {
            "robustCoverage": s["robustCoverage"],
            "overall": s["overall"],
            "casesRun": s["casesRun"],
            "falsePositives": s["falsePositives"],
            "vectors": {vid: c["robustCoverage"] for vid, c in dev["coverage"].items()},
        }
    if benign is not None:
        s = benign["summary"]
        out["benign"] = {"items": s["items"], "falsePositives": s["falsePositives"], "fpRate": s["fpRate"]}
    return out


def write_baseline(path: str | Path, baseline: Mapping[str, Any]) -> None:
    Path(path).write_text(stringify(baseline) + "\n", "utf8")


def load_baseline(path: str | Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(Path(path).read_text("utf8"))
    if data.get("schema") != SCHEMA:
        raise ValueError(f"{path}: not an mcp-defense-bench baseline (schema {data.get('schema')!r})")
    return data


@dataclass
class Comparison:
    """Regressions fail CI; improvements are reported so the baseline can be raised."""

    regressions: dict[str, list[str]] = field(default_factory=dict)
    improvements: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors and not any(self.regressions.values())

    def add(self, check: str, msg: str) -> None:
        self.regressions.setdefault(check, []).append(msg)


def compare(
    baseline: Mapping[str, Any],
    dev: Mapping[str, Any] | None = None,
    benign: Mapping[str, Any] | None = None,
    *,
    tolerance: float = 0.0,
) -> Comparison:
    """Compare results with ``baseline``. Checks: ``dev-coverage``, ``dev-false-positives``, ``benign-false-positives``."""
    cmp = Comparison()
    for res in (dev, benign):
        if res is not None and res["summary"]["rubricVersion"] != baseline.get("rubricVersion"):
            cmp.errors.append(
                f"baseline was recorded on rubric {baseline.get('rubricVersion')}, this run used "
                f"{res['summary']['rubricVersion']}; re-create the baseline"
            )
            return cmp
    if baseline.get("benchCommit") != BENCH_COMMIT:
        cmp.errors.append(
            f"baseline was recorded at bench {str(baseline.get('benchCommit'))[:7]}, this package scores bench "
            f"{BENCH_COMMIT[:7]}; re-create the baseline"
        )
        return cmp

    if dev is not None:
        b = baseline.get("dev")
        if b is None:
            cmp.errors.append("baseline has no dev section; re-create it with the dev corpus")
        else:
            cmp.regressions.setdefault("dev-coverage", [])
            cmp.regressions.setdefault("dev-false-positives", [])
            s = dev["summary"]
            if s["robustCoverage"] < b["robustCoverage"] - tolerance:
                cmp.add(
                    "dev-coverage",
                    f"CorpusRobustCoverage fell {_n(b['robustCoverage'])} → {_n(s['robustCoverage'])} "
                    f"({b['overall']} → {s['overall']})",
                )
            elif s["robustCoverage"] > b["robustCoverage"]:
                cmp.improvements.append(f"CorpusRobustCoverage rose {_n(b['robustCoverage'])} → {_n(s['robustCoverage'])}")
            for vid, now in ((v, c["robustCoverage"]) for v, c in dev["coverage"].items()):
                was = b["vectors"].get(vid)
                if was is None:
                    continue
                if now < was - tolerance:
                    cmp.add("dev-coverage", f"{vid}: {_n(was)} → {_n(now)}")
                elif now > was:
                    cmp.improvements.append(f"{vid}: {_n(was)} → {_n(now)}")
            if s["falsePositives"] > b["falsePositives"]:
                fps = [c["id"] for c in dev["cases"] if c["falsePositive"]]
                cmp.add(
                    "dev-false-positives",
                    f"matched-control false positives rose {b['falsePositives']} → {s['falsePositives']}: {', '.join(fps)}",
                )
            elif s["falsePositives"] < b["falsePositives"]:
                cmp.improvements.append(f"matched-control false positives fell {b['falsePositives']} → {s['falsePositives']}")

    if benign is not None:
        b = baseline.get("benign")
        if b is None:
            cmp.errors.append("baseline has no benign section; re-create it with the benign corpus")
        else:
            cmp.regressions.setdefault("benign-false-positives", [])
            s = benign["summary"]
            if s["items"] != b["items"]:
                cmp.errors.append(
                    f"benign corpus size changed {b['items']} → {s['items']} (fixtureTypes changed?); re-create the baseline"
                )
            elif s["falsePositives"] > b["falsePositives"]:
                fps = [it["id"] for it in benign["items"] if it["falsePositive"]]
                cmp.add(
                    "benign-false-positives",
                    f"benign false positives rose {b['falsePositives']} → {s['falsePositives']}/{s['items']}: "
                    + ", ".join(fps[:25]),
                )
            elif s["falsePositives"] < b["falsePositives"]:
                cmp.improvements.append(f"benign false positives fell {b['falsePositives']} → {s['falsePositives']}")
    return cmp
