"""The scorer: a line-faithful port of ``bin/run.mjs`` (bench 0.10.0).

Matched corpora (dev, held-out): each case is assessed twice, on the malicious ``fixture`` and on
its ``benignControl``. Per case:

* missed the attack                         -> ``none``
* caught it, and flagged the benign control -> ``none`` + ``falsePositive``
* caught it, clean on benign, warn-only     -> ``detect``
* caught it, clean on benign, can block     -> ``enforce``

then ``scoreCap: "detect"`` caps the level. Per vector, over all its fixtures (weights enforce 1,
detect 0.5, none 0): Capability = max, **CorpusRobustCoverage = mean** (the headline),
Guaranteed = min.

Benign corpus: every flag is a false positive; reports the rate with a Wilson 95% interval.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from typing import Any

from mcp_defense_bench.adapters import call_assess, meta_dict
from mcp_defense_bench.jscompat import UNDEFINED, fold_add, js_truthy, to_fixed, to_fixed_number

__all__ = [
    "RANK",
    "WEIGHT",
    "cap_level",
    "coverage_document",
    "iso_now",
    "level_from",
    "score_benign",
    "score_matched",
    "unwired_counts",
    "vector_metrics",
    "wilson",
    "wired",
]

WEIGHT: dict[str, float] = {"enforce": 1, "detect": 0.5, "observe": 0.1, "none": 0, "unknown": 0}
RANK: dict[str, int] = {"none": 0, "detect": 1, "enforce": 2}


def iso_now() -> str:
    """``new Date().toISOString()``: UTC, millisecond precision, ``Z`` suffix."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def wilson(k: int, n: int, z: float = 1.96) -> dict[str, float]:
    """Wilson 95% interval for a proportion — small-sample honest. Same operation order as JS."""
    if not n:
        return {"lo": 0, "hi": 0}
    p = k / n
    d = 1 + (z * z) / n
    c = p + (z * z) / (2 * n)
    h = z * math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))
    return {"lo": max(0, (c - h) / d), "hi": min(1, (c + h) / d)}


def level_from(mal: Mapping[str, Any], benign: Mapping[str, Any]) -> tuple[str, bool]:
    """(level, falsePositive) for one matched case, before the score cap."""
    if not js_truthy(mal.get("detect")):
        return "none", False
    if js_truthy(benign.get("detect")):
        return "none", True
    return ("enforce" if js_truthy(mal.get("enforce")) else "detect"), False


def cap_level(level: str, tc: Mapping[str, Any]) -> str:
    """RFC-conforming cap (DELEGATION-PREREG §6.4): ``scoreCap: "detect"`` never scores above detect."""
    return "detect" if tc.get("scoreCap") == "detect" and level == "enforce" else level


def wired(meta: Mapping[str, Any], tc: Mapping[str, Any]) -> bool:
    """Whether the adapter is run on ``tc`` at all (``wired`` in ``bin/run.mjs``).

    An adapter that declares the fixture types it is wired for (``fixtureTypes``), or the ones it is
    not yet wired for (``unwiredFixtureTypes``), is not run on other cases: their vectors stay
    ``unknown`` (scored 0, never a miss) and they are left out of the benign-corpus denominator.
    """
    types = meta.get("fixtureTypes")
    unwired = meta.get("unwiredFixtureTypes")
    fixture = tc.get("fixture")
    ftype = fixture.get("type") if isinstance(fixture, Mapping) else None
    return (not isinstance(types, (list, tuple)) or ftype in types) and not (
        isinstance(unwired, (list, tuple)) and ftype in unwired
    )


def unwired_counts(meta: Mapping[str, Any], cases: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Fixture type -> number of ``cases`` the adapter is not run on, in corpus order."""
    out: dict[str, int] = {}
    for tc in cases:
        if not wired(meta, tc):
            fixture = tc.get("fixture")
            ftype = str(fixture.get("type")) if isinstance(fixture, Mapping) else "?"
            out[ftype] = out.get(ftype, 0) + 1
    return out


def vector_metrics(fx: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    ws = [f["weight"] for f in fx]
    best = fx[0]
    for b in fx[1:]:
        if RANK[b["level"]] > RANK[best["level"]]:
            best = b
    return {
        "level": best["level"],
        "evidence": best["id"],
        "capability": max(ws),
        "robustCoverage": to_fixed_number(fold_add(ws) / len(ws), 4),
        "guaranteed": min(ws),
        "fixtures": len(fx),
        "fpCount": sum(1 for f in fx if f["falsePositive"]),
    }


def _get(tc: Mapping[str, Any], key: str) -> Any:
    """``tc[key]``, or JS ``undefined`` when absent (so the key is omitted from output)."""
    return tc.get(key, UNDEFINED)


def _nullish(tc: Mapping[str, Any], key: str) -> Any:
    """``tc[key] ?? null``."""
    v = tc.get(key)
    return None if v is None else v


async def score_matched(
    adapter: Any,
    cases: Sequence[Mapping[str, Any]],
    rubric: Mapping[str, Any],
    *,
    corpus: str = "dev",
    tool: str | None = None,
    measured_at: str | Callable[[], str] = iso_now,
) -> dict[str, Any]:
    """Score a matched corpus. Returns ``{summary, coverage, cases}`` exactly as ``bin/run.mjs`` writes it."""
    meta = meta_dict(adapter)
    rubric_ids = [v["id"] for v in rubric["vectors"]]
    per_case: list[dict[str, Any]] = []
    by_vector: dict[str, list[dict[str, Any]]] = {}
    for tc in cases:
        if not wired(meta, tc):
            continue
        mal = await call_assess(adapter, tc["fixture"], tc)
        benign = await call_assess(adapter, tc["benignControl"], tc)
        raw_level, false_positive = level_from(mal, benign)
        level = cap_level(raw_level, tc)
        rec: dict[str, Any] = {
            "id": tc["id"],
            "level": level,
            "falsePositive": false_positive,
            "mal": mal,
            "benign": benign,
            "expected": _get(tc, "expected"),
        }
        if level != raw_level:
            rec["cappedFrom"] = raw_level
        per_case.append(rec)
        by_vector.setdefault(tc["vector"], []).append(
            {
                "id": tc["id"],
                "level": level,
                "weight": WEIGHT.get(level, 0),
                "falsePositive": false_positive,
                "evasion": _nullish(tc, "evasion"),
                "family": _nullish(tc, "family"),
            }
        )

    coverage: dict[str, dict[str, Any]] = {}
    for vid in rubric_ids:
        if vid not in by_vector:
            coverage[vid] = {
                "level": "unknown",
                "capability": 0,
                "robustCoverage": 0,
                "guaranteed": 0,
                "fixtures": 0,
                "fpCount": 0,
                "evidence": None,
                "verified": False,
            }
            continue
        m = vector_metrics(by_vector[vid])
        coverage[vid] = {
            "level": m["level"],
            "capability": m["capability"],
            "robustCoverage": m["robustCoverage"],
            "guaranteed": m["guaranteed"],
            "fixtures": m["fixtures"],
            "fpCount": m["fpCount"],
            "evidence": m["evidence"],
            "verified": True,
        }
        if m["fpCount"]:
            coverage[vid]["falsePositive"] = True

    n = len(rubric_ids)
    robust_w = fold_add(coverage[i]["robustCoverage"] or 0 for i in rubric_ids)
    capability_w = fold_add(coverage[i]["capability"] or 0 for i in rubric_ids)
    guaranteed_w = fold_add(coverage[i]["guaranteed"] or 0 for i in rubric_ids)
    summary: dict[str, Any] = {
        "tool": meta.get("tool") or tool,
        "corpus": corpus,
        "rubricVersion": rubric["version"],
        "casesRun": len(per_case),
        "verifiedVectors": sum(1 for c in coverage.values() if c["verified"]),
        "falsePositives": sum(1 for c in per_case if c["falsePositive"]),
        "covered": {"enforce": 0, "detect": 0, "none": 0, "unknown": 0},
        "overall": f"{to_fixed((robust_w / n) * 100, 0)}% ({to_fixed(robust_w, 1)}/{n} CorpusRobustCoverage)",
        "robustCoverage": to_fixed_number(robust_w, 2),
        "capability": to_fixed_number(capability_w, 2),
        "guaranteed": to_fixed_number(guaranteed_w, 2),
    }
    for vid in rubric_ids:
        lvl = coverage[vid]["level"]
        summary["covered"][lvl] = summary["covered"].get(lvl, 0) + 1
    summary["measuredAt"] = measured_at() if callable(measured_at) else measured_at
    return {"summary": summary, "coverage": coverage, "cases": per_case}


async def score_benign(
    adapter: Any,
    cases: Sequence[Mapping[str, Any]],
    rubric: Mapping[str, Any],
    *,
    tool: str | None = None,
    measured_at: str | Callable[[], str] = iso_now,
) -> dict[str, Any]:
    """Score the benign-only corpus. Returns ``{summary, items}`` exactly as ``bin/run.mjs`` writes it."""
    meta = meta_dict(adapter)
    items: list[dict[str, Any]] = []
    flagged = 0
    by_kind: dict[str, dict[str, int]] = {}
    for tc in cases:
        if not wired(meta, tc):
            continue
        verdict = await call_assess(adapter, tc["fixture"], tc)
        fp = js_truthy(verdict.get("detect"))
        if fp:
            flagged += 1
        kind = tc.get("kind")
        bucket = by_kind.setdefault("other" if kind is None else kind, {"n": 0, "fp": 0})
        bucket["n"] += 1
        if fp:
            bucket["fp"] += 1
        items.append(
            {
                "id": tc["id"],
                "kind": _nullish(tc, "kind"),
                "source": _nullish(tc, "source"),
                "hardNegative": js_truthy(tc.get("hardNegative")),
                "falsePositive": fp,
                "verdict": verdict,
            }
        )
    ci = wilson(flagged, len(items))
    summary = {
        "tool": meta.get("tool") or tool,
        "corpus": "benign",
        "rubricVersion": rubric["version"],
        "items": len(items),
        "falsePositives": flagged,
        "fpRate": to_fixed_number(flagged / len(items), 4) if items else 0,
        "fpRate95ci": {"lo": to_fixed_number(ci["lo"], 4), "hi": to_fixed_number(ci["hi"], 4)},
        "byKind": by_kind,
        "measuredAt": measured_at() if callable(measured_at) else measured_at,
    }
    return {"summary": summary, "items": items}


def coverage_document(adapter: Any, result: Mapping[str, Any], *, tool: str | None = None) -> dict[str, Any]:
    """The ``adapters/<tool>/coverage.json`` that ``bin/run.mjs`` writes after a dev run."""
    meta = meta_dict(adapter)
    return {
        "tool": meta.get("tool") or tool,
        "repo": meta.get("repo"),
        "class": meta.get("class") or "unknown",
        "reproducible": bool(meta.get("reproducible", False)),
        "version": meta.get("version") or "local",
        "rubricVersion": result["summary"]["rubricVersion"],
        "measuredBy": "mcp_defense_bench (python)",
        "coverage": result["coverage"],
    }
