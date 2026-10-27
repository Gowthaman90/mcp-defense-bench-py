"""Totals over vector subsets, ported from ``bin/leaderboard.mjs``.

A coverage number is only meaningful relative to its denominator, so the leaderboard reports:

* **published vs all**: the vectors published before the newest family (no ``vectorFamily``)
  and all rubric vectors;
* **per family**: each ``vectorFamily`` (0.9.0 adds ``delegation``, 5 vectors; 0.10.0 adds
  ``authorization``, 4 vectors);
* **per protocol revision**: vectors whose ``appliesTo`` includes the revision, plus the vectors
  introduced by the latest revision only.

Each total is the sum of per-vector CorpusRobustCoverage over the subset. Held-out totals use
only the subset's vectors that the held-out run verified.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from mcp_defense_bench.jscompat import fold_add, to_fixed

__all__ = ["revision_row", "subset_total", "subsets", "totals", "two_totals_row"]

WEIGHT = {"enforce": 1, "detect": 0.5, "none": 0, "unknown": 0}


def _robust_of(cov: Mapping[str, Any], vid: str) -> float:
    cell = cov.get(vid) or {}
    rc = cell.get("robustCoverage")
    if isinstance(rc, (int, float)) and not isinstance(rc, bool):
        return rc
    return WEIGHT.get(cell.get("level", "unknown"), 0)


def _pct(x: float, n: int) -> str:
    return f"{to_fixed((x / n) * 100, 0)}%"


def subsets(rubric: Mapping[str, Any]) -> dict[str, list[str]]:
    """Named vector-id subsets, in leaderboard order: published, all, then one per family."""
    vectors = rubric["vectors"]
    ids = [v["id"] for v in vectors]
    families: list[str] = []
    for v in vectors:
        f = v.get("vectorFamily")
        if f and f not in families:
            families.append(f)
    out = {"published": [v["id"] for v in vectors if not v.get("vectorFamily")], "all": ids}
    for f in families:
        out[f"family:{f}"] = [v["id"] for v in vectors if v.get("vectorFamily") == f]
    return out


def subset_total(subset: Sequence[str], dev: Mapping[str, Any], heldout: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """CorpusRobustCoverage summed over ``subset`` (dev), plus held-out over its verified vectors."""
    d = fold_add(_robust_of(dev, vid) for vid in subset)
    out: dict[str, Any] = {
        "vectors": len(subset),
        "wired": any((dev.get(vid) or {}).get("verified") for vid in subset),
        "robustCoverage": d,
        "percent": _pct(d, len(subset)),
    }
    if heldout is not None:
        hs = [vid for vid in subset if (heldout.get(vid) or {}).get("verified")]
        h = fold_add(_robust_of(heldout, vid) for vid in hs)
        out["heldout"] = {"vectors": len(hs), "robustCoverage": h, "percent": _pct(h, len(hs)) if hs else None}
    return out


def totals(
    rubric: Mapping[str, Any], dev: Mapping[str, Any], heldout: Mapping[str, Any] | None = None
) -> dict[str, dict[str, Any]]:
    """Every named subset's totals, for a dev ``coverage`` map (and optionally a held-out one)."""
    return {name: subset_total(ids, dev, heldout) for name, ids in subsets(rubric).items()}


def _both(subset: Sequence[str], dev: Mapping[str, Any], heldout: Mapping[str, Any] | None) -> str:
    t = subset_total(subset, dev, heldout)
    if not t["wired"]:
        return "not wired"
    text = f"{t['percent']} ({to_fixed(t['robustCoverage'], 1)}/{t['vectors']})"
    h = t.get("heldout")
    if h and h["vectors"]:
        text += f" · held-out {h['percent']} ({to_fixed(h['robustCoverage'], 1)}/{h['vectors']})"
    return text


def two_totals_row(tool: str, rubric: Mapping[str, Any], dev: Mapping[str, Any], heldout: Mapping[str, Any] | None = None) -> str:
    """The leaderboard's "published vs all vectors" table row for one tool."""
    cells = [_both(ids, dev, heldout) for ids in subsets(rubric).values()]
    return f"| **{tool}** | {' | '.join(cells)} |"


def revision_row(tool: str, rubric: Mapping[str, Any], dev: Mapping[str, Any]) -> str:
    """The leaderboard's "coverage per protocol revision" table row for one tool."""
    spec = rubric.get("_specRevisions") or {}
    revisions: list[str] = spec.get("known") or []
    latest = spec.get("latest") or (revisions[-1] if revisions else None)
    vectors = rubric["vectors"]

    def applies(v: Mapping[str, Any], rev: str) -> bool:
        a = v.get("appliesTo")
        return not isinstance(a, list) or rev in a

    cols = []
    for rev in revisions:
        sub = [v["id"] for v in vectors if applies(v, rev)]
        r = fold_add(_robust_of(dev, vid) for vid in sub)
        cols.append(f"{_pct(r, len(sub))} ({to_fixed(r, 1)}/{len(sub)})")
    new = [
        v["id"]
        for v in vectors
        if isinstance(v.get("appliesTo"), list) and len(v["appliesTo"]) == 1 and v["appliesTo"][0] == latest
    ]
    rn = fold_add(_robust_of(dev, vid) for vid in new)
    last = f"{_pct(rn, len(new))} ({to_fixed(rn, 1)}/{len(new)})" if new else "—"
    return f"| **{tool}** | {' | '.join(cols)} | {last} |"
