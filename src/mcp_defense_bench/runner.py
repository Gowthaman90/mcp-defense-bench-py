"""High-level API: score one defence on one corpus.

>>> from mcp_defense_bench import run
>>> result = run("mcp_defense_bench.adapters.null:NullBaseline", corpus="dev")
>>> result["summary"]["overall"]
'0% (0.0/37 CorpusRobustCoverage)'
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcp_defense_bench.adapters import load_adapter, meta_dict
from mcp_defense_bench.bench import Bench, BenchError
from mcp_defense_bench.scoring import iso_now, score_benign, score_matched

__all__ = ["arun", "open_bench", "run"]

HELDOUT_NOTICE = (
    "The held-out corpus is a one-shot generalisation test (bench docs/HELD-OUT-PROTOCOL.md): "
    "score a defence on it once, at a frozen version, after all tuning on the dev corpus is done."
)


def open_bench(bench_path: str | Path | None = None, *, corpora: tuple[str, ...] = (), allow_unpinned: bool = False) -> Bench:
    """The vendored snapshot, or a checkout verified against the pinned manifest for ``corpora``."""
    if bench_path is None:
        return Bench.vendored_snapshot()
    bench = Bench.from_path(bench_path)
    report = bench.verify(corpora)
    if not report.ok and not allow_unpinned:
        raise BenchError(
            f"{bench.root} does not match the pinned bench commit (pass allow_unpinned / --allow-unpinned "
            "to score it anyway; results will not be comparable to the leaderboard):\n  " + "\n  ".join(report.problems[:20])
        )
    return bench


async def arun(
    defence: Any,
    corpus: str = "dev",
    *,
    bench: Bench | None = None,
    bench_path: str | Path | None = None,
    name: str | None = None,
    heldout_confirm: str | None = None,
    allow_unpinned: bool = False,
    measured_at: str | Callable[[], str] = iso_now,
) -> dict[str, Any]:
    """Async form of :func:`run`, for callers already inside an event loop."""
    adapter = load_adapter(defence, name=name)
    tool = meta_dict(adapter).get("tool") or name
    if corpus == "heldout":
        if bench is None and bench_path is None:
            raise BenchError("the held-out corpus is not vendored; pass bench_path (--bench-path) to a bench checkout")
        if not heldout_confirm or heldout_confirm != tool:
            raise BenchError(f"{HELDOUT_NOTICE} To proceed, pass heldout_confirm={tool!r} (--heldout-confirm {tool}).")
    if bench is None:
        bench = open_bench(bench_path, corpora=(corpus,), allow_unpinned=allow_unpinned and corpus != "heldout")
    cases = bench.load_cases(corpus)
    if corpus == "benign":
        return await score_benign(adapter, cases, bench.rubric, tool=tool, measured_at=measured_at)
    return await score_matched(adapter, cases, bench.rubric, corpus=corpus, tool=tool, measured_at=measured_at)


def run(defence: Any, corpus: str = "dev", **kwargs: Any) -> dict[str, Any]:
    """Score ``defence`` (an adapter, or a ``"module:Attr"`` spec) on ``corpus``.

    ``corpus`` is ``"dev"`` (default) or ``"benign"`` from the vendored snapshot, or ``"heldout"``
    from a bench checkout with an explicit ``heldout_confirm``. Returns the same JSON document as
    the JS ``bin/run.mjs``. Raises ``RuntimeError`` inside a running event loop; use :func:`arun`.
    """
    return asyncio.run(arun(defence, corpus, **kwargs))
