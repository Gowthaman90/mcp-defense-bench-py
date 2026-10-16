"""Command line: ``mcp-defense-bench run|check|verify|totals|info``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from mcp_defense_bench import BENCH_COMMIT, BENCH_VERSION, __version__
from mcp_defense_bench.adapters import load_adapter
from mcp_defense_bench.baseline import compare, load_baseline, make_baseline, write_baseline
from mcp_defense_bench.bench import Bench, BenchError, load_manifest
from mcp_defense_bench.jscompat import stringify, to_fixed
from mcp_defense_bench.runner import HELDOUT_NOTICE, open_bench, run
from mcp_defense_bench.scoring import coverage_document
from mcp_defense_bench.totals import totals, two_totals_row


def _print_matched(res: dict[str, Any], quiet: bool) -> None:
    s = {k: v for k, v in res["summary"].items() if k != "measuredAt"}
    print(stringify(s))
    cov = res["coverage"]
    brittle = [vid for vid, c in cov.items() if c["verified"] and c["robustCoverage"] < c["capability"]]
    if brittle:
        print(f"  ⚠ evasion-brittle (RobustCoverage < Capability): {', '.join(brittle)}")
    if not quiet:
        for c in res["cases"]:
            if c["level"] != "none" or c["falsePositive"]:
                sig = c["mal"].get("signal")
                print(f"  {'⚠ FP' if c['falsePositive'] else '✓'} {c['id']} → {c['level']}{f'  [{sig}]' if sig else ''}")


def _print_benign(res: dict[str, Any], quiet: bool) -> None:
    print(stringify({k: v for k, v in res["summary"].items() if k != "measuredAt"}))
    if not quiet:
        for it in res["items"]:
            if it["falsePositive"]:
                print(f"  ⚠ FP {it['id']}  [{it['verdict'].get('signal') or ''}]")


def _write(path: Path, doc: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stringify(doc) + "\n", "utf8")
    print(f"  wrote {path}", file=sys.stderr)


def _corpora(choice: str) -> list[str]:
    return ["dev", "benign"] if choice == "all" else [choice]


def _totals_line(rubric: dict[str, Any], coverage: dict[str, Any]) -> str:
    parts = []
    for name, t in totals(rubric, coverage).items():
        label = name.removeprefix("family:") + (" family" if name.startswith("family:") else "")
        parts.append(f"{label} {t['percent']} ({to_fixed(t['robustCoverage'], 1)}/{t['vectors']})")
    return "  totals: " + " · ".join(parts)


def cmd_run(a: argparse.Namespace) -> int:
    if a.corpus == "heldout":
        print(f"note: {HELDOUT_NOTICE}", file=sys.stderr)
    adapter = load_adapter(a.defence, name=a.name, search_path=os.getcwd())
    for corpus in _corpora(a.corpus):
        res = run(adapter, corpus, bench_path=a.bench_path, heldout_confirm=a.heldout_confirm, allow_unpinned=a.allow_unpinned)
        tool = res["summary"]["tool"]
        if corpus == "benign":
            _print_benign(res, a.quiet)
        else:
            _print_matched(res, a.quiet)
            print(_totals_line(open_bench(a.bench_path, allow_unpinned=True).rubric, res["coverage"]))
        if a.out_dir:
            out = Path(a.out_dir)
            _write(out / ("" if corpus == "dev" else corpus) / f"{tool}.json", res)
            if corpus == "dev":
                _write(out / "coverage" / f"{tool}.json", coverage_document(adapter, res))
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    corpora = _corpora(a.corpus)
    adapter = load_adapter(a.defence, name=a.name, search_path=os.getcwd())
    res = {c: run(adapter, c, bench_path=a.bench_path, allow_unpinned=a.allow_unpinned) for c in corpora}
    path = Path(a.baseline)
    if a.update or not path.exists():
        write_baseline(path, make_baseline(res.get("dev"), res.get("benign")))
        print(f"{'updated' if path.exists() and a.update else 'created'} baseline {path}")
        return 0
    cmp = compare(load_baseline(path), res.get("dev"), res.get("benign"), tolerance=a.tolerance)
    for e in cmp.errors:
        print(f"ERROR {e}")
    for check, msgs in cmp.regressions.items():
        print(f"{'FAIL' if msgs else 'ok  '} {check}")
        for m in msgs:
            print(f"     {m}")
    for m in cmp.improvements:
        print(f"  ↑ {m}")
    if cmp.improvements and cmp.ok:
        print("  (improved; raise the baseline with --update)")
    return 0 if cmp.ok else 1


def cmd_verify(a: argparse.Namespace) -> int:
    m = load_manifest()
    if a.bench_path:
        bench = Bench.from_path(a.bench_path)
        corpora = [c for c in ("dev", "benign", "heldout") if bench.has_corpus(c)]
    else:
        bench, corpora = Bench(Path(__file__).parent / "_bench", vendored=True), ["dev", "benign"]
    report = bench.verify(corpora)
    print(f"bench {m['benchVersion']} @ {m['benchCommit'][:7]} — {bench.root}")
    for c in corpora:
        want = m["corpora"][c]["cases"]
        print(f"  {c:8} {report.counts.get(c, 0):4} / {want} case files")
    for p in report.problems:
        print(f"  ✗ {p}")
    print("OK: matches the pinned manifest (hashes and counts only; nothing scored)" if report.ok else "MISMATCH")
    return 0 if report.ok else 1


def cmd_totals(a: argparse.Namespace) -> int:
    dev = json.loads(Path(a.result).read_text("utf8"))
    held = json.loads(Path(a.heldout).read_text("utf8"))["coverage"] if a.heldout else None
    rubric = open_bench(a.bench_path, allow_unpinned=True).rubric
    if a.markdown:
        print(two_totals_row(dev["summary"]["tool"], rubric, dev["coverage"], held))
    else:
        print(json.dumps(totals(rubric, dev["coverage"], held), indent=2))
    return 0


def cmd_info(_: argparse.Namespace) -> int:
    m = load_manifest()
    print(f"mcp-defense-bench {__version__} (Python)")
    print(f"  bench {BENCH_VERSION} @ {BENCH_COMMIT}  rubric {m['rubricVersion']}, {m['vectors']} vectors")
    for c, e in m["corpora"].items():
        print(f"  {c:8} {e['cases']:4} cases  {'vendored' if e['vendored'] else 'hashes only (needs --bench-path)'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="mcp-defense-bench", description="Score Python MCP defences on mcp-defense-bench.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__} (bench {BENCH_VERSION} @ {BENCH_COMMIT[:7]})")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser, corpora: Sequence[str]) -> None:
        sp.add_argument("defence", help="adapter spec 'package.module:Attr' (adapter, factory, or FastMCP Middleware)")
        sp.add_argument("--corpus", choices=corpora, default="dev")
        sp.add_argument("--name", help="tool name to report (default: adapter meta, else the attribute name)")
        sp.add_argument("--bench-path", help="score from a bench checkout instead of the vendored snapshot")
        sp.add_argument("--allow-unpinned", action="store_true", help="accept a checkout that differs from the pinned commit")

    r = sub.add_parser("run", help="score a defence and print the summary")
    common(r, ["dev", "benign", "heldout", "all"])
    r.add_argument("--out-dir", help="write <dir>/<tool>.json, <dir>/benign/<tool>.json, <dir>/coverage/<tool>.json")
    r.add_argument("--heldout-confirm", metavar="TOOL", help="required for --corpus heldout: the tool name, as acknowledgement")
    r.add_argument("-q", "--quiet", action="store_true")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("check", help="fail (exit 1) if coverage fell or false positives rose against a baseline")
    common(c, ["dev", "benign", "all"])
    c.set_defaults(corpus="all")
    c.add_argument("--baseline", default="mcp-defense-baseline.json")
    c.add_argument("--update", action="store_true", help="overwrite the baseline with this run")
    c.add_argument("--tolerance", type=float, default=0.0, help="allowed coverage drop before failing")
    c.set_defaults(func=cmd_check)

    v = sub.add_parser("verify", help="check corpus hashes and counts against the pinned manifest")
    v.add_argument("--bench-path", help="verify a bench checkout (including held-out hashes) instead")
    v.set_defaults(func=cmd_verify)

    t = sub.add_parser("totals", help="published / all / per-family totals for a dev result file")
    t.add_argument("result")
    t.add_argument("--heldout", help="a recorded held-out result file, to add held-out totals")
    t.add_argument("--markdown", action="store_true", help="print the leaderboard table row")
    t.add_argument("--bench-path")
    t.set_defaults(func=cmd_totals)

    i = sub.add_parser("info", help="package, bench and corpus versions")
    i.set_defaults(func=cmd_info)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        rc: int = a.func(a)
    except (BenchError, ImportError, AttributeError, TypeError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return rc
