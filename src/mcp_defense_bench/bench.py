"""Locate, verify and load the benchmark: the rubric and the three corpora.

Two sources are supported:

* the snapshot vendored in this package (rubric + dev + benign at ``BENCH_COMMIT``), checked
  against ``_bench/MANIFEST.json`` on load;
* a local checkout of github.com/Gowthaman90/mcp-defense-bench (``Bench.from_path``), needed for
  the held-out corpus, which is deliberately not vendored.

Case discovery mirrors ``bin/run.mjs`` exactly, including its order (directory entries sorted by
code point, as libuv's scandir returns them) and its skip rules: non-directories, ``_``-prefixed
directories and ``harvested/`` hold raw inputs, not cases.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Corpus = Literal["dev", "heldout", "benign"]
CORPUS_DIRS: dict[str, str] = {"dev": "testcases", "heldout": "testcases-heldout", "benign": "testcases-benign"}
VENDORED_ROOT = Path(__file__).resolve().parent / "_bench"


class BenchError(Exception):
    """The benchmark data is missing, altered, or used against the held-out protocol."""


def scored_case_files(corpus_dir: Path) -> list[Path]:
    """The case files ``bin/run.mjs`` scores in ``corpus_dir``, in the order it scores them."""
    if not corpus_dir.is_dir():
        raise BenchError(f"corpus directory {corpus_dir} does not exist")
    files: list[Path] = []
    for vec in sorted(p.name for p in corpus_dir.iterdir()):
        p = corpus_dir / vec
        if not p.is_dir() or vec.startswith("_") or vec == "harvested":
            continue
        files.extend(p / f for f in sorted(x.name for x in p.iterdir()) if f.endswith(".json"))
    return files


def _sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _digest(hashes: dict[str, str]) -> str:
    return hashlib.sha256("".join(f"{h}  {p}\n" for p, h in hashes.items()).encode()).hexdigest()


@dataclass
class VerifyReport:
    """Outcome of comparing a benchmark tree with the manifest."""

    ok: bool = True
    problems: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)

    def fail(self, msg: str) -> None:
        self.ok = False
        self.problems.append(msg)


def load_manifest() -> dict[str, Any]:
    p = VENDORED_ROOT / "MANIFEST.json"
    if not p.is_file():
        raise BenchError(f"vendored manifest missing at {p}; the package install is incomplete")
    manifest: dict[str, Any] = json.loads(p.read_text("utf8"))
    return manifest


@dataclass
class Bench:
    """A benchmark tree on disk (vendored snapshot or a checkout)."""

    root: Path
    vendored: bool = False
    _rubric: dict[str, Any] | None = field(default=None, repr=False)

    @classmethod
    def vendored_snapshot(cls, verify: bool = True) -> Bench:
        bench = cls(VENDORED_ROOT, vendored=True)
        if verify:
            report = bench.verify(("dev", "benign"))
            if not report.ok:
                raise BenchError("vendored corpus does not match MANIFEST.json:\n  " + "\n  ".join(report.problems))
        return bench

    @classmethod
    def from_path(cls, path: str | Path) -> Bench:
        root = Path(path).expanduser().resolve()
        if not (root / "rubric" / "crosswalk.json").is_file():
            raise BenchError(f"{root} is not an mcp-defense-bench checkout (no rubric/crosswalk.json)")
        return cls(root)

    @property
    def rubric(self) -> dict[str, Any]:
        if self._rubric is None:
            self._rubric = json.loads((self.root / "rubric" / "crosswalk.json").read_text("utf8"))
        return self._rubric

    def has_corpus(self, corpus: str) -> bool:
        return (self.root / CORPUS_DIRS[corpus]).is_dir()

    def load_cases(self, corpus: str) -> list[dict[str, Any]]:
        """Every test case of ``corpus``, parsed, in scoring order."""
        if corpus not in CORPUS_DIRS:
            raise BenchError(f"unknown corpus {corpus!r}; expected one of {sorted(CORPUS_DIRS)}")
        if corpus == "heldout" and self.vendored:
            raise BenchError("the held-out corpus is not vendored; pass a bench checkout (--bench-path)")
        return [json.loads(f.read_text("utf8")) for f in scored_case_files(self.root / CORPUS_DIRS[corpus])]

    def verify(self, corpora: Iterable[str] = ("dev", "benign", "heldout")) -> VerifyReport:
        """Compare this tree's rubric and scored case files with the pinned manifest.

        Only file hashes and counts are read; nothing is scored.
        """
        manifest = load_manifest()
        report = VerifyReport()
        for rel, want in manifest["rubric"].items():
            p = self.root / rel
            if not p.is_file():
                report.fail(f"missing {rel}")
            elif _sha256(p) != want:
                report.fail(f"{rel} differs from bench {manifest['benchCommit'][:7]}")
        for corpus in corpora:
            entry = manifest["corpora"][corpus]
            corpus_dir = self.root / CORPUS_DIRS[corpus]
            if not corpus_dir.is_dir():
                report.fail(f"{CORPUS_DIRS[corpus]}/ not present")
                continue
            files = scored_case_files(corpus_dir)
            got = {f.relative_to(self.root).as_posix(): _sha256(f) for f in files}
            report.counts[corpus] = len(got)
            if _digest(got) == entry["digest"]:
                continue
            want_files: dict[str, str] = entry["files"]
            for rel in sorted(set(want_files) - set(got)):
                report.fail(f"{corpus}: missing {rel}")
            for rel in sorted(set(got) - set(want_files)):
                report.fail(f"{corpus}: unexpected {rel}")
            for rel in sorted(set(got) & set(want_files)):
                if got[rel] != want_files[rel]:
                    report.fail(f"{corpus}: {rel} differs")
            if not report.problems:
                report.fail(f"{corpus}: digest mismatch")
        return report
