from __future__ import annotations

import json
import shutil

import pytest

from mcp_defense_bench import BENCH_COMMIT
from mcp_defense_bench.bench import VENDORED_ROOT, Bench, BenchError, load_manifest, scored_case_files


def test_vendored_snapshot_verifies(bench):
    report = bench.verify(("dev", "benign"))
    assert report.ok, report.problems
    assert report.counts == {"dev": 66, "benign": 337}


def test_manifest_pins_commit_and_counts():
    m = load_manifest()
    assert m["benchCommit"] == BENCH_COMMIT
    assert (m["benchVersion"], m["rubricVersion"], m["vectors"]) == ("0.9.0", "0.9.0", 37)
    c = m["corpora"]
    assert (c["dev"]["cases"], c["dev"]["vectorDirs"]) == (66, 37)
    assert (c["benign"]["cases"], c["benign"]["vectorDirs"]) == (337, 13)
    assert (c["heldout"]["cases"], c["heldout"]["vectorDirs"], c["heldout"]["vendored"]) == (63, 29, False)


def test_heldout_is_not_vendored(bench):
    assert not (VENDORED_ROOT / "testcases-heldout").exists()
    with pytest.raises(BenchError, match="not vendored"):
        bench.load_cases("heldout")


def test_rubric(bench):
    ids = [v["id"] for v in bench.rubric["vectors"]]
    assert len(ids) == len(set(ids)) == 37
    assert sum(v.get("vectorFamily") == "delegation" for v in bench.rubric["vectors"]) == 5


def test_tampering_is_detected(tmp_path):
    root = tmp_path / "bench"
    shutil.copytree(VENDORED_ROOT, root)
    victim = root / "testcases" / "tool-poisoning" / "001-instruction-override.json"
    tc = json.loads(victim.read_text("utf8"))
    tc["fixture"]["tool"]["description"] = "harmless"
    victim.write_text(json.dumps(tc), "utf8")
    (root / "testcases" / "tool-poisoning" / "999-extra.json").write_text("{}", "utf8")
    report = Bench(root).verify(("dev",))
    assert not report.ok
    assert any("001-instruction-override.json differs" in p for p in report.problems)
    assert any("unexpected testcases/tool-poisoning/999-extra.json" in p for p in report.problems)


def test_loader_mirrors_run_mjs_skip_rules_and_order(tmp_path):
    """Messy corpus folder: raw harvests, private dirs, stray files, non-JSON files."""
    d = tmp_path / "testcases"
    for rel in [
        "b-vec/002.json",
        "b-vec/001.json",
        "b-vec/notes.md",
        "a-vec/x.json",
        "_staging/1.json",
        "harvested/server.json",
        "harvested/docker.skipped.json",
        "README.md",
    ]:
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("{}", "utf8")
    got = [f.relative_to(d).as_posix() for f in scored_case_files(d)]
    assert got == ["a-vec/x.json", "b-vec/001.json", "b-vec/002.json"]


def test_checkout_heldout_hashes_and_counts_only(bench_checkout):
    """Held-out integrity: hashes and counts against the manifest. Nothing is scored."""
    report = Bench.from_path(bench_checkout).verify(("heldout",))
    assert report.ok, report.problems
    assert report.counts == {"heldout": 63}
