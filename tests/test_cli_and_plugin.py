from __future__ import annotations

import json

from mcp_defense_bench.cli import main

NULL = "mcp_defense_bench.adapters.null:NullBaseline"


def test_cli_run_writes_js_layout(tmp_path, capsys):
    assert main(["run", NULL, "--corpus", "all", "--out-dir", str(tmp_path), "-q"]) == 0
    out = capsys.readouterr().out
    assert '"overall": "0% (0.0/37 CorpusRobustCoverage)"' in out
    assert "totals: published 0% (0.0/32) · all 0% (0.0/37) · delegation family 0% (0.0/5)" in out
    assert json.loads((tmp_path / "null-baseline.json").read_text())["summary"]["casesRun"] == 66
    assert json.loads((tmp_path / "benign" / "null-baseline.json").read_text())["summary"]["items"] == 337
    assert json.loads((tmp_path / "coverage" / "null-baseline.json").read_text())["measuredBy"].startswith("mcp_defense_bench")


def test_cli_heldout_needs_confirmation(capsys):
    assert main(["run", NULL, "--corpus", "heldout"]) == 2
    assert "not vendored" in capsys.readouterr().err


def test_cli_verify_and_info(capsys):
    assert main(["verify"]) == 0
    assert main(["info"]) == 0
    out = capsys.readouterr().out
    assert "OK: matches the pinned manifest" in out and "heldout    63 cases" in out


def test_cli_totals_markdown(js_fixtures, capsys):
    assert main(["totals", str(js_fixtures / "results" / "mcp-bastion.json"), "--markdown"]) == 0
    assert capsys.readouterr().out.strip() == "| **mcp-bastion** | 62% (19.9/32) | 66% (24.6/37) | 93% (4.7/5) |"


def test_cli_check_gate(tmp_path, capsys):
    base = tmp_path / "b.json"
    assert main(["check", NULL, "--baseline", str(base)]) == 0  # creates it
    assert main(["check", NULL, "--baseline", str(base)]) == 0  # unchanged → pass
    doc = json.loads(base.read_text())
    doc["dev"]["robustCoverage"] = 3.0
    doc["dev"]["vectors"]["tool-poisoning"] = 1
    doc["benign"]["falsePositives"] = -1
    base.write_text(json.dumps(doc))
    assert main(["check", NULL, "--baseline", str(base)]) == 1
    out = capsys.readouterr().out
    assert "FAIL dev-coverage" in out and "tool-poisoning: 1 → 0" in out and "FAIL benign-false-positives" in out


GUARD = """
from mcp_defense_bench import Verdict

class Guard:
    meta = {"tool": "demo-guard", "class": "test", "reproducible": True}
    catch_poisoning = %s

    def assess(self, input, testcase):
        hit = self.catch_poisoning and input.get("type") == "malicious-tool-definition"
        return Verdict(detect=hit, enforce=hit)
"""


def _guard(pytester, catch: bool) -> None:
    pytester.makepyfile(demo_guard=GUARD % catch)
    pytester.syspathinsert()


def test_plugin_is_inert_without_option(pytester):
    pytester.makepyfile(test_x="def test_ok(): pass")
    pytester.runpytest("-p", "no:cacheprovider").assert_outcomes(passed=1)


def test_plugin_requires_a_baseline(pytester):
    _guard(pytester, True)
    r = pytester.runpytest("--mcp-defense=demo_guard:Guard")
    r.assert_outcomes(failed=3)
    r.stdout.fnmatch_lines(["*no baseline at*", "*pytest --mcp-defense=demo_guard:Guard --mcp-defense-update-baseline"])


def test_plugin_gate_passes_then_fails_on_regression(pytester):
    _guard(pytester, True)
    pytester.runpytest("--mcp-defense=demo_guard:Guard", "--mcp-defense-update-baseline").assert_outcomes(passed=3)
    assert (pytester.path / "mcp-defense-baseline.json").exists()
    r = pytester.runpytest("--mcp-defense=demo_guard:Guard")
    r.assert_outcomes(passed=3)
    r.stdout.fnmatch_lines(["*demo-guard: dev * CorpusRobustCoverage*", "*benign FP 0/337*"])
    _guard(pytester, False)  # the guard got worse
    r = pytester.runpytest("--mcp-defense=demo_guard:Guard")
    r.assert_outcomes(passed=2, failed=1)
    r.stdout.fnmatch_lines(["*dev-coverage regressed*", "*tool-poisoning: 1 → 0"])


def test_plugin_ini_config_and_fixture(pytester):
    _guard(pytester, True)
    pytester.makeini("[pytest]\nmcp_defense = demo_guard:Guard\nmcp_defense_corpus = dev\n")
    pytester.makepyfile(
        test_custom="""
def test_floor(mcp_defense_results):
    assert mcp_defense_results["dev"]["coverage"]["tool-poisoning"]["level"] == "enforce"
"""
    )
    pytester.runpytest("--mcp-defense-update-baseline").assert_outcomes(passed=3)


def test_plugin_imports_guard_from_rootdir_without_pythonpath(pytester):
    """A guard module next to the user's code, not installed and not on sys.path."""
    pytester.makepyfile(rootdir_guard=GUARD % True)
    pytester.runpytest("--mcp-defense=rootdir_guard:Guard", "--mcp-defense-update-baseline").assert_outcomes(passed=3)


def test_cli_imports_guard_from_cwd(pytester, capsys):
    pytester.makepyfile(cwd_guard=GUARD % True)
    assert main(["run", "cwd_guard:Guard", "-q"]) == 0
    assert '"tool": "demo-guard"' in capsys.readouterr().out
