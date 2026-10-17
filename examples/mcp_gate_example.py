"""Score mcp-gate (https://pypi.org/project/mcp-gate-policy/) as it ships: its stdio proxy.

mcp-gate is a policy firewall for ``tools/call``: every call is matched against a first-match-wins
ruleset and allowed, denied, redacted, or held for a human. A heuristic threat scanner scores the
call's *arguments*; ``tools/list`` and tool results pass through unread by design.

Config choices (policies/mcp_gate_operator.yaml):

* The threat-scan rule is the one in mcp-gate's README, unchanged: ``min_threat_score: 4`` ->
  ``require_approval``. No approval hook is wired, so held calls are rejected, which is mcp-gate's
  documented fail-safe.
* ``default_effect: deny`` as the README says, plus one ``allow`` rule for the served tools.
  Each fixture serves only its own tools, so an operator's allow-list of their own tools is
  ``"*"`` here. Without it every call on both arms is denied, which scores 0 with every control
  flagged and says nothing about the scanner.
* ``--fail closed`` (the CLI default); anonymous identity (no ``--secret``), since the bench has
  no agent identity to present.

Read the result as "this policy on this corpus", not as a rating of the project.

    pip install "mcp-defense-bench[fastmcp]" "mcp-gate-policy[yaml]"
    mcp-defense-bench run examples.mcp_gate_example:operator_policy --corpus all --name mcp-gate
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from mcp_defense_bench.adapters.stdio import StdioProxyAdapter

POLICY = Path(__file__).with_name("policies") / "mcp_gate_operator.yaml"


def _mcp_gate() -> str:
    exe = shutil.which("mcp-gate") or str(Path(sys.executable).with_name("mcp-gate"))
    if not Path(exe).exists():
        raise RuntimeError("mcp-gate is not installed: pip install 'mcp-gate-policy[yaml]'")
    return exe


def operator_policy() -> StdioProxyAdapter:
    def wrap(server: list[str], work: Path) -> tuple[list[str], dict[str, str]]:
        cmd = [
            _mcp_gate(),
            "run",
            "--policy",
            str(POLICY),
            "--audit",
            str(work / "audit.jsonl"),
            "--fail",
            "closed",
            "--",
            *server,
        ]
        return cmd, {}

    from importlib.metadata import version

    return StdioProxyAdapter("mcp-gate", wrap, version=version("mcp-gate-policy"))
