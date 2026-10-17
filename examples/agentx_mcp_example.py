"""Score agentx-mcp (https://pypi.org/project/agentx-mcp/) as it ships: its stdio proxy.

agentx-mcp wraps a server's launch command and screens every ``tools/call`` with the keyless
shield from agentx-security-sdk (destructive SQL, SSRF, secret reads, ...). It also fingerprints
each ``tools/list`` answer: a definition that changes after first sight, or a description that
carries a hidden-Unicode payload, is reported on stderr as "MCP Tool Description Drift".

Config choices:

* ``AGENTX_POSTURE=enforce``, the one line the README gives "to block rather than watch". The
  out-of-the-box posture is watch, which never changes traffic; it would score each enforce
  verdict below as detect only if its findings were visible, and they go to a local ledger.
* Tool pinning left at its default, ``warn``: a drift or poison finding is a stderr WARNING,
  scored as detect.
* No ``.agentx/rules.json`` or policies: the keyless built-in floor only, as a fresh install has.
* ``AGENTX_TELEMETRY=off`` (the documented opt-out of the default-on usage pulse) and ``HOME``
  pointed at a fresh temp directory per run, so no pin, ledger or pulse state leaks between
  fixtures and nothing is written to the real home directory or sent anywhere.

Read the result as "this config on this corpus", not as a rating of the project.

    pip install "mcp-defense-bench[fastmcp]" agentx-mcp
    mcp-defense-bench run examples.agentx_mcp_example:enforce --corpus all --name agentx-mcp
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

from mcp_defense_bench.adapters.stdio import StdioProxyAdapter


def _agentx_mcp() -> str:
    exe = shutil.which("agentx-mcp") or str(Path(sys.executable).with_name("agentx-mcp"))
    if not Path(exe).exists():
        raise RuntimeError("agentx-mcp is not installed: pip install agentx-mcp")
    return exe


def enforce() -> StdioProxyAdapter:
    def wrap(server: list[str], work: Path) -> tuple[list[str], dict[str, str]]:
        home = work / "home"
        home.mkdir()
        env = {"HOME": str(home), "AGENTX_TELEMETRY": "off", "AGENTX_POSTURE": "enforce"}
        return [_agentx_mcp(), *server], env

    from importlib.metadata import version

    return StdioProxyAdapter(
        "agentx-mcp",
        wrap,
        warn_pattern=r"\[agentx-mcp\] WARNING:",
        version=f"{version('agentx-mcp')} (agentx-security-sdk {version('agentx-security-sdk')})",
    )
