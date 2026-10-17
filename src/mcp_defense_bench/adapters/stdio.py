"""Score a stdio MCP *proxy*: a command you put in front of a server's launch command.

Many MCP defences are not middleware but a wrapper, ``my-proxy [options] -- python server.py``.
To score one as it ships, this adapter starts a fixture server
(``python -m mcp_defense_bench.adapters.stdio_server``) for each input, drives it with
``fastmcp.Client`` over stdio once directly and once through the proxy, and compares the two
runs. Nothing inside the proxy is imported or re-implemented: the bench sees exactly what an MCP
client would. The traffic per fixture type is the same as ``FastMCPAdapter``'s.

``wrap`` turns the server command into the proxied one. Either a command prefix::

    StdioProxyAdapter("my-proxy", wrap=["my-proxy", "--policy", "policy.yaml", "--"])

or, when the proxy needs per-run files or environment, a function
``wrap(server_cmd, workdir) -> (full_cmd, extra_env)``. ``workdir`` is a fresh temporary
directory for that run (also the processes' working directory), so a proxy's state (pins, audit
logs, a ``HOME``) never leaks from one input to the next. Both runs start from the MCP SDK's
minimal default environment; ``extra_env`` is added on top for the proxied run only.

Verdict, as in ``FastMCPAdapter``: **enforce** when the proxied run raised, returned an error,
kept a call from reaching the tool, hid or rewrote a definition, or rewrote a result; **detect**
when it only printed a stderr line matching ``warn_pattern``; otherwise nothing.

The stdio form costs two process starts per input, so a full ``--corpus all`` run takes minutes.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

try:
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport

    from mcp_defense_bench.adapters import AdapterMeta, Verdict
    from mcp_defense_bench.adapters._fixture import FIXTURE_TYPES, call_outcome, calls, diff, listing
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError("the stdio adapter needs fastmcp: pip install 'mcp-defense-bench[fastmcp]'") from e

__all__ = ["SERVER_MODULE", "StdioProxyAdapter", "Wrap", "server_command"]

SERVER_MODULE = "mcp_defense_bench.adapters.stdio_server"

# wrap(server_cmd, workdir) -> (full command, extra environment)
Wrap = Callable[[list[str], Path], tuple[list[str], dict[str, str]]]


def server_command(fixture_path: Path, invocations_path: Path) -> list[str]:
    """The command that serves one fixture over stdio, with this interpreter."""
    return [sys.executable, "-m", SERVER_MODULE, str(fixture_path), str(invocations_path)]


class StdioProxyAdapter:
    """Wrap a stdio MCP proxy command as a bench adapter."""

    def __init__(
        self,
        tool: str,
        wrap: Wrap | Sequence[str],
        *,
        warn_pattern: str | None = None,
        tool_class: str = "runtime-proxy",
        timeout: float = 60.0,
        version: str | None = None,
    ) -> None:
        if callable(wrap):
            self.wrap: Wrap = wrap
        elif isinstance(wrap, str):
            raise TypeError("wrap must be a command prefix list or a function, not a string")
        else:
            prefix = [str(a) for a in wrap]
            self.wrap = lambda server, _work: ([*prefix, *server], {})
        self.warn = re.compile(warn_pattern) if warn_pattern else None
        self.timeout = timeout
        extra = {"version": version} if version else {}
        self.meta = AdapterMeta(tool=tool, class_=tool_class, reproducible=True, fixture_types=FIXTURE_TYPES, extra=extra)

    async def assess(self, input: Mapping[str, Any], testcase: Mapping[str, Any]) -> Verdict:
        base = await self._drive(input, proxied=False)
        if base["raised"]:
            raise RuntimeError(f"fixture server failed without the proxy: {base['raised']}\n{base['stderr'][-2000:]}")
        guarded = await self._drive(input, proxied=True)
        if guarded["raised"]:
            return Verdict(True, True, f"blocked: {guarded['raised']}"[:200])
        for i, (b, g) in enumerate(zip(base["steps"], guarded["steps"], strict=False)):
            if b != g:
                return Verdict(True, True, f"step {i + 1} ({b['op']}): {diff(b, g)}"[:200])
        if self.warn:
            hit = next((ln for ln in guarded["stderr"].splitlines() if self.warn.search(ln)), None)
            if hit:
                return Verdict(True, False, f"warned: {hit.strip()}"[:200])
        return Verdict(False, False)

    async def _drive(self, fx: Mapping[str, Any], *, proxied: bool) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="mdb-") as tmp:
            work = Path(tmp)
            (work / "fixture.json").write_text(json.dumps(fx), encoding="utf-8")
            calls_log = work / "invocations.jsonl"
            calls_log.touch()
            cmd = server_command(work / "fixture.json", calls_log)
            env: dict[str, str] = {}
            if proxied:
                cmd, env = self.wrap(cmd, work)
            stderr_path = work / "stderr.log"
            steps: list[dict[str, Any]] = []
            raised = None
            with open(stderr_path, "w", encoding="utf-8") as err:
                transport = StdioTransport(cmd[0], cmd[1:], env=env or None, cwd=str(work), keep_alive=False, log_file=err)
                try:
                    await asyncio.wait_for(_traffic(fx, Client(transport), calls_log, steps), self.timeout)
                except Exception as e:  # the proxy may refuse by failing the request or the session
                    raised = f"{type(e).__name__}: {e}"
            return {"steps": steps, "raised": raised, "stderr": stderr_path.read_text(encoding="utf-8", errors="replace")}


async def _traffic(fx: Mapping[str, Any], client: Client[Any], calls_log: Path, steps: list[dict[str, Any]]) -> None:
    ftype = fx.get("type")
    async with client:
        if ftype in ("malicious-tool-definition", "benign-tool-definition"):
            steps.append({"op": "tools/list", "tools": listing(await client.list_tools())})
        elif ftype == "definition-change":  # the server swaps before -> after after the first list
            steps.append({"op": "tools/list", "tools": listing(await client.list_tools())})
            steps.append({"op": "tools/list", "tools": listing(await client.list_tools())})
        else:
            for call in calls(fx):
                before = len(_invocations(calls_log))
                r = await client.call_tool(call["name"], call["arguments"], raise_on_error=False)
                steps.append(call_outcome(r, _invocations(calls_log)[before:]))


def _invocations(path: Path) -> list[dict[str, Any]]:
    return [json.loads(ln)["arguments"] for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
