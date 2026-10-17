"""Score a FastMCP middleware by running each fixture through a real in-memory FastMCP server.

For every input the adapter builds a fresh ``FastMCP`` server that serves the fixture's tools,
mounts the middleware, and drives it with a ``fastmcp.Client`` over the in-memory transport —
so the middleware sees exactly the ``tools/list`` and ``tools/call`` traffic it would see in
production, and nothing else. The same traffic is replayed through a server *without* the
middleware; any difference is the middleware acting.

Fixture types it can express (others stay ``unknown``, per the bench's integrity rule):

==========================================  ==========================================
``malicious-``/``benign-tool-definition``   ``tools/list`` serving that definition
``tool-call``                               ``tools/call`` with the fixture's arguments
``malicious-``/``benign-tool-result``       ``tools/call`` whose tool returns that result
``tool-call-sequence``                      the calls, in order, in one session
``definition-change``                       list, swap ``before`` → ``after``, list again
==========================================  ==========================================

A result fixture that gives no ``call`` is called with placeholder values for the tool's
``required`` arguments (first ``enum`` value, ``"x"``, ``0``, ``false``, ``[]``, ``{}``), so a gate
that enforces the input schema does not refuse both arms of a case for a request the fixture never
specified.

Verdict: **enforce** when the middleware raised, returned an error, kept the call from reaching
the tool, hid or rewrote a tool definition, or rewrote a result; **detect** when it only logged a
WARNING or worse on ``warn_logger``; otherwise nothing. Operator-side context a middleware never
receives over MCP (e.g. a fixture's ``configuredBoundary``) is not passed to it.
"""

from __future__ import annotations

import copy
import logging
from collections.abc import Callable, Mapping
from typing import Any

try:
    from fastmcp import Client, FastMCP
    from fastmcp.server.middleware import Middleware

    from mcp_defense_bench.adapters._fixture import (
        FIXTURE_TYPES,
        FixtureTool,
        call_outcome,
        calls,
        diff,
        fixture_reply,
        fixture_tool,
        listing,
    )
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError("the FastMCP adapter needs fastmcp: pip install 'mcp-defense-bench[fastmcp]'") from e

__all__ = ["FIXTURE_TYPES", "FastMCPAdapter"]


class FastMCPAdapter:
    """Wrap a FastMCP ``Middleware`` (class, zero-arg factory, or instance) as a bench adapter.

    A fresh middleware is created for every input (an instance is deep-copied), so state such as
    definition pins never leaks from one fixture to the next.
    """

    def __init__(
        self,
        middleware: type[Middleware] | Callable[[], Middleware] | Middleware,
        *,
        tool: str | None = None,
        tool_class: str = "fastmcp-middleware",
        warn_logger: str | None = None,
    ) -> None:
        if isinstance(middleware, Middleware):
            instance = middleware
            self._factory: Callable[[], Middleware] = lambda: copy.deepcopy(instance)
            default_name = type(middleware).__name__
        else:
            self._factory = middleware
            default_name = getattr(middleware, "__name__", "fastmcp-middleware")
        self.warn_logger = warn_logger
        self.meta: dict[str, Any] = {
            "tool": tool or default_name,
            "class": tool_class,
            "reproducible": True,
            "fixtureTypes": list(FIXTURE_TYPES),
        }

    async def assess(self, input: Mapping[str, Any], testcase: Mapping[str, Any]) -> dict[str, Any]:
        base = await self._drive(input, None)
        records: list[logging.LogRecord] = []
        handler = _Collect(records)
        log = logging.getLogger(self.warn_logger) if self.warn_logger else None
        if log:
            log.addHandler(handler)
        try:
            guarded = await self._drive(input, self._factory())
        finally:
            if log:
                log.removeHandler(handler)
        if guarded.get("raised") and not base.get("raised"):
            return {"detect": True, "enforce": True, "signal": f"blocked: {guarded['raised']}"[:200]}
        for i, (b, g) in enumerate(zip(base["steps"], guarded["steps"], strict=False)):
            if b != g:
                return {"detect": True, "enforce": True, "signal": f"step {i + 1} ({b['op']}): {diff(b, g)}"[:200]}
        if records:
            return {"detect": True, "enforce": False, "signal": f"warned: {records[0].getMessage()}"[:200]}
        return {"detect": False, "enforce": False}

    async def _drive(self, fx: Mapping[str, Any], middleware: Middleware | None) -> dict[str, Any]:
        """Run the fixture's MCP traffic and record each observable step."""
        server = FastMCP("mcp-defense-bench")
        steps: list[dict[str, Any]] = []
        ftype = fx.get("type")
        quiet = logging.getLogger("fastmcp")
        level = quiet.level
        quiet.setLevel(logging.ERROR)  # the client warns when a middleware hides a tool; expected here
        try:
            if ftype in ("malicious-tool-definition", "benign-tool-definition"):
                server.add_tool(fixture_tool(fx["tool"]))
            elif ftype in ("tool-call", "malicious-tool-result", "benign-tool-result"):
                server.add_tool(fixture_tool(fx["tool"], fixture_reply(fx)))
            elif ftype == "tool-call-sequence":
                for name in dict.fromkeys(str(c["name"]) for c in fx["calls"]):
                    server.add_tool(fixture_tool({"name": name}))
            elif ftype == "definition-change":
                server.add_tool(fixture_tool(fx["before"]))
            else:
                raise ValueError(f"fixture type {ftype!r} is not wired for FastMCP")
            if middleware is not None:
                server.add_middleware(middleware)

            async with Client(server) as client:
                try:
                    if ftype in ("malicious-tool-definition", "benign-tool-definition"):
                        steps.append({"op": "tools/list", "tools": listing(await client.list_tools())})
                    elif ftype == "definition-change":
                        steps.append({"op": "tools/list", "tools": listing(await client.list_tools())})
                        server.local_provider.remove_tool(str(fx["before"]["name"]))
                        server.add_tool(fixture_tool(fx["after"]))
                        steps.append({"op": "tools/list", "tools": listing(await client.list_tools())})
                    else:
                        for call in calls(fx):
                            tool = await _get_tool(server, call["name"])
                            before = len(tool.invocations)
                            r = await client.call_tool(call["name"], call["arguments"], raise_on_error=False)
                            steps.append(call_outcome(r, tool.invocations[before:]))
                except Exception as e:  # the middleware may refuse by raising
                    return {"steps": steps, "raised": f"{type(e).__name__}: {e}"}
        finally:
            quiet.setLevel(level)
        return {"steps": steps, "raised": None}


async def _get_tool(server: FastMCP, name: str) -> FixtureTool:
    tool = await server.get_tool(name)
    assert isinstance(tool, FixtureTool)
    return tool


class _Collect(logging.Handler):
    def __init__(self, sink: list[logging.LogRecord]) -> None:
        super().__init__(logging.WARNING)
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        self.sink.append(record)
