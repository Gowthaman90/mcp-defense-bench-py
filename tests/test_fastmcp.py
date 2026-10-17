from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import pytest

fastmcp = pytest.importorskip("fastmcp")
from fastmcp.exceptions import ToolError  # noqa: E402
from fastmcp.server.middleware import Middleware  # noqa: E402

from mcp_defense_bench import load_adapter, run  # noqa: E402
from mcp_defense_bench.adapters._fixture import placeholder_arguments  # noqa: E402
from mcp_defense_bench.adapters.fastmcp import FastMCPAdapter  # noqa: E402


class Pinning(Middleware):
    """Trust-on-first-use definition pinning: refuse a tool whose definition changed."""

    def __init__(self) -> None:
        self.pins: dict[str, str] = {}

    async def on_list_tools(self, context: Any, call_next: Any) -> Any:
        out = []
        for t in await call_next(context):
            h = json.dumps([t.description, t.parameters], sort_keys=True)
            if self.pins.setdefault(t.name, h) == h:
                out.append(t)
        return out


class WarnOnly(Middleware):
    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        if ";" in json.dumps(context.message.arguments):
            logging.getLogger("warn_only").warning("suspicious argument")
        return await call_next(context)


class Sanitiser(Middleware):
    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        clean = {k: str(v).split(";")[0] for k, v in (context.message.arguments or {}).items()}
        return await call_next(context.copy(message=context.message.model_copy(update={"arguments": clean})))


class RequiredArgs(Middleware):
    """A schema-enforcing gate: refuse a call that leaves out a required argument."""

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        tool = await context.fastmcp_context.fastmcp.get_tool(context.message.name)
        missing = set(tool.parameters.get("required", ())) - set(context.message.arguments or {})
        if missing:
            raise ToolError(f"missing required argument: {', '.join(sorted(missing))}")
        return await call_next(context)


class Refuser(Middleware):
    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        raise ToolError("no")


def _case(bench, cid: str) -> dict[str, Any]:
    return next(c for c in bench.load_cases("dev") if c["id"] == cid)


def test_pass_through_middleware_scores_exactly_like_null(bench):
    """No spurious differences: an inert middleware must score 0 with 0 false positives."""
    dev = run(FastMCPAdapter(Middleware, tool="inert"))["summary"]
    ben = run(FastMCPAdapter(Middleware, tool="inert"), "benign")["summary"]
    assert dev["robustCoverage"] == 0 and dev["falsePositives"] == 0
    assert dev["covered"]["none"] == dev["verifiedVectors"] and dev["casesRun"] > 0
    assert ben["falsePositives"] == 0 and ben["items"] > 300


def test_pinning_catches_rug_pull_but_not_unchanged_definition(bench):
    tc = _case(bench, "rug-pull/001-post-trust-mutation")
    a = FastMCPAdapter(Pinning)
    mal = asyncio.run(a.assess(tc["fixture"], tc))
    assert mal["detect"] and mal["enforce"] and "step 2" in mal["signal"]
    assert asyncio.run(a.assess(tc["benignControl"], tc)) == {"detect": False, "enforce": False}


def test_fresh_middleware_per_input(bench):
    tc = _case(bench, "rug-pull/001-post-trust-mutation")
    a = FastMCPAdapter(Pinning())  # an instance is deep-copied per input
    for _ in range(2):
        assert asyncio.run(a.assess(tc["benignControl"], tc))["detect"] is False


def test_warn_logger_is_detect_only(bench):
    tc = _case(bench, "command-injection/001-shell-metacharacter")
    v = asyncio.run(FastMCPAdapter(WarnOnly, warn_logger="warn_only").assess(tc["fixture"], tc))
    assert (v["detect"], v["enforce"]) == (True, False)
    v = asyncio.run(FastMCPAdapter(WarnOnly).assess(tc["fixture"], tc))
    assert v["detect"] is False


def test_rewriting_arguments_counts_as_enforce(bench):
    tc = _case(bench, "command-injection/001-shell-metacharacter")
    v = asyncio.run(FastMCPAdapter(Sanitiser).assess(tc["fixture"], tc))
    assert v["enforce"] and "rewrote the call arguments" in v["signal"]


def test_refusing_every_call_is_a_false_positive(bench):
    s = run(FastMCPAdapter(Refuser, tool="refuser"))
    tc = next(c for c in s["cases"] if c["id"] == "command-injection/001-shell-metacharacter")
    assert tc["level"] == "none" and tc["falsePositive"] is True


def test_placeholder_arguments_fill_only_required_properties():
    schema = {
        "type": "object",
        "properties": {
            "mode": {"type": "string", "enum": ["fast", "safe"]},
            "q": {"type": "string"},
            "n": {"type": "integer"},
            "x": {"type": "number"},
            "on": {"type": "boolean"},
            "tags": {"type": "array"},
            "opts": {"type": "object"},
            "maybe": {"type": ["null", "string"]},
            "optional": {"type": "string"},
        },
        "required": ["mode", "q", "n", "x", "on", "tags", "opts", "maybe", "undeclared"],
    }
    assert placeholder_arguments(schema) == {
        "mode": "fast",
        "q": "x",
        "n": 0,
        "x": 0,
        "on": False,
        "tags": [],
        "opts": {},
        "maybe": "x",
        "undeclared": "x",
    }
    assert placeholder_arguments(None) == {} and placeholder_arguments({"type": "object"}) == {}


def test_schema_enforcing_gate_passes_result_fixtures_without_a_call(bench):
    """A result fixture with no ``call`` must not be refused on both arms for a missing argument."""
    for cid in ("response-injection/001-result-borne-instruction", "indirect-retrieval-injection/002-secret-in-fetched-doc"):
        tc = _case(bench, cid)
        assert "call" not in tc["fixture"]
        a = FastMCPAdapter(RequiredArgs)
        for arm in (tc["fixture"], tc["benignControl"]):
            assert asyncio.run(a.assess(arm, tc)) == {"detect": False, "enforce": False}, cid


def test_load_adapter_wraps_middleware_classes():
    a = load_adapter(Pinning, name="pin")
    assert isinstance(a, FastMCPAdapter) and a.meta["tool"] == "pin"


def test_example_keyword_guard():
    s = run("examples.keyword_guard:KeywordGuard")["summary"]
    assert s["tool"] == "KeywordGuard" and 0 < s["robustCoverage"] < 37
