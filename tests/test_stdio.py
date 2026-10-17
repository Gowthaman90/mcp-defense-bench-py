from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastmcp")
from mcp_defense_bench.adapters.stdio import StdioProxyAdapter

PROXY = [sys.executable, str(Path(__file__).with_name("stdio_passthrough_proxy.py"))]
CASES = (
    "tool-poisoning/001-instruction-override",  # tools/list
    "response-injection/001-result-borne-instruction",  # tools/call with placeholder arguments
    "rug-pull/001-post-trust-mutation",  # tools/list twice, definition swapped in between
)


def _case(bench, cid: str) -> dict[str, Any]:
    return next(c for c in bench.load_cases("dev") if c["id"] == cid)


def test_pass_through_proxy_changes_nothing(bench):
    a = StdioProxyAdapter("pass-through", wrap=[*PROXY, "--"])
    for cid in CASES:
        tc = _case(bench, cid)
        assert asyncio.run(a.assess(tc["fixture"], tc)).to_dict() == {"detect": False, "enforce": False}, cid


def test_result_fixture_is_called_with_placeholder_arguments(bench):
    tc = _case(bench, "response-injection/001-result-borne-instruction")
    run = asyncio.run(StdioProxyAdapter("pass-through", wrap=[*PROXY, "--"])._drive(tc["fixture"], proxied=True))
    assert run["raised"] is None and run["steps"][0]["received"] == [{"city": "x"}]


def test_stderr_warning_is_detect_only_and_refusal_is_enforce(bench):
    tc = _case(bench, "command-injection/001-shell-metacharacter")

    def warn(server: list[str], work: Path) -> tuple[list[str], dict[str, str]]:
        return [*PROXY, "--warn", "--", *server], {}

    v = asyncio.run(StdioProxyAdapter("warn", wrap=warn, warn_pattern=r"\[proxy\] WARNING:").assess(tc["fixture"], tc))
    assert (v.detect, v.enforce) == (True, False) and "tools/call" in (v.signal or "")
    v = asyncio.run(StdioProxyAdapter("refuse", wrap=[*PROXY, "--refuse", "--"]).assess(tc["fixture"], tc))
    assert (v.detect, v.enforce) == (True, True) and "refused by proxy" in (v.signal or "")


def test_wrap_must_not_be_a_bare_string():
    with pytest.raises(TypeError):
        StdioProxyAdapter("x", wrap="my-proxy --")
