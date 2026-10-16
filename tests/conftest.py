from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from mcp_defense_bench import BENCH_COMMIT
from mcp_defense_bench.bench import Bench

pytest_plugins = ["pytester"]

FIXTURES = Path(__file__).parent / "fixtures" / f"js-{BENCH_COMMIT[:7]}"
TOOLS = ("null-baseline", "mcp-bastion", "mcp-firewall", "pipelock")


@pytest.fixture(scope="session")
def bench() -> Bench:
    return Bench.vendored_snapshot()


@pytest.fixture(scope="session")
def js_fixtures() -> Path:
    return FIXTURES


def recorded(path: Path) -> tuple[bytes, dict[str, Any]]:
    raw = path.read_bytes()
    return raw, json.loads(raw)


@pytest.fixture(scope="session")
def bench_checkout() -> Path:
    """A local mcp-defense-bench checkout (MCP_DEFENSE_BENCH_PATH, or a sibling folder)."""
    env = os.environ.get("MCP_DEFENSE_BENCH_PATH")
    candidates = [Path(env)] if env else [Path(__file__).resolve().parents[2] / "mcp-defense-bench"]
    for p in candidates:
        if (p / "rubric" / "crosswalk.json").is_file():
            return p
    pytest.skip("no mcp-defense-bench checkout (set MCP_DEFENSE_BENCH_PATH)")
