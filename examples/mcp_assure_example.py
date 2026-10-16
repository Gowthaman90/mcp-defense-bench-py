"""Score mcp-assure (https://pypi.org/project/mcp-assure/) through its FastMCP middleware.

mcp-assure is a deny-by-default authorization gate on ``tools/call``: it decides *who may call
which tool with which arguments*, from an operator-written policy pack. This example uses its
shipped ``baseline`` pack unchanged. A real deployment writes a pack for its own tools, so read
the result as "this pack on this corpus", not as a rating of the project.

    pip install "mcp-defense-bench[fastmcp]" mcp-assure
    mcp-defense-bench run examples.mcp_assure_example:baseline_pack --corpus all --name mcp-assure
"""

from __future__ import annotations

from typing import Any

from mcp_assure import AssureEngine
from mcp_assure.integrations.fastmcp_mw import build_assure_middleware
from mcp_assure.packs import load_pack


def baseline_pack() -> Any:
    """A fresh engine and middleware (velocity state is per instance), so no state leaks between fixtures."""
    return build_assure_middleware(AssureEngine(load_pack("baseline")))
