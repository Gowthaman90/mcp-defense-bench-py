"""Score mcp-assure (https://pypi.org/project/mcp-assure/) through its FastMCP middleware.

mcp-assure is a deny-by-default authorization gate on ``tools/call``: it decides *who may call
which tool with which arguments*, from an operator-written policy pack. It checks the tool name
and the argument *names* (required / allowed / forbidden), size, depth and call velocity; it does
not read argument values, tool results or tool definitions.

Two configs:

* ``baseline_pack`` — the shipped ``baseline`` pack unchanged. It allow-lists three demo tools
  (``echo``, ``read_file``, ``list_dir``), so nearly every fixture's tool is unknown and denied on
  both arms: almost every control is flagged and the score says little about the gate.
* ``operator_pack`` — the pack an operator writes for the tools their own server exposes, built
  by one mechanical rule from each served tool's ``inputSchema``, never from a case:
  ``required_args`` = the schema's ``required``; ``allowed_args`` = its ``properties`` (left open
  when the schema declares none); ``forbidden_args`` = the baseline pack's credential names
  (``token``, ``password``, ``api_key``, ``authorization``) that the tool does not itself declare.
  Everything else (``max_blast``, size, depth, velocity) stays at mcp-assure's defaults.

Read either result as "this pack on this corpus", not as a rating of the project.

    pip install "mcp-defense-bench[fastmcp]" mcp-assure
    mcp-defense-bench run examples.mcp_assure_example:operator_pack --corpus all --name mcp-assure
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastmcp.server.middleware import Middleware
from mcp_assure import AssureEngine, ToolPolicy, ToolPolicyRegistry
from mcp_assure.integrations.fastmcp_mw import build_assure_middleware
from mcp_assure.packs import load_pack

CREDENTIAL_ARGS = ("token", "password", "api_key", "authorization")


def baseline_pack() -> Any:
    """A fresh engine and middleware (velocity state is per instance), so no state leaks between fixtures."""
    return build_assure_middleware(AssureEngine(load_pack("baseline")))


def policy_for(name: str, schema: Mapping[str, Any] | None) -> ToolPolicy:
    """The operator's entry for one served tool, from its declared input schema."""
    props = schema.get("properties") if isinstance(schema, Mapping) else None
    declared = tuple(props) if isinstance(props, Mapping) else ()
    required = schema.get("required") if isinstance(schema, Mapping) else None
    return ToolPolicy(
        name=name,
        required_args=tuple(required or ()),
        allowed_args=declared if isinstance(props, Mapping) else None,
        forbidden_args=tuple(a for a in CREDENTIAL_ARGS if a not in declared),
    )


class _OperatorPack(Middleware):
    """mcp-assure's own FastMCP middleware, with a pack written for the tools this server serves.

    The pack is built once, from the server's tool list, before the first call is gated, which is
    when an operator would have written it. The gate itself is ``build_assure_middleware``, unchanged.
    """

    def __init__(self) -> None:
        self.gate: Any = None

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        if self.gate is None:
            # AssureEngine replaces an empty (falsy) registry with a new one, so fill it first.
            server = context.fastmcp_context.fastmcp
            registry = ToolPolicyRegistry([policy_for(t.name, t.parameters) for t in await server.list_tools()])
            self.gate = build_assure_middleware(AssureEngine(registry))
        return await self.gate.on_call_tool(context, call_next)


def operator_pack() -> Any:
    return _OperatorPack()
