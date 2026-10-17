"""The MCP traffic a fixture stands for, shared by the in-process FastMCP and the stdio harnesses.

Both harnesses serve a fixture's tools from a real FastMCP server, drive the same requests with
``fastmcp.Client``, and compare one run without the defence to one run with it. Keeping the tool,
the calls and the step comparison in one place means the two cannot drift apart.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from typing import Any

import mcp.types as mt
from fastmcp.tools.base import Tool, ToolResult
from pydantic import Field

__all__ = [
    "FIXTURE_TYPES",
    "FixtureTool",
    "call_outcome",
    "calls",
    "diff",
    "fixture_reply",
    "fixture_tool",
    "listing",
    "placeholder_arguments",
]

FIXTURE_TYPES = (
    "malicious-tool-definition",
    "benign-tool-definition",
    "tool-call",
    "malicious-tool-result",
    "benign-tool-result",
    "tool-call-sequence",
    "definition-change",
)
_ANY_OBJECT = {"type": "object", "additionalProperties": True}
_PLACEHOLDER: dict[str, Any] = {"string": "x", "number": 0, "integer": 0, "boolean": False, "array": [], "object": {}}


class FixtureTool(Tool):
    """A tool that serves a fixture's definition and returns its recorded result.

    Every call it actually receives is kept in ``invocations`` and, when ``log_path`` is set (a tool
    in another process), appended to that JSONL file, so a harness can tell whether a defence
    stopped the call or rewrote its arguments.
    """

    reply: list[dict[str, Any]] | None = None
    invocations: list[dict[str, Any]] = Field(default_factory=list)
    log_path: str | None = None

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        self.invocations.append(dict(arguments))
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"name": self.name, "arguments": arguments}) + "\n")
        blocks = self.reply or [{"type": "text", "text": "ok"}]
        return ToolResult(content=[mt.TextContent(type="text", text=str(b.get("text", ""))) for b in blocks])


def fixture_tool(defn: Mapping[str, Any], reply: list[dict[str, Any]] | None = None, log_path: str | None = None) -> FixtureTool:
    schema = defn.get("inputSchema")
    return FixtureTool(
        name=str(defn["name"]),
        description=defn.get("description"),
        parameters=dict(schema) if isinstance(schema, Mapping) else dict(_ANY_OBJECT),
        reply=reply,
        invocations=[],
        log_path=log_path,
    )


def fixture_reply(fx: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    result = fx.get("result")
    return list(result.get("content") or []) if isinstance(result, Mapping) else None


def placeholder_arguments(schema: Any) -> dict[str, Any]:
    """Minimal schema-valid arguments: one placeholder per ``required`` property.

    The first ``enum`` value, else ``"x"`` for a string (or an untyped property), ``0`` for a
    number, ``false``, ``[]`` or ``{}``. A gate that enforces the schema then lets the call through
    on both arms, so it is scored on the result, not on a request the fixture never specified.
    """
    if not isinstance(schema, Mapping):
        return {}
    props = schema.get("properties")
    props = props if isinstance(props, Mapping) else {}
    out: dict[str, Any] = {}
    for name in schema.get("required") or ():
        prop = props.get(name)
        out[str(name)] = _placeholder(prop if isinstance(prop, Mapping) else {})
    return out


def _placeholder(prop: Mapping[str, Any]) -> Any:
    enum = prop.get("enum")
    if isinstance(enum, list) and enum:
        return copy.deepcopy(enum[0])
    kind = prop.get("type")
    if isinstance(kind, list):  # e.g. ["string", "null"]
        kind = next((k for k in kind if k != "null"), None)
    return copy.deepcopy(_PLACEHOLDER.get(kind, "x")) if isinstance(kind, str) else "x"


def calls(fx: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The ``tools/call`` requests a call or result fixture stands for, in order.

    A result fixture that gives no ``call`` is a call to its tool with placeholder arguments.
    """
    if fx.get("type") == "tool-call-sequence":
        return [{"name": str(c["name"]), "arguments": dict(c.get("arguments") or {})} for c in fx["calls"]]
    call = fx.get("call")
    if call:
        return [{"name": str(call["name"]), "arguments": dict(call.get("arguments") or {})}]
    return [{"name": str(fx["tool"]["name"]), "arguments": placeholder_arguments(fx["tool"].get("inputSchema"))}]


def listing(tools: Any) -> list[dict[str, Any]]:
    return [{"name": t.name, "description": t.description, "inputSchema": t.input_schema} for t in tools]


def call_outcome(r: Any, received: list[dict[str, Any]]) -> dict[str, Any]:
    texts = [getattr(b, "text", repr(b)) for b in r.content]
    return {"op": "tools/call", "error": bool(r.is_error), "content": texts, "invoked": len(received), "received": received}


def diff(b: Mapping[str, Any], g: Mapping[str, Any]) -> str:
    """What the defence changed between the unguarded step ``b`` and the guarded step ``g``."""
    if b["op"] == "tools/list":
        hidden = {t["name"] for t in b["tools"]} - {t["name"] for t in g["tools"]}
        return f"hid {', '.join(sorted(hidden))}" if hidden else "rewrote a tool definition"
    if g.get("error") and not b.get("error"):
        return "returned an error: " + " ".join(g["content"])
    if g.get("invoked", 0) < b.get("invoked", 0):
        return "call never reached the tool"
    if g.get("received") != b.get("received"):
        return "rewrote the call arguments"
    return "rewrote the result"
