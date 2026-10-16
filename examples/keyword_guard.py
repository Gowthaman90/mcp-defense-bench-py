"""A deliberately simple FastMCP guard, to show the scorer working on a real middleware.

It is NOT a recommended defence: keyword rules are easy to evade, and the benchmark's evasion
fixtures and benign hard negatives are there to show exactly that.

    mcp-defense-bench run examples.keyword_guard:KeywordGuard --corpus all
"""

from __future__ import annotations

import re
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

INJECTION = re.compile(r"<important>|ignore (all|previous) instructions|do not (tell|mention)|system prompt", re.I)
SHELL = re.compile(r"[;&|`]|\$\(")
EXFIL = re.compile(r"https?://\S+", re.I)


class KeywordGuard(Middleware):
    async def on_list_tools(self, context: Any, call_next: Any) -> Any:
        tools = await call_next(context)
        return [t for t in tools if not INJECTION.search(t.description or "")]

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        args = context.message.arguments or {}
        if any(isinstance(v, str) and SHELL.search(v) for v in args.values()):
            raise ToolError("blocked: shell metacharacters in an argument")
        result = await call_next(context)
        text = " ".join(getattr(b, "text", "") for b in result.content)
        if INJECTION.search(text) or (EXFIL.search(text) and re.search(r"token|password|send|post", text, re.I)):
            raise ToolError("blocked: tool result looks like an injection")
        return result
