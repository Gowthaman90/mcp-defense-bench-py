"""Null baseline: a defender with zero protection, the scientific control.

It catches nothing, which confirms the fixtures fire and anchors the 0% end of the scale.
Same verdict as the bench's ``adapters/null-baseline/adapter.mjs``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from mcp_defense_bench.adapters import Verdict


class NullBaseline:
    meta: Mapping[str, Any] = {"tool": "null-baseline", "class": "none", "reproducible": True}

    def assess(self, input: Mapping[str, Any], testcase: Mapping[str, Any]) -> Verdict:
        return Verdict(detect=False, enforce=False, signal="no protection")
