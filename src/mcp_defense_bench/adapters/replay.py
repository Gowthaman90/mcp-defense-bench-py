"""Replay adapter: answers with the verdicts recorded in a results file.

Feeding a JS run's ``results/<tool>.json`` (or ``results/benign/<tool>.json``) back through the
Python scorer must reproduce that file byte for byte (apart from ``measuredAt``). That is the
parity check between the two scorers, and it needs no JS tool installed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any


class ReplayAdapter:
    def __init__(self, results: str | Path | Mapping[str, Any], *, tool_class: str = "replay") -> None:
        data: Mapping[str, Any] = json.loads(Path(results).read_text("utf8")) if isinstance(results, (str, Path)) else results
        summary = data["summary"]
        self.corpus: str = summary["corpus"]
        self.meta: Mapping[str, Any] = {"tool": summary["tool"], "class": tool_class, "reproducible": True}
        self._matched: dict[str, tuple[Any, Any]] = {}
        self._benign: dict[str, Any] = {}
        if self.corpus == "benign":
            self._benign = {it["id"]: it["verdict"] for it in data["items"]}
        else:
            self._matched = {c["id"]: (c["mal"], c["benign"]) for c in data["cases"]}

    def assess(self, input: Mapping[str, Any], testcase: Mapping[str, Any]) -> Any:
        case_id = testcase["id"]
        if self.corpus == "benign":
            if case_id not in self._benign:
                raise KeyError(f"no recorded verdict for {case_id}")
            return self._benign[case_id]
        if case_id not in self._matched:
            raise KeyError(f"no recorded verdict for {case_id}")
        mal, benign = self._matched[case_id]
        return mal if input is testcase["fixture"] else benign
