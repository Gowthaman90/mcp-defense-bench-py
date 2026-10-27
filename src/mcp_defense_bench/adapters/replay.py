"""Replay adapter: answers with the verdicts recorded in a results file.

Feeding a JS run's ``results/<tool>.json`` (or ``results/benign/<tool>.json``) back through the
Python scorer must reproduce that file byte for byte (apart from ``measuredAt``). That is the
parity check between the two scorers, and it needs no JS tool installed.

A recorded tool that was wired for some fixture types only (its JS ``meta.fixtureTypes`` or
``meta.unwiredFixtureTypes``, e.g. agentgateway and ToolHive on ``authorized-call`` only) has no
verdicts for the other cases. Give the replay the same declaration (``fixture_types=`` /
``unwired_fixture_types=``), or pass ``cases=`` to infer ``fixtureTypes`` from the fixture types
the record actually holds, so the scorer skips those cases exactly as ``bin/run.mjs`` did.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any


class ReplayAdapter:
    def __init__(
        self,
        results: str | Path | Mapping[str, Any],
        *,
        tool_class: str = "replay",
        fixture_types: Iterable[str] | None = None,
        unwired_fixture_types: Iterable[str] | None = None,
        cases: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        data: Mapping[str, Any] = json.loads(Path(results).read_text("utf8")) if isinstance(results, (str, Path)) else results
        summary = data["summary"]
        self.corpus: str = summary["corpus"]
        self._matched: dict[str, tuple[Any, Any]] = {}
        self._benign: dict[str, Any] = {}
        if self.corpus == "benign":
            self._benign = {it["id"]: it["verdict"] for it in data["items"]}
        else:
            self._matched = {c["id"]: (c["mal"], c["benign"]) for c in data["cases"]}
        meta: dict[str, Any] = {"tool": summary["tool"], "class": tool_class, "reproducible": True}
        if fixture_types is None and cases is not None:
            fixture_types = self.recorded_fixture_types(cases)
        if fixture_types is not None:
            meta["fixtureTypes"] = list(fixture_types)
        if unwired_fixture_types is not None:
            meta["unwiredFixtureTypes"] = list(unwired_fixture_types)
        self.meta: Mapping[str, Any] = meta

    def recorded_fixture_types(self, cases: Sequence[Mapping[str, Any]]) -> list[str]:
        """The fixture types of ``cases`` that this record has verdicts for, in first-seen order."""
        recorded = self._benign if self.corpus == "benign" else self._matched
        out: list[str] = []
        for tc in cases:
            ftype = (tc.get("fixture") or {}).get("type")
            if tc.get("id") in recorded and isinstance(ftype, str) and ftype not in out:
                out.append(ftype)
        return out

    def assess(self, input: Mapping[str, Any], testcase: Mapping[str, Any]) -> Any:
        case_id = testcase["id"]
        recorded = self._benign if self.corpus == "benign" else self._matched
        if case_id not in recorded:
            ftype = (testcase.get("fixture") or {}).get("type")
            raise KeyError(
                f"no recorded verdict for {case_id} (fixture type {ftype!r}); if the recorded tool was not wired "
                "for it, pass fixture_types=, unwired_fixture_types= or cases="
            )
        if self.corpus == "benign":
            return self._benign[case_id]
        mal, benign = self._matched[case_id]
        return mal if input is testcase["fixture"] else benign
