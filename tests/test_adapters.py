from __future__ import annotations

import sys
import types

import pytest

from mcp_defense_bench import AdapterMeta, Verdict, load_adapter, run
from mcp_defense_bench.adapters import meta_dict
from mcp_defense_bench.adapters.null import NullBaseline


@pytest.fixture
def guard_module():
    mod = types.ModuleType("fake_guard")

    class Guard:
        meta = AdapterMeta(tool="fake-guard", class_="runtime-proxy", reproducible=True)

        async def assess(self, input, testcase):
            return Verdict(detect=False)

    def assess(input, testcase):
        return {"detect": False, "enforce": False}

    mod.Guard = Guard
    mod.instance = Guard()
    mod.make = lambda: Guard()
    mod.assess = assess
    sys.modules["fake_guard"] = mod
    yield mod
    del sys.modules["fake_guard"]


@pytest.mark.parametrize("spec", ["fake_guard:Guard", "fake_guard:instance", "fake_guard:make"])
def test_load_adapter_forms(guard_module, spec):
    a = load_adapter(spec)
    assert meta_dict(a) == {"tool": "fake-guard", "class": "runtime-proxy", "reproducible": True}


def test_module_adapter_gets_a_name(guard_module):
    a = load_adapter("fake_guard")
    assert meta_dict(a)["tool"] == "fake_guard"
    assert meta_dict(load_adapter("fake_guard", name="custom"))["tool"] == "custom"


def test_bad_specs():
    with pytest.raises(ValueError, match="bad adapter spec"):
        load_adapter(":Guard")
    with pytest.raises(TypeError, match="no assess"):
        load_adapter("json:JSONDecoder")


def test_async_adapter_and_verdict_object_run(guard_module):
    s = run("fake_guard:Guard")["summary"]
    assert s["tool"] == "fake-guard" and s["casesRun"] == 78


def test_null_baseline_object_passes_through():
    a = NullBaseline()
    assert load_adapter(a) is a
