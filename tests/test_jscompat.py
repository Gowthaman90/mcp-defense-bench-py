from __future__ import annotations

import json
import random
import shutil
import struct
import subprocess

import pytest

from mcp_defense_bench.jscompat import UNDEFINED, fold_add, js_number, js_truthy, stringify, to_fixed


@pytest.mark.parametrize(
    ("x", "digits", "want"),
    [
        (0.25, 1, "0.3"),  # Python's f"{0.25:.1f}" is "0.2"
        (0.125, 2, "0.13"),
        (2.5, 0, "3"),
        (-2.5, 0, "-3"),
        (1.005, 2, "1.00"),  # 1.005 is really 1.00499999…
        (-0.0, 2, "0.00"),
        (-0.0001, 2, "-0.00"),
        (24.5834, 1, "24.6"),
        (1e21, 2, "1e+21"),
        (float("nan"), 2, "NaN"),
    ],
)
def test_to_fixed(x, digits, want):
    assert to_fixed(x, digits) == want


@pytest.mark.parametrize(
    ("x", "want"),
    [
        (1.0, "1"),
        (0, "0"),
        (-0.0, "0"),
        (0.0415, "0.0415"),
        (1e-7, "1e-7"),
        (1.5e-6, "0.0000015"),
        (1e21, "1e+21"),
        (123456789012345680000.0, "123456789012345680000"),
        (5e-324, "5e-324"),
        (0.1 + 0.2, "0.30000000000000004"),
        (2**60, "1152921504606847000"),
    ],
)
def test_js_number(x, want):
    assert js_number(x) == want


def test_fold_add_is_a_plain_left_fold():
    vals = [0.1] * 10
    total = 0.0
    for v in vals:
        total += v
    assert fold_add(vals) == total == 0.9999999999999999  # sum() is 1.0 on Python >= 3.12


def test_js_truthy():
    assert js_truthy([]) and js_truthy({}) and js_truthy("x") and js_truthy(1)
    assert not any(js_truthy(v) for v in (None, False, 0, 0.0, "", float("nan")))


def test_stringify_layout_and_escapes():
    doc = {"b": 1.0, "a": [], "o": {}, "s": 'q"\\\n\t\x01é😀\ud800', "u": UNDEFINED, "2": True, "1": None, "n": [UNDEFINED, 0.5]}
    assert stringify(doc) == (
        '{\n  "1": null,\n  "2": true,\n  "b": 1,\n  "a": [],\n  "o": {},\n'
        '  "s": "q\\"\\\\\\n\\t\\u0001é😀\\ud800",\n  "n": [\n    null,\n    0.5\n  ]\n}'
    )


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_numbers_match_node_on_random_doubles():
    rnd = random.Random(20261016)
    vals = [struct.unpack("d", struct.pack("Q", rnd.getrandbits(64)))[0] for _ in range(1500)]
    vals += [rnd.randint(0, 400) / rnd.randint(1, 400) for _ in range(1500)]
    vals = [v for v in vals if v == v and abs(v) != float("inf")]
    js = (
        "const v=JSON.parse(require('fs').readFileSync(0,'utf8')).map(Number);"
        "console.log(JSON.stringify(v.map(x=>[String(x),x.toFixed(0),x.toFixed(1),x.toFixed(2),x.toFixed(4)])))"
    )
    out = subprocess.run(
        ["node", "-e", js], input=json.dumps([repr(v) for v in vals]), capture_output=True, text=True, check=True
    )
    for v, want in zip(vals, json.loads(out.stdout), strict=True):
        assert [js_number(v), *(to_fixed(v, d) for d in (0, 1, 2, 4))] == want, v
