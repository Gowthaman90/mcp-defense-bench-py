"""JavaScript-exact arithmetic and serialisation, so results match ``bin/run.mjs`` byte for byte.

Three places where a naive Python port silently drifts from the JS scorer:

* ``Number.prototype.toFixed`` rounds an exact tie *up* (away from zero); Python's ``format`` and
  ``round`` round half to even. ``(0.25).toFixed(1)`` is ``"0.3"``; ``f"{0.25:.1f}"`` is ``"0.2"``.
* Python 3.12+ ``sum()`` over floats uses compensated summation; JS ``reduce((a, b) => a + b, 0)``
  is a plain left fold. ``fold_add`` is the left fold.
* ``JSON.stringify`` prints ``1`` for ``1.0``, switches to exponent form at different magnitudes
  than ``repr``, orders integer-like keys first, and never escapes non-ASCII text.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Mapping
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

__all__ = ["UNDEFINED", "fold_add", "js_number", "js_truthy", "stringify", "to_fixed", "to_fixed_number"]


def js_truthy(v: object) -> bool:
    """JS ``!!v``: unlike Python, empty lists and dicts are truthy; NaN is falsy."""
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)):
        return v == v and v != 0
    if isinstance(v, str):
        return v != ""
    return True


def fold_add(values: Iterable[float]) -> float:
    """``values.reduce((a, b) => a + b, 0)`` — a left fold, with no compensation."""
    total: float = 0
    for v in values:
        total = total + v
    return total


def to_fixed(x: float, digits: int) -> str:
    """``Number.prototype.toFixed(digits)`` for ``0 <= digits <= 100``."""
    if math.isnan(x):
        return "NaN"
    if math.isinf(x):
        return "Infinity" if x > 0 else "-Infinity"
    if abs(x) >= 1e21:
        return js_number(x)
    # Decimal(x) is the exact binary value, so only true ties are rounded away from zero —
    # what the spec's "if there are two such n, pick the larger n" means for |x|.
    q = Decimal(x).quantize(Decimal(1).scaleb(-digits), rounding=ROUND_HALF_UP)
    s = f"{q:f}"
    # -0 is not < 0, so (-0).toFixed(2) is "0.00"; but (-0.0001).toFixed(2) is "-0.00".
    return s[1:] if x == 0 and s.startswith("-") else s


def to_fixed_number(x: float, digits: int) -> float:
    """``Number(x.toFixed(digits))`` — the rounding ``bin/run.mjs`` stores in its JSON."""
    return float(to_fixed(x, digits))


def js_number(x: float | int) -> str:
    """``Number.prototype.toString()`` / how ``JSON.stringify`` prints a finite number."""
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int):
        if abs(x) <= 2**53:
            return str(x)
        x = float(x)  # JS numbers are doubles; a huge int prints as its nearest double
    if math.isnan(x):
        return "NaN"
    if math.isinf(x):
        return "Infinity" if x > 0 else "-Infinity"
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    # repr() gives the shortest round-tripping digits, the same digits ECMAScript chooses;
    # only the layout differs, so re-lay them out per Number::toString.
    # Value = 0.<digits> * 10**n, with no leading or trailing zeros in digits (spec's k and n).
    mantissa, _, exp = repr(abs(x)).partition("e")
    whole, _, frac = mantissa.partition(".")
    raw = whole + frac
    digits = raw.lstrip("0")
    n = len(whole) + int(exp or 0) - (len(raw) - len(digits))
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        body = (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + body


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
_NEEDS_ESCAPE = re.compile(r'["\\\x00-\x1f\ud800-\udfff]')
_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")


def _quote(s: str) -> str:
    def esc(m: re.Match[str]) -> str:
        c = m.group(0)
        return _ESCAPES.get(c) or f"\\u{ord(c):04x}"

    # Python strings hold surrogates individually, so a valid pair (from a JSON 😀 escape
    # decoded by json.loads into one code point) never reaches here as two; any surrogate seen is lone.
    return '"' + _NEEDS_ESCAPE.sub(esc, s) + '"'


def _ordered_keys(obj: Mapping[str, Any]) -> list[str]:
    """Own-property order: array-index keys ascending, then string keys in insertion order."""
    idx = [k for k in obj if _ARRAY_INDEX.fullmatch(k) and int(k) < 2**32 - 1]
    if not idx:
        return list(obj)
    idx_set = set(idx)
    return sorted(idx, key=int) + [k for k in obj if k not in idx_set]


def stringify(value: Any, indent: int = 2) -> str:
    """``JSON.stringify(value, null, indent)`` for JSON-shaped Python data.

    Mapping entries whose value is the ``UNDEFINED`` sentinel are omitted, as JS omits
    ``undefined`` properties.
    """
    pad = " " * indent
    out: list[str] = []

    def emit(v: Any, depth: int) -> None:
        if v is None:
            out.append("null")
        elif v is True:
            out.append("true")
        elif v is False:
            out.append("false")
        elif isinstance(v, (int, float)):
            out.append("null" if isinstance(v, float) and not math.isfinite(v) else js_number(v))
        elif isinstance(v, str):
            out.append(_quote(v))
        elif isinstance(v, Mapping):
            keys = [k for k in _ordered_keys(v) if v[k] is not UNDEFINED]
            if not keys:
                out.append("{}")
                return
            inner = "\n" + pad * (depth + 1)
            out.append("{")
            for i, k in enumerate(keys):
                out.append(("," if i else "") + inner + _quote(str(k)) + ": ")
                emit(v[k], depth + 1)
            out.append("\n" + pad * depth + "}")
        elif isinstance(v, (list, tuple)):
            if not v:
                out.append("[]")
                return
            inner = "\n" + pad * (depth + 1)
            out.append("[")
            for i, item in enumerate(v):
                out.append(("," if i else "") + inner)
                emit(None if item is UNDEFINED else item, depth + 1)  # JS prints undefined in an array as null
            out.append("\n" + pad * depth + "]")
        else:
            raise TypeError(f"not JSON-serialisable: {type(v).__name__}")

    emit(value, 0)
    return "".join(out)


class _Undefined:
    """Marks a JS ``undefined`` property: omitted by ``stringify``."""

    _instance: _Undefined | None = None

    def __new__(cls) -> _Undefined:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNDEFINED"


UNDEFINED: Any = _Undefined()
