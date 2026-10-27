"""The adapter contract: how any Python MCP defence plugs into the scorer.

It is the Python form of ``adapters/CONTRACT.md`` in the bench. An adapter is any object with

* ``meta`` — a mapping (or ``AdapterMeta``) with ``tool``, ``class``, ``reproducible`` and the
  optional ``fixtureTypes`` (the fixture types it is wired for) or ``unwiredFixtureTypes`` (the ones
  it is not wired for yet). Cases it is not wired for are not run: their vectors stay ``unknown``,
  never a miss, and they do not count toward the benign-corpus denominator;
* ``assess(input, testcase)`` — called twice per matched case (malicious ``fixture``, then
  ``benignControl``) and once per benign-corpus item. Returns a ``Verdict`` or a mapping with
  ``detect``, ``enforce`` and an optional ``signal``. It may be ``async``.

The integrity rule is the bench's: report only what the defence actually inspects at runtime,
never what its rules *could* catch if pointed at data it never sees.

``authorized-call`` fixtures (the authorization family, bench 0.10.0) state a deployment ``policy``,
an already-authenticated ``caller`` (``client``, ``user``, ``agent``) and one ``tools/call``
``request``. An adapter translates the policy into the defence's own policy language and maps the
caller to credentials the defence verifies natively; a rule it cannot express is a miss with the
reason in ``signal``, never approximated. ``enforce`` means the call was refused before any
upstream contact. This package scores such an adapter; it does not evaluate policies itself.
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeAlias, runtime_checkable

__all__ = ["Adapter", "AdapterMeta", "Verdict", "load_adapter", "meta_dict", "normalize_verdict"]


@dataclass(frozen=True)
class Verdict:
    """What a defence did with one input."""

    detect: bool
    enforce: bool = False
    signal: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"detect": self.detect, "enforce": self.enforce}
        if self.signal is not None:
            d["signal"] = self.signal
        return d


@dataclass(frozen=True)
class AdapterMeta:
    tool: str
    class_: str = "unknown"
    reproducible: bool = False
    fixture_types: tuple[str, ...] | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)
    unwired_fixture_types: tuple[str, ...] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"tool": self.tool, "class": self.class_, "reproducible": self.reproducible}
        if self.fixture_types is not None:
            d["fixtureTypes"] = list(self.fixture_types)
        if self.unwired_fixture_types is not None:
            d["unwiredFixtureTypes"] = list(self.unwired_fixture_types)
        d.update(self.extra)
        return d


VerdictLike: TypeAlias = "Verdict | Mapping[str, Any]"


@runtime_checkable
class Adapter(Protocol):
    meta: Mapping[str, Any] | AdapterMeta

    def assess(self, input: Mapping[str, Any], testcase: Mapping[str, Any]) -> VerdictLike | Awaitable[VerdictLike]: ...


def meta_dict(adapter: Any) -> dict[str, Any]:
    meta = getattr(adapter, "meta", None)
    if meta is None:
        return {}
    if isinstance(meta, AdapterMeta):
        return meta.to_dict()
    return dict(meta)


def normalize_verdict(v: Any) -> dict[str, Any]:
    """The verdict as the JSON object stored in results (a mapping is kept as returned)."""
    if isinstance(v, Verdict):
        return v.to_dict()
    if isinstance(v, Mapping):
        return dict(v)
    raise TypeError(f"assess() must return a Verdict or a mapping, got {type(v).__name__}")


async def call_assess(adapter: Any, input: Mapping[str, Any], testcase: Mapping[str, Any]) -> dict[str, Any]:
    out = adapter.assess(input, testcase)
    if inspect.isawaitable(out):
        out = await out
    return normalize_verdict(out)


def _is_fastmcp_middleware(obj: Any) -> bool:
    try:
        from fastmcp.server.middleware import Middleware
    except ImportError:
        return False
    return isinstance(obj, Middleware) or (inspect.isclass(obj) and issubclass(obj, Middleware))


def _import(mod_name: str, search_path: str | os.PathLike[str] | None) -> Any:
    try:
        return importlib.import_module(mod_name)
    except ModuleNotFoundError as e:
        top = mod_name.split(".")[0]
        where = os.fspath(search_path) if search_path is not None else None
        if e.name != top or where is None or where in sys.path:
            raise
        sys.path.insert(0, where)
        return importlib.import_module(mod_name)


def load_adapter(spec: str | Any, *, name: str | None = None, search_path: str | os.PathLike[str] | None = None) -> Any:
    """Resolve ``"package.module:Attr"`` (or ``"package.module"``) to an adapter object.

    ``Attr`` may be an adapter class (instantiated with no arguments), an adapter instance, a
    zero-argument factory function, a module with ``assess``/``meta`` (like a JS adapter.mjs), or
    a FastMCP ``Middleware`` class or instance (wrapped in ``FastMCPAdapter``). An object that is
    already an adapter is returned as is.

    If the module is not importable and ``search_path`` is given (the CLI passes the working
    directory, the pytest plugin the rootdir), that directory is put on ``sys.path`` and the import
    retried — so a guard module next to your code works without being installed.
    """
    if not isinstance(spec, str):
        obj: Any = spec
        label = name or getattr(spec, "__name__", type(spec).__name__)
    else:
        mod_name, _, attr = spec.partition(":")
        if not mod_name:
            raise ValueError(f"bad adapter spec {spec!r}; expected 'package.module:Attr'")
        obj = _import(mod_name, search_path)
        for part in filter(None, attr.split(".")):
            obj = getattr(obj, part)
        label = name or (attr.rsplit(".", 1)[-1] if attr else mod_name.rsplit(".", 1)[-1])

    if _is_fastmcp_middleware(obj):
        from mcp_defense_bench.adapters.fastmcp import FastMCPAdapter

        return FastMCPAdapter(obj, tool=name or label)
    if inspect.isclass(obj):
        obj = obj()
    elif callable(obj) and not hasattr(obj, "assess"):
        factory, obj = obj, obj()
        if _is_fastmcp_middleware(obj):
            from mcp_defense_bench.adapters.fastmcp import FastMCPAdapter

            return FastMCPAdapter(factory, tool=name or label)  # a fresh middleware per input
    if not callable(getattr(obj, "assess", None)):
        raise TypeError(f"{spec!r} resolved to {type(obj).__name__}, which has no assess(input, testcase)")
    if name or not meta_dict(obj).get("tool"):
        obj = _Named(obj, str(name or label))
    return obj


class _Named:
    """Wraps an adapter to give it a tool name without mutating it."""

    def __init__(self, inner: Any, tool: str) -> None:
        self._inner = inner
        self.meta = {**meta_dict(inner), "tool": tool}

    def assess(self, input: Mapping[str, Any], testcase: Mapping[str, Any]) -> Any:
        return self._inner.assess(input, testcase)
