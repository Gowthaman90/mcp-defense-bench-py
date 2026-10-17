"""Score Python MCP defences on the mcp-defense-bench corpus.

A Python port of the scorer in github.com/Gowthaman90/mcp-defense-bench (``bin/run.mjs``) that
reproduces the JS leaderboard's numbers byte for byte.

>>> from mcp_defense_bench import run
>>> run("mcp_defense_bench.adapters.null:NullBaseline")["summary"]["overall"]
'0% (0.0/37 CorpusRobustCoverage)'
"""

__version__ = "0.2.0"

# The bench release and commit this package scores against. The corpus is vendored from exactly
# this commit (scripts/vendor_bench.py) and checked against _bench/MANIFEST.json on load.
BENCH_VERSION = "0.9.0"
BENCH_COMMIT = "c4a4863ba677f42b78660dbfb61f7a058373c932"

from mcp_defense_bench.adapters import Adapter, AdapterMeta, Verdict, load_adapter  # noqa: E402
from mcp_defense_bench.bench import Bench, BenchError  # noqa: E402
from mcp_defense_bench.runner import arun, run  # noqa: E402

__all__ = [
    "BENCH_COMMIT",
    "BENCH_VERSION",
    "Adapter",
    "AdapterMeta",
    "Bench",
    "BenchError",
    "Verdict",
    "__version__",
    "arun",
    "load_adapter",
    "run",
]
