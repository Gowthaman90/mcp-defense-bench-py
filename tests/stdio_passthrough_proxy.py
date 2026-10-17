"""A trivial stdio MCP proxy for the stdio adapter's tests: ``proxy.py [--warn|--refuse] -- server...``.

It starts the server command and relays both pipes line by line, untouched. ``--warn`` also
prints a WARNING to stderr for every ``tools/call`` it relays; ``--refuse`` answers every
``tools/call`` itself with a JSON-RPC error instead of forwarding it.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading

flags, server = sys.argv[1 : sys.argv.index("--")], sys.argv[sys.argv.index("--") + 1 :]
child = subprocess.Popen(server, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
out_lock = threading.Lock()


def send(line: bytes) -> None:
    with out_lock:
        sys.stdout.buffer.write(line)
        sys.stdout.buffer.flush()


def from_server() -> None:
    assert child.stdout is not None
    for line in iter(child.stdout.readline, b""):
        send(line)


threading.Thread(target=from_server, daemon=True).start()
assert child.stdin is not None
for line in iter(sys.stdin.buffer.readline, b""):
    try:
        msg = json.loads(line)
    except ValueError:
        msg = None
    if isinstance(msg, dict) and msg.get("method") == "tools/call":
        if "--warn" in flags:
            print(f"[proxy] WARNING: tools/call {msg['params']['name']}", file=sys.stderr, flush=True)
        if "--refuse" in flags:
            err = {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32000, "message": "refused by proxy"}}
            send((json.dumps(err) + "\n").encode())
            continue
    child.stdin.write(line)
    child.stdin.flush()
child.stdin.close()
sys.exit(child.wait())
