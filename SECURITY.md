# Security policy

`mcp-defense-bench` measures MCP defences; it is not itself a defence. Its corpus contains
attack payloads as inert JSON data, and nothing in it is executed.

Adapters you score are ordinary Python code imported from the spec you pass
(`module:Attr`), with your privileges. Only score code you trust.

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/Gowthaman90/mcp-defense-bench-py/security/advisories/new)
rather than in a public issue. You can expect an acknowledgement within 7 days.

Issues with the corpus or the scoring rules themselves (for example, a fixture that is
mislabelled) belong in the benchmark repository:
https://github.com/Gowthaman90/mcp-defense-bench/issues.
