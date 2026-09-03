"""Resolve finding paths like 'rules[3]' or 'dns.listen' to source lines."""

from __future__ import annotations

import re

_PART = re.compile(r"^([\w-]+)\[(\d+)\]$")


def resolve_line(config: dict, path: str) -> int | None:
    """Best-effort walk over a finding path; returns a 1-based line or None."""
    node = config
    line: int | None = None
    if not path:
        return line
    for part in path.split("."):
        m = _PART.match(part)
        if m:
            name, idx = m.group(1), int(m.group(2))
            if not isinstance(node, dict) or name not in node:
                return line
            line = _key_line(node, name)
            seq = node[name]
            if not isinstance(seq, list) or idx >= len(seq):
                return line
            item = seq[idx]
            line = getattr(item, "line", None) or getattr(seq, "line", None) or line
            node = item
        else:
            if not isinstance(node, dict) or part not in node:
                return line
            line = _key_line(node, part)
            node = node[part]
    return line


def _key_line(node: dict, key: str) -> int | None:
    key_lines = getattr(node, "key_lines", None) or {}
    return key_lines.get(key) or getattr(node, "line", None)


def snippet_for(lines: list[str], line: int | None) -> str:
    if line is None or line < 1 or line > len(lines):
        return ""
    return lines[line - 1].strip()
