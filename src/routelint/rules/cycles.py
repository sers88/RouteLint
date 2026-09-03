"""Group include cycles."""

from __future__ import annotations

from ..loader import Ctx
from ..model import Finding, Severity
from . import Rule

#: node states for cycle detection (3-colour DFS)
_WHITE, _GREY, _BLACK = 0, 1, 2


def find_cycles(groups: dict[str, list]) -> list[list[str]]:
    """Return every include cycle in `groups` as a path like [A, B, A]."""
    color: dict[str, int] = {name: _WHITE for name in groups}
    path: list[str] = []
    cycles: list[list[str]] = []

    def dfs(node: str) -> None:
        if node not in groups:
            return
        state = color.get(node, _WHITE)
        if state == _BLACK:
            return
        if state == _GREY:  # back-edge -> cycle
            cycles.append(path[path.index(node):] + [node])
            return
        color[node] = _GREY
        path.append(node)
        for member in groups[node]:
            dfs(member)
        path.pop()
        color[node] = _BLACK

    for name in groups:
        dfs(name)
    return cycles


class GroupCycles(Rule):
    code = "CYC"
    description = "proxy-groups include cycles"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        for cycle in find_cycles(ctx.groups):
            chain = " -> ".join(cycle)
            findings.append(
                Finding(
                    code="CYC001",
                    severity=Severity.ERROR,
                    title="proxy-group cycle",
                    message=f"circular group reference: {chain}",
                    hint="mihomo resolves groups lazily; cycles produce dead groups or startup errors",
                )
            )
        return findings


RULES: list[Rule] = [GroupCycles()]

