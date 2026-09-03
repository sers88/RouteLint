"""Group include cycles."""

from __future__ import annotations

from ..loader import Ctx
from ..model import Finding, Severity
from . import Rule


def find_cycle(groups: dict[str, list], start: str) -> list[str] | None:
    path: list[str] = []
    seen: set[str] = set()

    def dfs(node: str) -> list[str] | None:
        if node in seen:
            return path[path.index(node):] + [node]
        if node not in groups:
            return None
        seen.add(node)
        path.append(node)
        for member in groups[node]:
            cycle = dfs(member)
            if cycle:
                return cycle
        path.pop()
        return None

    return dfs(start)


class GroupCycles(Rule):
    code = "CYC"
    description = "proxy-groups include cycles"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        reported: frozenset[str] = frozenset()
        for name in ctx.groups_order:
            if name in reported:
                continue
            cycle = find_cycle(ctx.groups, name)
            if cycle:
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
                reported = frozenset(set(reported) | set(cycle[:-1]))
        return findings


RULES: list[Rule] = [GroupCycles()]

