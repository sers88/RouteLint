"""Rule shadowing: unreachable rules, duplicates, missing final MATCH."""

from __future__ import annotations

from ..loader import Ctx
from ..model import Finding, Severity
from . import Rule


def _parts(rule: str) -> list[str]:
    return [p.strip() for p in rule.split(",") if p.strip()]


class MatchNotLast(Rule):
    code = "SHD"
    description = "MATCH is not the last rule / rules after MATCH are unreachable"

    def check(self, ctx: Ctx) -> list[Finding]:
        rules = [r for r in ctx.config.get("rules") or [] if isinstance(r, str)]
        matches = [i for i, r in enumerate(rules) if _parts(r)[0].upper() == "MATCH"]
        findings = []
        for i in matches:
            if i != len(rules) - 1:
                findings.append(
                    Finding(
                        code="SHD001",
                        severity=Severity.ERROR,
                        title="unreachable rules after MATCH",
                        message=f"rules[{i}] is MATCH, but {len(rules) - i - 1} rule(s) follow it and can never match",
                        path=f"rules[{i}]",
                        hint="MOVE MATCH to the end, or narrow it",
                    )
                )
        if not matches and rules:
            findings.append(
                Finding(
                    code="SHD002",
                    severity=Severity.INFO,
                    title="no final MATCH rule",
                    message="rules have no MATCH fallback; unmatched traffic goes DIRECT by default",
                    path="rules",
                    hint="add an explicit `MATCH,<policy>` to make the default intent visible",
                )
            )
        return findings


class DuplicateRules(Rule):
    code = "DUPRULE"
    description = "identical duplicate rules"

    def check(self, ctx: Ctx) -> list[Finding]:
        rules = [r for r in ctx.config.get("rules") or [] if isinstance(r, str)]
        findings = []
        seen: dict[str, int] = {}
        for i, rule in enumerate(rules):
            if rule in seen:
                findings.append(
                    Finding(
                        code="DUPRULE001",
                        severity=Severity.WARN,
                        title="duplicate rule",
                        message=f"rules[{i}] duplicates rules[{seen[rule]}]",
                        path=f"rules[{i}]",
                    )
                )
            else:
                seen[rule] = i
        return findings


RULES: list[Rule] = [MatchNotLast(), DuplicateRules()]

