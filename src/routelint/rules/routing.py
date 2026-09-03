"""Routing anti-patterns: common real-world ordering / intent mistakes."""

from __future__ import annotations

from ..loader import Ctx
from ..model import Finding, Severity
from . import Rule


def _parts(rule: str) -> list[str]:
    return [p.strip() for p in rule.split(",") if p.strip()]


class BlockingFinal(Rule):
    code = "RT"
    description = "MATCH that blocks or misroutes everything"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        for i, rule in enumerate(ctx.config.get("rules") or []):
            if not isinstance(rule, str):
                continue
            parts = _parts(rule)
            if parts[0].upper() != "MATCH":
                continue
            target = parts[-1]
            if target in ("REJECT", "REJECT-DROP"):
                findings.append(
                    Finding(
                        code="RT001",
                        severity=Severity.ERROR,
                        title="MATCH rejects all traffic",
                        message=f"rules[{i}] is MATCH -> {target}: every unmatched connection is blocked",
                        path=f"rules[{i}]",
                        hint="usually a typo; route to a proxy group or DIRECT instead",
                    )
                )
        return findings


class GeoipCnViaProxy(Rule):
    code = "RTGEO"
    description = "GEOIP,CN routed through proxy (typical RU/EU setup mistake)"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        for i, rule in enumerate(ctx.config.get("rules") or []):
            if not isinstance(rule, str):
                continue
            parts = _parts(rule)
            if len(parts) >= 3 and parts[0].upper() == "GEOIP" and parts[1].upper() == "CN":
                target = parts[-1]
                if target not in ("DIRECT",):
                    findings.append(
                        Finding(
                            code="RTGEO001",
                            severity=Severity.WARN,
                            title="GEOIP,CN routed through proxy",
                            message=(
                                f"rules[{i}] sends CN hosts to {target!r}; "
                                "in RU direct / rest proxy setups this slows down CN resources"
                            ),
                            path=f"rules[{i}]",
                            hint="if this is a RU direct config, route GEOIP,CN (and GEOSITE,CN) to DIRECT",
                        )
                    )
        return findings


class BroadBeforeSpecific(Rule):
    code = "RTORD"
    description = "IP/port rules placed before more specific domain rules"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        rules = [r for r in ctx.config.get("rules") or [] if isinstance(r, str)]
        specific_types = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "GEOSITE"}
        broad_types = {"IP-CIDR", "IP-CIDR6", "GEOIP", "DST-PORT", "SRC-PORT", "SRC-IP-CIDR"}
        for i, rule in enumerate(rules):
            p = _parts(rule)
            if not p or p[0].upper() not in broad_types:
                continue
            for j in range(i + 1, len(rules)):
                q = _parts(rules[j])
                if not q:
                    continue
                if q[0].upper() in specific_types and _target(p) != _target(q):
                    findings.append(
                        Finding(
                            code="RTORD001",
                            severity=Severity.WARN,
                            title="broad rule shadows later domain rules",
                            message=(
                                f"rules[{i}] ({p[0].upper()}) matches by IP/port before rules[{j}] ({q[0].upper()}); "
                                f"domains resolving into that range will take the earlier rule"
                            ),
                            path=f"rules[{j}]",
                            hint="put DOMAIN/GEOSITE rules before IP-CIDR/GEOIP rules",
                        )
                    )
                    break
        return findings


def _target(parts: list[str]) -> str:
    params = {"no-resolve", "src"}
    body = [p for p in parts[1:] if p.lower() not in params]
    return body[-1] if body else ""


RULES: list[Rule] = [BlockingFinal(), GeoipCnViaProxy(), BroadBeforeSpecific()]

