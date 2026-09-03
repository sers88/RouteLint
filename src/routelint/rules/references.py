"""Reference integrity: dangling proxy/group/provider refs, duplicates, unused."""

from __future__ import annotations

from ..loader import BUILTIN_POLICIES, Ctx, rule_target
from ..model import Finding, Severity
from . import Rule


class MissingGroupRefs(Rule):
    code = "REF"
    description = "proxy-groups reference names that do not exist"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        known = ctx.all_policy_names()
        for gi, group in enumerate(ctx.config.get("proxy-groups") or []):
            name = group.get("name", "?")
            for pi, entry in enumerate(group.get("proxies") or []):
                if entry not in known:
                    findings.append(
                        Finding(
                            code="REF001",
                            severity=Severity.ERROR,
                            title="group references missing proxy/group",
                            message=f"group {name!r} includes {entry!r}, but no such proxy or group exists",
                            path=f"proxy-groups[{gi}].proxies[{pi}]",
                            hint=f"available: proxies, groups, builtins {sorted(BUILTIN_POLICIES)}",
                        )
                    )
            for ui, pname in enumerate(group.get("use") or []):
                if pname not in ctx.proxy_providers:
                    findings.append(
                        Finding(
                            code="REF002",
                            severity=Severity.ERROR,
                            title="group uses missing proxy-provider",
                            message=f"group {name!r} uses provider {pname!r}, but it is not defined in proxy-providers",
                            path=f"proxy-groups[{gi}].use[{ui}]",
                        )
                    )
        return findings


class MissingRuleTargets(Rule):
    code = "RULE"
    description = "rules route to policies that do not exist"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        known = ctx.all_policy_names()
        for ri, rule in enumerate(ctx.config.get("rules") or []):
            if not isinstance(rule, str):
                continue
            parts = [p.strip() for p in rule.split(",")]
            if parts and parts[0].upper() == "RULE-SET":
                provider = parts[1] if len(parts) > 1 else ""
                if provider and provider not in ctx.rule_providers:
                    findings.append(
                        Finding(
                            code="RULE001",
                            severity=Severity.ERROR,
                            title="RULE-SET references missing rule-provider",
                            message=f"rule references provider {provider!r} not defined in rule-providers",
                            path=f"rules[{ri}]",
                        )
                    )
            target = rule_target(rule)
            if target and target not in known:
                findings.append(
                    Finding(
                        code="RULE002",
                        severity=Severity.ERROR,
                        title="rule routes to missing proxy/group",
                        message=f"rule {rule!r} targets {target!r}, which does not exist",
                        path=f"rules[{ri}]",
                    )
                )
        return findings


class DuplicateNames(Rule):
    code = "DUP"
    description = "duplicate proxy or group names"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        seen: dict[str, int] = {}
        for section in ("proxies", "proxy-groups"):
            for i, item in enumerate(ctx.config.get(section) or []):
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                if not isinstance(name, str):
                    continue
                if name in seen:
                    findings.append(
                        Finding(
                            code="DUP001",
                            severity=Severity.ERROR,
                            title="duplicate name",
                            message=f"{name!r} is defined more than once; references will resolve to one of them",
                            path=f"{section}[{i}].name",
                        )
                    )
                seen[name] = i
        return findings


#: names with special meaning in clash/mihomo that need no explicit references
SPECIAL_GROUP_NAMES = {"GLOBAL"}


class Unused(Rule):
    code = "UNUSED"
    description = "proxies/groups never referenced by any group or rule"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        referenced: set[str] = set(ctx.rule_targets)
        for members in ctx.groups.values():
            referenced.update(members)
        for proxy in sorted(ctx.proxies - referenced):
            findings.append(
                Finding(
                    code="UNUSED001",
                    severity=Severity.INFO,
                    title="proxy is never used",
                    message=f"proxy {proxy!r} is not referenced by any group or rule",
                )
            )
        for group in ctx.groups_order:
            if group in referenced or group in SPECIAL_GROUP_NAMES:
                continue
            findings.append(
                Finding(
                    code="UNUSED002",
                    severity=Severity.INFO,
                    title="group is never used",
                    message=f"group {group!r} is not referenced by any rule or other group",
                )
            )
        return findings


RULES: list[Rule] = [MissingGroupRefs(), MissingRuleTargets(), DuplicateNames(), Unused()]

