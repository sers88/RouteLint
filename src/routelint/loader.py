"""YAML loading and config indexing (Ctx) shared by all rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ConfigError(Exception):
    """Config could not be read or parsed."""


BUILTIN_POLICIES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"}


@dataclass
class Ctx:
    """Parsed config plus indexes used by semantic rules."""

    config: dict
    proxies: set[str] = field(default_factory=set)
    groups: dict[str, list] = field(default_factory=dict)  # name -> proxies list
    proxy_providers: set[str] = field(default_factory=set)
    rule_providers: set[str] = field(default_factory=set)
    sub_rules: dict[str, list] = field(default_factory=dict)  # name -> rules
    rule_targets: set[str] = field(default_factory=set)  # policies referenced by rules

    @property
    def groups_order(self) -> list[str]:
        return list(self.groups)

    def all_policy_names(self) -> set[str]:
        return self.proxies | set(self.groups) | BUILTIN_POLICIES


def load_config(path: str | Path) -> dict:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read {p}: {e}") from e
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {p}: {e}") from e
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(f"config root must be a mapping, got {type(data).__name__}")
    return data


def build_ctx(config: dict) -> Ctx:
    ctx = Ctx(config=config)
    for proxy in config.get("proxies") or []:
        if isinstance(proxy, dict) and isinstance(proxy.get("name"), str):
            ctx.proxies.add(proxy["name"])
    for group in config.get("proxy-groups") or []:
        if isinstance(group, dict) and isinstance(group.get("name"), str):
            ctx.groups[group["name"]] = group.get("proxies") or []
    for name in config.get("proxy-providers") or {}:
        ctx.proxy_providers.add(str(name))
    for name in config.get("rule-providers") or {}:
        ctx.rule_providers.add(str(name))
    ctx.sub_rules.update(_sub_rules(config))
    for rule in config.get("rules") or []:
        if isinstance(rule, str):
            target = rule_target(rule)
            if target:
                ctx.rule_targets.add(target)
    return ctx


def _sub_rules(config: dict) -> dict[str, list]:
    """Normalize `sub-rules` (map or list of single-key maps) to name -> rules."""
    raw = config.get("sub-rules") or {}
    result: dict[str, list] = {}
    if isinstance(raw, dict):
        for name, rules in raw.items():
            result[str(name)] = list(rules or [])
    elif isinstance(raw, list):
        for entry in raw:
            if isinstance(entry, dict):
                for name, rules in entry.items():
                    result[str(name)] = list(rules or [])
    return result


def rule_target(rule: str) -> str | None:
    """Extract the policy (target) part of a rule string, skipping params."""
    parts = [p.strip() for p in rule.split(",")]
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return None
    params = {"no-resolve", "src"}
    body = [p for p in parts[1:] if p.lower() not in params]
    return body[-1] if body else None

