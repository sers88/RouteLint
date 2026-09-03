"""Semantic rules registry. Each rule is a tiny class with one check()."""

from __future__ import annotations

from ..loader import Ctx
from ..model import Finding


class Rule:
    code: str = ""
    description: str = ""

    def check(self, ctx: Ctx) -> list[Finding]:
        raise NotImplementedError


def _load_rules() -> list[Rule]:
    from . import cycles, dns, references, routing, security, shadowing

    rules: list[Rule] = []
    for module in (references, cycles, shadowing, security, dns, routing):
        rules.extend(module.RULES)
    return rules


REGISTRY: list[Rule] = _load_rules()

