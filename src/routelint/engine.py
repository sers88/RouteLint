"""Layer 3: semantic rule engine. Applies the rule registry to a Ctx."""

from __future__ import annotations

from .loader import Ctx
from .model import Finding, LayerResult
from .rules import REGISTRY


def run_semantic_layer(
    ctx: Ctx,
    disable: list[str] | None = None,
    only: list[str] | None = None,
) -> tuple[LayerResult, list[Finding]]:
    disable = [d.strip().upper() for d in disable or []]
    only = [o.strip().upper() for o in only or []]

    findings: list[Finding] = []
    applied = 0
    for rule in REGISTRY:
        if _excluded(rule.code, disable, only):
            continue
        applied += 1
        findings.extend(rule.check(ctx))

    status = "failed" if any(f.severity.value >= 30 for f in findings) else "ok"
    return LayerResult("semantic", status, f"{applied}/{len(REGISTRY)} rules applied"), findings


def _excluded(code: str, disable: list[str], only: list[str]) -> bool:
    if only and not any(code == o or code.startswith(o) for o in only):
        return True
    return any(code == d or code.startswith(d) for d in disable)

