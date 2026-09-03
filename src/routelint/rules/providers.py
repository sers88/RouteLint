"""Proxy-provider hygiene."""

from __future__ import annotations

from ..loader import Ctx
from ..model import Finding, Severity
from . import Rule


class ProviderHealthCheck(Rule):
    code = "PROV"
    description = "proxy-providers without health-check"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        for name, provider in (ctx.config.get("proxy-providers") or {}).items():
            if not isinstance(provider, dict):
                continue
            health = provider.get("health-check") or {}
            if health.get("enable"):
                continue
            findings.append(
                Finding(
                    code="PROV001",
                    severity=Severity.INFO,
                    title="proxy-provider without health-check",
                    message=f"provider {name!r} has no enabled health-check, so dead nodes are never detected",
                    path=f"proxy-providers.{name}.health-check",
                    hint="add health-check.enable: true (url + interval), or a url-test/fallback group over the provider",
                )
            )
        return findings


class ProviderHttpUrl(Rule):
    code = "PROVU"
    description = "http proxy-providers without url"

    def check(self, ctx: Ctx) -> list[Finding]:
        findings = []
        for name, provider in (ctx.config.get("proxy-providers") or {}).items():
            if not isinstance(provider, dict):
                continue
            if provider.get("type", "http") == "http" and not provider.get("url"):
                findings.append(
                    Finding(
                        code="PROVU001",
                        severity=Severity.ERROR,
                        title="http proxy-provider without url",
                        message=f"provider {name!r} has type http but no `url` to download from",
                        path=f"proxy-providers.{name}.url",
                    )
                )
        return findings


RULES: list[Rule] = [ProviderHealthCheck(), ProviderHttpUrl()]
