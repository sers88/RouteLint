"""Inbound exposure: LAN-reachable proxy without authentication."""

from __future__ import annotations

from ..loader import Ctx
from ..model import Finding, Severity
from . import Rule

_WILDCARD_BIND = {"*", "0.0.0.0", ""}


class OpenInbound(Rule):
    code = "INB"
    description = "proxy open to the LAN without authentication"

    def check(self, ctx: Ctx) -> list[Finding]:
        if not ctx.config.get("allow-lan"):
            return []
        auth = ctx.config.get("authentication") or []
        if auth:
            return []
        skip = ctx.config.get("skip-auth-prefixes") or []
        bind = str(ctx.config.get("bind-address", ""))
        wildcard = bind in _WILDCARD_BIND

        detail = "allow-lan is true"
        if wildcard:
            detail += f" and bind-address {bind!r} binds all interfaces"
        detail += ", but `authentication` is empty"
        return [
            Finding(
                code="INB001",
                severity=Severity.INFO if skip else Severity.WARN,
                title="proxy reachable from the LAN without authentication",
                message=detail,
                path="authentication",
                hint=(
                    "anyone on the LAN can use the proxy and the API; add `authentication` users, "
                    "or restrict `skip-auth-prefixes` to trusted subnets"
                    if not skip
                    else "skip-auth-prefixes is set; make sure it only covers trusted subnets"
                ),
            )
        ]


RULES: list[Rule] = [OpenInbound()]
