"""Security of the management plane: external-controller, secret, external-ui."""

from __future__ import annotations

from ..loader import Ctx
from ..model import Finding, Severity
from . import Rule

WILDCARD_HOSTS = {"0.0.0.0", "::", "", "*"}


def _controller_host(value: str) -> str:
    # formats: "0.0.0.0:9090", ":9090", "127.0.0.1:9090", "localhost:9090"
    host = value.rsplit(":", 1)[0] if ":" in value else value
    return host.strip("[]")


class ControllerExposure(Rule):
    code = "SEC"
    description = "external-controller exposure and authentication"

    def check(self, ctx: Ctx) -> list[Finding]:
        ec = ctx.config.get("external-controller")
        if not ec or not isinstance(ec, str):
            return []
        host = _controller_host(ec)
        secret = ctx.config.get("secret")
        has_secret = isinstance(secret, str) and secret != ""
        public = host in WILDCARD_HOSTS
        if public and not has_secret:
            return [
                Finding(
                    code="SEC001",
                    severity=Severity.WARN,
                    title="external-controller exposed without secret",
                    message=f"external-controller {ec!r} listens on all interfaces with no `secret` set",
                    path="external-controller",
                    hint="anyone on the network can read traffic and reconfigure the proxy; set a secret or bind to 127.0.0.1",
                )
            ]
        if public:
            return [
                Finding(
                    code="SEC002",
                    severity=Severity.WARN,
                    title="external-controller listens on all interfaces",
                    message=f"external-controller {ec!r} is reachable from the network (secret is set)",
                    path="external-controller",
                    hint="prefer binding to 127.0.0.1 unless a dashboard on another host is required",
                )
            ]
        if not has_secret:
            return [
                Finding(
                    code="SEC003",
                    severity=Severity.INFO,
                    title="external-controller without secret",
                    message=f"external-controller {ec!r} is local-only, but setting a `secret` is still recommended",
                    path="secret",
                )
            ]
        return []


class ExternalUi(Rule):
    code = "UI"
    description = "external-ui / external-ui-url consistency"

    def check(self, ctx: Ctx) -> list[Finding]:
        ui = ctx.config.get("external-ui")
        url = ctx.config.get("external-ui-url")
        if ui and not url:
            return [
                Finding(
                    code="UI001",
                    severity=Severity.INFO,
                    title="external-ui without external-ui-url",
                    message=f"external-ui is {ui!r} but external-ui-url is not set, so the dashboard will not auto-download",
                    path="external-ui-url",
                )
            ]
        if url and not ui:
            return [
                Finding(
                    code="UI002",
                    severity=Severity.INFO,
                    title="external-ui-url without external-ui",
                    message="external-ui-url is set but external-ui is not; the URL is ignored",
                    path="external-ui",
                )
            ]
        return []


RULES: list[Rule] = [ControllerExposure(), ExternalUi()]

