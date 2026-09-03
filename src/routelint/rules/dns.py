"""Suspicious DNS settings and leak risks."""

from __future__ import annotations

from ..loader import Ctx
from ..model import Finding, Severity
from . import Rule


class TunWithoutDns(Rule):
    code = "DNS"
    description = "TUN enabled without DNS section (system DNS leak)"

    def check(self, ctx: Ctx) -> list[Finding]:
        tun = ctx.config.get("tun") or {}
        dns = ctx.config.get("dns") or {}
        if tun.get("enable") and not dns.get("enable"):
            return [
                Finding(
                    code="DNS001",
                    severity=Severity.HIGH,
                    title="TUN enabled but dns.enable is off",
                    message="with TUN up and the internal DNS server disabled, the system resolver queries outside the tunnel",
                    path="dns.enable",
                    hint="set dns.enable: true and add fake-ip-filter / hijacked DNS, or DNS traffic leaks",
                )
            ]
        return []


class DnsListenPublic(Rule):
    code = "DNSLISTEN"
    description = "dns.listen exposed to the network"

    def check(self, ctx: Ctx) -> list[Finding]:
        dns = ctx.config.get("dns") or {}
        listen = dns.get("listen")
        if not listen or not isinstance(listen, str):
            return []
        host = listen.rsplit(":", 1)[0].strip("[]") if ":" in listen else ""
        if host in ("0.0.0.0", "::", ""):
            return [
                Finding(
                    code="DNSLISTEN001",
                    severity=Severity.WARN,
                    title="DNS server listens on all interfaces",
                    message=f"dns.listen {listen!r} is an open resolver for the local network",
                    path="dns.listen",
                    hint="bind to 127.0.0.0:1053 unless you intentionally share the resolver",
                )
            ]
        return []


class DnsSanity(Rule):
    code = "DNSSAN"
    description = "misc DNS sanity checks"

    def check(self, ctx: Ctx) -> list[Finding]:
        dns = ctx.config.get("dns") or {}
        findings = []
        if dns.get("enable"):
            if not dns.get("nameserver"):
                findings.append(
                    Finding(
                        code="DNSSAN001",
                        severity=Severity.ERROR,
                        title="DNS enabled without nameservers",
                        message="dns.enable is true but `nameserver` is empty or missing",
                        path="dns.nameserver",
                    )
                )
            if dns.get("ipv6") and not ctx.config.get("ipv6", False):
                findings.append(
                    Finding(
                        code="DNSSAN002",
                        severity=Severity.INFO,
                        title="DNS returns AAAA while ipv6 is disabled",
                        message="dns.ipv6 is true but top-level ipv6 is false; AAAA answers are queried and then dropped",
                        path="dns.ipv6",
                        hint="set dns.ipv6: false to save lookups, or enable ipv6 if you meant to use it",
                    )
                )
        return findings


RULES: list[Rule] = [TunWithoutDns(), DnsListenPublic(), DnsSanity()]

