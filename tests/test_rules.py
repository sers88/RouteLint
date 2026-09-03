from helpers import check_one, codes
from routelint.model import Severity
from routelint.rules.cycles import GroupCycles
from routelint.rules.dns import DnsListenPublic, DnsSanity, TunWithoutDns
from routelint.rules.references import DuplicateNames, MissingGroupRefs, MissingRuleTargets, Unused
from routelint.rules.routing import BlockingFinal, BroadBeforeSpecific, GeoipCnViaProxy
from routelint.rules.security import ControllerExposure, ExternalUi
from routelint.rules.shadowing import DuplicateRules, MatchNotLast

# --- references ---------------------------------------------------------


def test_missing_group_ref():
    cfg = {
        "proxies": [{"name": "p1"}],
        "proxy-groups": [{"name": "g1", "type": "select", "proxies": ["p1", "ghost"]}],
    }
    assert codes(check_one(MissingGroupRefs(), cfg)) == ["REF001"]


def test_builtin_policies_ok():
    cfg = {"proxy-groups": [{"name": "g1", "type": "select", "proxies": ["DIRECT", "REJECT"]}]}
    assert check_one(MissingGroupRefs(), cfg) == []


def test_missing_provider_use():
    cfg = {
        "proxy-groups": [{"name": "g1", "type": "select", "proxies": ["DIRECT"], "use": ["nope"]}]
    }
    assert codes(check_one(MissingGroupRefs(), cfg)) == ["REF002"]


def test_rule_routes_to_missing_group():
    cfg = {"rules": ["DOMAIN-SUFFIX,ru,ghost", "MATCH,DIRECT"]}
    assert codes(check_one(MissingRuleTargets(), cfg)) == ["RULE002"]


def test_ruleset_missing_provider():
    cfg = {"rules": ["RULE-SET,ads,REJECT"]}
    assert codes(check_one(MissingRuleTargets(), cfg)) == ["RULE001"]


def test_duplicate_names():
    cfg = {
        "proxies": [{"name": "a"}, {"name": "a"}],
        "proxy-groups": [{"name": "a", "type": "select", "proxies": ["a"]}],
    }
    assert "DUP001" in codes(check_one(DuplicateNames(), cfg))


def test_unused_proxy_and_group():
    cfg = {
        "proxies": [{"name": "used"}, {"name": "lonely"}],
        "proxy-groups": [{"name": "dead-group", "type": "select", "proxies": ["used"]}],
        "rules": ["MATCH,DIRECT"],
    }
    found = codes(check_one(Unused(), cfg))
    assert "UNUSED001" in found and "UNUSED002" in found


def test_global_group_is_special():
    # GLOBAL has built-in meaning; not an unused-group false positive (issue #3)
    cfg = {
        "proxies": [{"name": "p"}],
        "proxy-groups": [
            {"name": "GLOBAL", "type": "select", "proxies": ["p"]},
        ],
        "rules": ["MATCH,DIRECT"],
    }
    assert "UNUSED002" not in codes(check_one(Unused(), cfg))


# --- cycles -------------------------------------------------------------


def test_self_cycle():
    cfg = {"proxy-groups": [{"name": "g", "type": "select", "proxies": ["g"]}]}
    assert codes(check_one(GroupCycles(), cfg)) == ["CYC001"]


def test_mutual_cycle():
    cfg = {
        "proxy-groups": [
            {"name": "a", "type": "select", "proxies": ["b"]},
            {"name": "b", "type": "select", "proxies": ["a"]},
        ]
    }
    assert len(check_one(GroupCycles(), cfg)) == 1


def test_no_cycle():
    cfg = {
        "proxies": [{"name": "p"}],
        "proxy-groups": [{"name": "g", "type": "select", "proxies": ["p"]}],
    }
    assert check_one(GroupCycles(), cfg) == []


def test_shared_subgroup_is_not_a_cycle():
    # regression for #1: cross-edge used to crash with ValueError
    cfg = {
        "proxies": [{"name": "p"}],
        "proxy-groups": [
            {"name": "A", "type": "select", "proxies": ["SHARED"]},
            {"name": "B", "type": "select", "proxies": ["SHARED"]},
            {"name": "SHARED", "type": "select", "proxies": ["p"]},
        ],
    }
    assert check_one(GroupCycles(), cfg) == []


def test_diamond_is_not_a_cycle():
    cfg = {
        "proxy-groups": [
            {"name": "TOP", "type": "select", "proxies": ["L", "R"]},
            {"name": "L", "type": "select", "proxies": ["MID"]},
            {"name": "R", "type": "select", "proxies": ["MID"]},
            {"name": "MID", "type": "select", "proxies": ["DIRECT"]},
        ],
    }
    assert check_one(GroupCycles(), cfg) == []


def test_two_independent_cycles():
    cfg = {
        "proxy-groups": [
            {"name": "a", "type": "select", "proxies": ["b"]},
            {"name": "b", "type": "select", "proxies": ["a"]},
            {"name": "x", "type": "select", "proxies": ["y"]},
            {"name": "y", "type": "select", "proxies": ["x"]},
        ],
    }
    assert len(check_one(GroupCycles(), cfg)) == 2


def test_cycle_behind_shared_node():
    # a -> shared -> loop, reached from two parents: reported once
    cfg = {
        "proxy-groups": [
            {"name": "p1", "type": "select", "proxies": ["shared"]},
            {"name": "p2", "type": "select", "proxies": ["shared"]},
            {"name": "shared", "type": "select", "proxies": ["loop-a"]},
            {"name": "loop-a", "type": "select", "proxies": ["loop-b"]},
            {"name": "loop-b", "type": "select", "proxies": ["loop-a"]},
        ],
    }
    findings = check_one(GroupCycles(), cfg)
    assert [f.code for f in findings] == ["CYC001"]
    assert "loop-a -> loop-b -> loop-a" in findings[0].message


# --- shadowing ----------------------------------------------------------


def test_match_not_last():
    cfg = {"rules": ["MATCH,DIRECT", "DOMAIN,example.com,PROXY"]}
    assert codes(check_one(MatchNotLast(), cfg)) == ["SHD001"]


def test_no_match_info():
    cfg = {"rules": ["DOMAIN,example.com,PROXY"]}
    assert codes(check_one(MatchNotLast(), cfg)) == ["SHD002"]


def test_duplicate_rule():
    cfg = {"rules": ["DOMAIN,x.com,DIRECT", "DOMAIN,x.com,DIRECT", "MATCH,PROXY"]}
    assert codes(check_one(DuplicateRules(), cfg)) == ["DUPRULE001"]


# --- security -----------------------------------------------------------


def test_controller_public_no_secret():
    cfg = {"external-controller": "0.0.0.0:9090"}
    (finding,) = check_one(ControllerExposure(), cfg)
    assert finding.code == "SEC001" and finding.severity == Severity.WARN


def test_controller_public_with_secret():
    cfg = {"external-controller": "0.0.0.0:9090", "secret": "s3cret"}
    assert codes(check_one(ControllerExposure(), cfg)) == ["SEC002"]


def test_controller_local_no_secret():
    cfg = {"external-controller": "127.0.0.1:9090"}
    assert codes(check_one(ControllerExposure(), cfg)) == ["SEC003"]


def test_controller_local_with_secret_ok():
    cfg = {"external-controller": "127.0.0.1:9090", "secret": "s3cret"}
    assert check_one(ControllerExposure(), cfg) == []


def test_external_ui_pairing():
    assert codes(check_one(ExternalUi(), {"external-ui": "ui"})) == ["UI001"]
    assert codes(check_one(ExternalUi(), {"external-ui-url": "http://x"})) == ["UI002"]
    assert check_one(ExternalUi(), {"external-ui": "ui", "external-ui-url": "http://x"}) == []


# --- dns ----------------------------------------------------------------


def test_tun_without_dns():
    cfg = {"tun": {"enable": True}, "dns": {"enable": False}}
    assert codes(check_one(TunWithoutDns(), cfg)) == ["DNS001"]


def test_tun_with_dns_ok():
    cfg = {"tun": {"enable": True}, "dns": {"enable": True, "nameserver": ["1.1.1.1"]}}
    assert check_one(TunWithoutDns(), cfg) == []


def test_dns_listen_public():
    assert codes(check_one(DnsListenPublic(), {"dns": {"listen": "0.0.0.0:1053"}})) == ["DNSLISTEN001"]
    assert check_one(DnsListenPublic(), {"dns": {"listen": "127.0.0.1:1053"}}) == []


def test_dns_no_nameservers():
    assert codes(check_one(DnsSanity(), {"dns": {"enable": True}})) == ["DNSSAN001"]


def test_dns_ipv6_mismatch():
    cfg = {"ipv6": False, "dns": {"enable": True, "nameserver": ["1.1.1.1"], "ipv6": True}}
    assert "DNSSAN002" in codes(check_one(DnsSanity(), cfg))


# --- routing ------------------------------------------------------------


def test_match_reject():
    cfg = {"rules": ["MATCH,REJECT"]}
    assert codes(check_one(BlockingFinal(), cfg)) == ["RT001"]


def test_geoip_cn_via_proxy():
    cfg = {"rules": ["GEOIP,CN,PROXY", "MATCH,PROXY"]}
    assert codes(check_one(GeoipCnViaProxy(), cfg)) == ["RTGEO001"]
    cfg["rules"] = ["GEOIP,CN,DIRECT", "MATCH,PROXY"]
    assert check_one(GeoipCnViaProxy(), cfg) == []


def test_broad_before_specific():
    cfg = {
        "rules": [
            "IP-CIDR,1.2.3.4/32,PROXY",
            "DOMAIN-SUFFIX,example.com,DIRECT",
            "MATCH,PROXY",
        ]
    }
    assert codes(check_one(BroadBeforeSpecific(), cfg)) == ["RTORD001"]


def test_broad_same_target_no_shadow():
    cfg = {"rules": ["IP-CIDR,1.2.3.4/32,DIRECT", "DOMAIN-SUFFIX,example.com,DIRECT", "MATCH,PROXY"]}
    assert check_one(BroadBeforeSpecific(), cfg) == []

