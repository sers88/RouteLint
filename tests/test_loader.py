import pytest

from routelint.loader import ConfigError, load_config, rule_target


def test_load_ok(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("port: 7890\nrules:\n  - MATCH,DIRECT\n")
    assert load_config(f) == {"port": 7890, "rules": ["MATCH,DIRECT"]}


def test_load_empty(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("")
    assert load_config(f) == {}


def test_load_bad_yaml(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("rules: [unclosed\n")
    with pytest.raises(ConfigError):
        load_config(f)


def test_load_non_mapping(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text("- a\n- b\n")
    with pytest.raises(ConfigError):
        load_config(f)


@pytest.mark.parametrize(
    "rule,target",
    [
        ("MATCH,PROXY", "PROXY"),
        ("DOMAIN-SUFFIX,ru,DIRECT", "DIRECT"),
        ("GEOIP,CN,PROXY,no-resolve", "PROXY"),
        ("MATCH", None),
    ],
)
def test_rule_target(rule, target):
    assert rule_target(rule) == target

