import json

import pytest

from routelint.cli import EXIT_FINDINGS, EXIT_OK, main
from routelint.engine import run_semantic_layer
from routelint.loader import build_ctx
from routelint.model import Severity
from routelint.reporters import render_json, render_text

GOOD = """\
port: 7890
external-controller: 127.0.0.1:9090
secret: "s3cret"
proxies:
  - name: p1
    type: ss
    server: example.com
    port: 443
    cipher: aes-128-gcm
    password: x
proxy-groups:
  - name: PROXY
    type: select
    proxies: [p1]
rules:
  - DOMAIN-SUFFIX,ru,PROXY
  - MATCH,PROXY
"""

BAD = """\
external-controller: 0.0.0.0:9090
proxies:
  - name: p1
    type: ss
    server: example.com
    port: 443
    cipher: aes-128-gcm
    password: x
proxy-groups:
  - name: A
    type: select
    proxies: [p1, B]
  - name: B
    type: select
    proxies: [A]
rules:
  - MATCH,REJECT
  - DOMAIN,example.com,A
"""


def _write(tmp_path, content):
    p = tmp_path / "config.yaml"
    p.write_text(content, encoding="utf-8")
    return p


def test_clean_config(tmp_path, capsys):
    rc = main([str(_write(tmp_path, GOOD)), "--no-native", "-f", "json"])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["findings"] == []
    layers = {lyr["name"]: lyr["status"] for lyr in data["layers"]}
    assert layers["schema"] == "skipped" and layers["native"] == "skipped" and layers["semantic"] == "ok"


def test_bad_config_findings_and_exit_code(tmp_path, capsys):
    rc = main([str(_write(tmp_path, BAD)), "--no-native", "-f", "json"])
    assert rc == EXIT_FINDINGS
    data = json.loads(capsys.readouterr().out)
    found = {f["code"] for f in data["findings"]}
    assert {"SEC001", "CYC001", "SHD001", "RT001"} <= found
    assert any(f["severity"] == "high" for f in data["findings"])


def test_min_severity_filters(tmp_path, capsys):
    rc = main([str(_write(tmp_path, GOOD)), "--no-native", "-f", "json", "--min-severity", "error"])
    assert rc == EXIT_OK
    data = json.loads(capsys.readouterr().out)
    assert data["findings"] == []


def test_parse_error(tmp_path, capsys):
    rc = main([str(_write(tmp_path, "rules: [oops")), "--no-native", "-f", "json"])
    assert rc == EXIT_FINDINGS
    data = json.loads(capsys.readouterr().out)
    assert data["findings"][0]["code"] == "CONFIG001"


def test_text_report(tmp_path, capsys):
    rc = main([str(_write(tmp_path, BAD)), "--no-native"])
    out = capsys.readouterr().out
    assert rc == EXIT_FINDINGS
    assert "Layers:" in out and "SEC001" in out


def test_missing_config():
    assert main(["nope.yaml", "--no-native"]) == 2


# --- engine filtering ----------------------------------------------------


def test_engine_disable_and_only():
    ctx = build_ctx({"proxy-groups": [{"name": "g", "type": "select", "proxies": ["g"]}]})
    layer, findings = run_semantic_layer(ctx, disable=["CYC"])
    assert findings == []
    layer, findings = run_semantic_layer(ctx, only=["CYC"])
    assert [f.code for f in findings] == ["CYC001"]
    assert layer.status == "failed"


# --- reporters -----------------------------------------------------------


def test_render_dispatch_and_json():
    from routelint.model import Finding, LayerResult, Report

    report = Report(
        config_path="x.yaml",
        layers=[LayerResult("semantic", "ok", "1/1")],
        findings=[Finding("REF001", Severity.ERROR, "t", "m", path="rules[0]")],
    )
    assert json.loads(render_json(report))["summary"]["error"] == 1
    text = render_text(report)
    assert "REF001" in text and "path: rules[0]" in text


def test_severity_parse():
    assert Severity.parse("high") == Severity.HIGH
    with pytest.raises(ValueError):
        Severity.parse("bogus")


