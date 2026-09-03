import textwrap

from routelint.loader import load_config
from routelint.locate import resolve_line, snippet_for

CONFIG = textwrap.dedent("""\
    port: 7890
    external-controller: 0.0.0.0:9090
    dns:
      enable: true
      listen: 0.0.0.0:1053
    proxy-groups:
      - name: A
        type: select
        proxies: [DIRECT]
    rules:
      - MATCH,REJECT
      - DOMAIN,example.com,DIRECT
""")


def test_resolve_top_level_key(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(CONFIG, encoding="utf-8")
    config = load_config(p)
    assert resolve_line(config, "external-controller") == 2
    assert resolve_line(config, "dns.listen") == 5
    assert resolve_line(config, "port") == 1


def test_resolve_list_index(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(CONFIG, encoding="utf-8")
    config = load_config(p)
    assert resolve_line(config, "rules[0]") == 11  # MATCH,REJECT
    assert resolve_line(config, "rules[1]") == 12  # DOMAIN,example.com,DIRECT
    assert resolve_line(config, "proxy-groups[0]") == 7  # "- name: A"


def test_resolve_missing_path(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(CONFIG, encoding="utf-8")
    config = load_config(p)
    assert resolve_line(config, "") is None
    assert resolve_line(config, "nope.nope") is None
    assert resolve_line(config, "rules[99]") == 10  # falls back to the list start


def test_snippet():
    lines = CONFIG.splitlines()
    assert snippet_for(lines, 2) == "external-controller: 0.0.0.0:9090"
    assert snippet_for(lines, None) == ""
    assert snippet_for(lines, 999) == ""


def test_cli_annotates_line_and_snippet(tmp_path, capsys):
    from routelint.cli import EXIT_FINDINGS, main

    p = tmp_path / "c.yaml"
    p.write_text(CONFIG, encoding="utf-8")
    rc = main([str(p), "--no-native"])
    out = capsys.readouterr().out
    assert rc == EXIT_FINDINGS
    assert "line 11: - MATCH,REJECT" in out
    assert "line 2:" in out  # SEC001 on external-controller
