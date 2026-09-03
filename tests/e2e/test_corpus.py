"""Golden-snapshot tests over the vendored real-world config corpus.

Each corpus config is linted (semantic layer only) and the set of
(code, severity) pairs is compared against tests/e2e/expected/<name>.json.
A mismatch means rule behavior changed — review it, then update the snapshot
with `python tests/e2e/update_snapshots.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from routelint.engine import run_semantic_layer
from routelint.loader import ConfigError, build_ctx, load_config

CORPUS = Path(__file__).parent / "corpus"
EXPECTED = Path(__file__).parent / "expected"

CASES = sorted(p.stem for p in CORPUS.glob("*.yaml"))


def _snapshot(config: dict) -> list[dict]:
    _, findings = run_semantic_layer(build_ctx(config))
    return [
        {"code": f.code, "severity": f.severity.label}
        for f in sorted(findings, key=lambda f: (f.code, f.path, f.message))
    ]


@pytest.mark.parametrize("name", CASES)
def test_corpus_snapshot(name: str):
    path = CORPUS / f"{name}.yaml"
    expected_path = EXPECTED / f"{name}.json"
    assert expected_path.exists(), "missing snapshot; run python tests/e2e/update_snapshots.py"

    try:
        config = load_config(path)
    except ConfigError:
        snapshot = [{"code": "CONFIG001", "severity": "error"}]
    else:
        snapshot = _snapshot(config)

    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    assert snapshot == expected, f"snapshot drift for {name}; review and regenerate"
