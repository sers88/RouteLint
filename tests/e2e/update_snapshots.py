"""Regenerate golden snapshots for the corpus.

Usage: python tests/e2e/update_snapshots.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routelint.engine import run_semantic_layer  # noqa: E402
from routelint.loader import ConfigError, build_ctx, load_config  # noqa: E402

CORPUS = Path(__file__).parent / "corpus"
EXPECTED = Path(__file__).parent / "expected"


def main() -> int:
    EXPECTED.mkdir(exist_ok=True)
    for path in sorted(CORPUS.glob("*.yaml")):
        try:
            config = load_config(path)
        except ConfigError:
            snapshot = [{"code": "CONFIG001", "severity": "error"}]
        else:
            _, findings = run_semantic_layer(build_ctx(config))
            snapshot = [
                {"code": f.code, "severity": f.severity.label}
                for f in sorted(findings, key=lambda f: (f.code, f.path, f.message))
            ]
        out = EXPECTED / f"{path.stem}.json"
        out.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
        print(f"{path.stem}: {len(snapshot)} findings -> {out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
