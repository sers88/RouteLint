"""Layer 1: JSON Schema validation (optional, needs `jsonschema`)."""

from __future__ import annotations

import json
from pathlib import Path

from .model import Finding, LayerResult, Severity

#: Known community schemas; used only as documentation / future default.
DEFAULT_SCHEMA_URL = "https://raw.githubusercontent.com/VaalaCat/mihomo-schema/main/mihomo_schema.json"


def run_schema_layer(config: dict, schema_path: str | None) -> tuple[LayerResult, list[Finding]]:
    if not schema_path:
        return LayerResult("schema", "skipped", "no --schema given"), []
    try:
        import jsonschema
    except ImportError:
        return (
            LayerResult("schema", "skipped", "jsonschema not installed (pip install 'mihomo-doctor[schema]')"),
            [],
        )
    try:
        schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return LayerResult("schema", "failed", f"cannot load schema: {e}"), []

    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(config), key=lambda e: list(e.absolute_path))
    findings = [
        Finding(
            code="SCHEMA001",
            severity=Severity.ERROR,
            title="config does not match JSON Schema",
            message=e.message,
            path=_json_path(e),
            hint="see the schema and the mihomo docs for the expected structure",
        )
        for e in errors
    ]
    status = "failed" if findings else "ok"
    return LayerResult("schema", status, f"{len(errors)} schema violations"), findings


def _json_path(error) -> str:
    path = "$"
    for part in error.absolute_path:
        path += f"[{part}]" if isinstance(part, int) else f".{part}"
    return path

