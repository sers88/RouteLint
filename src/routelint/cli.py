"""CLI entry point.

Exit codes:
  0 - clean (no findings at or above the error threshold)
  1 - findings at ERROR/HIGH severity, or config could not be parsed
  2 - usage / internal error
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from pathlib import Path

from . import __version__
from .engine import run_semantic_layer
from .loader import ConfigError, build_ctx, load_config
from .model import Finding, LayerResult, Report, Severity
from .native_validator import run_native_layer
from .reporters import render
from .schema_validator import run_schema_layer

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="routelint",
        description="Lint a Mihomo / Clash.Meta config: JSON Schema + `mihomo -t` + semantic rules",
    )
    parser.add_argument("config", help="path to config.yaml")
    parser.add_argument("--format", "-f", choices=("text", "json"), default="text")
    parser.add_argument("--schema", help="path to a JSON Schema for clash/mihomo configs")
    parser.add_argument("--mihomo", help="path to the mihomo binary (default: search PATH)")
    parser.add_argument("--no-native", action="store_true", help="skip the `mihomo -t` layer")
    parser.add_argument("--disable", help="comma-separated rule codes to skip (e.g. SEC,UNUSED)")
    parser.add_argument("--only", help="comma-separated rule codes to run (e.g. REF,CYC)")
    parser.add_argument(
        "--min-severity",
        choices=("info", "warn", "error", "high"),
        default="info",
        help="report findings at this severity or above (default: info)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def run(args: argparse.Namespace) -> int:
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"error: config not found: {config_path}", file=sys.stderr)
        return EXIT_ERROR

    report = Report(config_path=str(config_path))

    try:
        config = load_config(config_path)
    except ConfigError as e:
        report.layers.append(LayerResult("parse", "failed", str(e)))
        report.findings.append(
            Finding(
                code="CONFIG001",
                severity=Severity.ERROR,
                title="config could not be parsed",
                message=str(e),
            )
        )
        _emit(report, args)
        return EXIT_FINDINGS

    disable = [c for c in (args.disable or "").split(",") if c.strip()]
    only = [c for c in (args.only or "").split(",") if c.strip()]

    layer, findings = run_schema_layer(config, args.schema)
    report.layers.append(layer)
    report.findings.extend(findings)

    if args.no_native:
        report.layers.append(LayerResult("native", "skipped", "disabled via --no-native"))
    else:
        layer, findings = run_native_layer(config_path, args.mihomo)
        report.layers.append(layer)
        report.findings.extend(findings)

    layer, findings = run_semantic_layer(build_ctx(config), disable=disable, only=only)
    report.layers.append(layer)
    report.findings.extend(findings)

    min_sev = Severity.parse(args.min_severity)
    report.findings = [f for f in report.findings if f.severity >= min_sev]

    _emit(report, args)
    worst = report.max_severity()
    return EXIT_FINDINGS if worst is not None and worst >= Severity.ERROR else EXIT_OK


def _emit(report: Report, args: argparse.Namespace) -> None:
    print(render(report, fmt=args.format))


def _force_utf8_streams() -> None:
    # Windows consoles often use a legacy codepage (cp1251 etc.); config names
    # routinely contain emoji, which would crash print() with UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            with contextlib.suppress(OSError, ValueError):
                reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    _force_utf8_streams()
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())

