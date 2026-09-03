"""Reporters: render a Report as text or JSON."""

from __future__ import annotations

import json
import sys

from ..model import Report, Severity

__all__ = ["render", "render_text", "render_json"]

_ORDER = [Severity.HIGH, Severity.ERROR, Severity.WARN, Severity.INFO]


def render(report: Report, fmt: str = "text", *, use_color: bool | None = None) -> str:
    if fmt == "json":
        return render_json(report)
    return render_text(report, use_color=use_color if use_color is not None else sys.stdout.isatty())


def render_text(report: Report, *, use_color: bool = False) -> str:
    lines: list[str] = []
    lines.append(f"routelint report: {report.config_path}")
    lines.append("")
    lines.append("Layers:")
    for layer in report.layers:
        mark = {"ok": "+", "skipped": "-", "failed": "x"}[layer.status]
        lines.append(f"  [{mark}] {layer.name:<10} {layer.status}  {layer.detail}")
    lines.append("")

    if not report.findings:
        lines.append("No findings. Config looks healthy.")
        return "\n".join(lines)

    counts = report.counts
    summary = ", ".join(f"{counts[s.label]} {s.label}" for s in _ORDER if counts[s.label])
    lines.append(f"Findings ({len(report.findings)}): {summary}")
    lines.append("")
    for f in sorted(report.findings, key=lambda f: -f.severity):
        sev = f.severity.label.upper()
        lines.append(f"  [{sev:<5}] {f.code}  {f.title}")
        if f.path:
            lines.append(f"          path: {f.path}")
        lines.append(f"          {f.message}")
        if f.hint:
            lines.append(f"          hint: {f.hint}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_json(report: Report) -> str:
    return json.dumps(report.as_dict(), indent=2, ensure_ascii=False)

