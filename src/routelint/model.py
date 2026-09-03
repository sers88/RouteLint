"""Core data model: findings, severities, layers, report."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Ordered severity. INFO < WARN < ERROR < HIGH."""

    INFO = 10
    WARN = 20
    ERROR = 30
    HIGH = 40

    @property
    def label(self) -> str:
        return _LABELS[self]

    @classmethod
    def parse(cls, name: str) -> Severity:
        try:
            return cls(_BY_NAME[name.strip().lower()])
        except KeyError:
            raise ValueError(
                f"unknown severity {name!r}; expected one of: info, warn, error, high"
            ) from None


_LABELS = {
    Severity.INFO: "info",
    Severity.WARN: "warn",
    Severity.ERROR: "error",
    Severity.HIGH: "high",
}
_BY_NAME = {v: k for k, v in _LABELS.items()}


@dataclass(frozen=True)
class Finding:
    """A single problem (or note) found in the config."""

    code: str
    severity: Severity
    title: str
    message: str
    path: str = ""
    hint: str = ""
    line: int | None = None  # 1-based source line, filled during annotation
    snippet: str = ""  # the source line text, filled during annotation

    def as_dict(self) -> dict:
        data: dict = {
            "code": self.code,
            "severity": self.severity.label,
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "hint": self.hint,
        }
        if self.line is not None:
            data["line"] = self.line
            data["snippet"] = self.snippet
        return data


@dataclass
class LayerResult:
    """Outcome of one validation layer (schema / native / semantic)."""

    name: str
    status: str  # "ok" | "skipped" | "failed"
    detail: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "detail": self.detail}


@dataclass
class Report:
    config_path: str
    findings: list[Finding] = field(default_factory=list)
    layers: list[LayerResult] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def as_dict(self) -> dict:
        return {
            "config": self.config_path,
            "layers": [layer.as_dict() for layer in self.layers],
            "findings": [f.as_dict() for f in self.findings],
            "summary": self.counts,
        }

