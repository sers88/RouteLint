"""Layer 2: native validation via `mihomo -t` (adapter)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .model import Finding, LayerResult, Severity


def run_native_layer(
    config_path: str | Path,
    mihomo_path: str | None = None,
    timeout: float = 60.0,
) -> tuple[LayerResult, list[Finding]]:
    binary = mihomo_path or shutil.which("mihomo") or shutil.which("clash-meta")
    if not binary:
        return (
            LayerResult("native", "skipped", "mihomo binary not found in PATH (use --mihomo)"),
            [],
        )

    proc = _run(binary, config_path, timeout)
    if proc is None:
        return LayerResult("native", "failed", f"timed out after {timeout:.0f}s"), []

    returncode, output = proc
    if returncode == 0:
        return LayerResult("native", "ok", "mihomo -t passed"), []

    detail = _tail(output)
    finding = Finding(
        code="NATIVE001",
        severity=Severity.ERROR,
        title="mihomo -t rejected the config",
        message=detail,
        path="",
        hint="this is what mihomo itself reports; fix it first, then re-run the doctor",
    )
    return LayerResult("native", "failed", f"exit code {returncode}"), [finding]


def _run(binary: str, config_path: str | Path, timeout: float):
    try:
        proc = subprocess.run(
            [binary, "-t", "-f", str(config_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(Path(config_path).parent or "."),
        )
    except OSError as e:
        return 127, str(e)
    return proc.returncode, (proc.stderr or "") + (proc.stdout or "")


def _tail(output: str, limit: int = 1200) -> str:
    output = output.strip()
    return output[-limit:] if len(output) > limit else output

