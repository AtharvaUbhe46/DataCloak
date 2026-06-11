"""
DataCloak report generation module.

Generates structured JSON reports from scan results.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .detectors import DEFAULT_DETECTORS, BaseDetector
from .file_scanner import FileScanResult, scan_file
from .scanner import scan_summary, scan_text

logger = logging.getLogger(__name__)


@dataclass
class Report:
    """A complete PII scan report."""

    generated_at: str
    source: str
    total_findings: int
    summary: dict[str, int]
    details: dict[str, list[str]]
    risk_level: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def save(self, path: str | Path) -> Path:
        dest = Path(path)
        dest.write_text(self.to_json(), encoding="utf-8")
        logger.info("Report saved to %s", dest)
        return dest


def _risk_level(total: int) -> str:
    if total == 0:
        return "NONE"
    if total <= 3:
        return "LOW"
    if total <= 10:
        return "MEDIUM"
    return "HIGH"


def generate_report_from_text(
    text: str,
    source_label: str = "<inline text>",
    detectors: list[BaseDetector] | None = None,
) -> Report:
    """
    Generate a :class:`Report` from an in-memory string.

    Parameters
    ----------
    text:
        The text to scan.
    source_label:
        A human-readable label for the source (used in the report).
    detectors:
        Custom detectors.

    Returns
    -------
    :class:`Report`
    """
    from .scanner import scan_text as _scan

    active = detectors or DEFAULT_DETECTORS
    details = _scan(text, detectors=active)
    summary = {k: len(v) for k, v in details.items()}
    total = sum(summary.values())

    return Report(
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        source=source_label,
        total_findings=total,
        summary=summary,
        details=details,
        risk_level=_risk_level(total),
    )


def generate_report_from_file(
    file_path: str | Path,
    detectors: list[BaseDetector] | None = None,
) -> Report:
    """
    Generate a :class:`Report` from a file.

    Parameters
    ----------
    file_path:
        Path to the file to scan.
    detectors:
        Custom detectors.

    Returns
    -------
    :class:`Report`
    """
    path = Path(file_path)
    file_result: FileScanResult = scan_file(path, detectors=detectors)

    summary = file_result.summary
    total = sum(summary.values())

    return Report(
        generated_at=datetime.now(tz=timezone.utc).isoformat(),
        source=str(path),
        total_findings=total,
        summary=summary,
        details=file_result.by_type,
        risk_level=_risk_level(total),
    )
