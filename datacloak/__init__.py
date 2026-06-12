"""
DataCloak — Privacy Protection Library
=======================================

A production-ready Python library for detecting and masking Personally
Identifiable Information (PII) in text, logs, files, and application data.

Quick start::

    from datacloak import mask, scan

    text = \"\"\"
    Aadhaar: 2345 6789 0123
    PAN: ABCDE1234F
    Email: alice@example.com
    Phone: 9876543210
    \"\"\"

    print(mask(text))          # partial masking (default)
    print(mask(text, mode="full"))
    print(mask(text, mode="hash"))

    findings = scan(text)
    # {"aadhaar": ["2345 6789 0123"], "pan": ["ABCDE1234F"], ...}
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .detectors import (
    DEFAULT_DETECTORS,
    AadhaarDetector,
    BaseDetector,
    CreditCardDetector,
    Detection,
    EmailDetector,
    IFSCDetector,
    IPAddressDetector,
    MobileDetector,
    PANDetector,
    UPIDetector,
)
from .file_scanner import FileScanResult, scan_file
from .masker import MaskMode, mask_text
from .reporter import Report, generate_report_from_file, generate_report_from_text
from .scanner import ScanResult, scan_summary, scan_text

if TYPE_CHECKING:
    from pathlib import Path

__version__ = "0.1.1"
__author__ = "DataCloak Contributors"
__license__ = "MIT"

# Set up a NullHandler so the library is silent unless the caller configures logging.
logging.getLogger(__name__).addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Convenience aliases (the primary public surface)
# ---------------------------------------------------------------------------


def mask(
    text: str,
    mode: MaskMode = "partial",
    detectors: list[BaseDetector] | None = None,
) -> str:
    """
    Detect and mask all PII in *text*.

    Parameters
    ----------
    text:
        Input string containing potential PII.
    mode:
        ``"partial"`` (default) — keep trailing characters visible.
        ``"full"`` — replace with descriptive tags like ``[EMAIL_REDACTED]``.
        ``"hash"`` — replace with SHA-256 digest.
    detectors:
        Optional list of :class:`~datacloak.detectors.BaseDetector` instances.
        Defaults to all built-in detectors.

    Returns
    -------
    str
        The masked string.

    Example::

        >>> from datacloak import mask
        >>> mask("Call me at 9876543210")
        'Call me at ******3210'
    """
    return mask_text(text, mode=mode, detectors=detectors)


def scan(
    text: str,
    detectors: list[BaseDetector] | None = None,
) -> ScanResult:
    """
    Scan *text* for PII without modifying it.

    Parameters
    ----------
    text:
        Input string to scan.
    detectors:
        Optional custom detectors.

    Returns
    -------
    dict
        Mapping of PII type name → list of detected values.

    Example::

        >>> from datacloak import scan
        >>> scan("Email me at bob@example.com")
        {'email': ['bob@example.com']}
    """
    return scan_text(text, detectors=detectors)


def report(
    text: str,
    source_label: str = "<inline text>",
    detectors: list[BaseDetector] | None = None,
) -> Report:
    """
    Generate a structured :class:`~datacloak.reporter.Report` from *text*.

    Example::

        >>> from datacloak import report
        >>> r = report("john@example.com called 9876543210")
        >>> print(r.to_json())
    """
    return generate_report_from_text(text, source_label=source_label, detectors=detectors)


__all__ = [
    # Version
    "__version__",
    # Core API
    "mask",
    "scan",
    "report",
    # File operations
    "scan_file",
    # Lower-level API
    "mask_text",
    "scan_text",
    "scan_summary",
    "generate_report_from_text",
    "generate_report_from_file",
    # Detectors
    "BaseDetector",
    "Detection",
    "DEFAULT_DETECTORS",
    "AadhaarDetector",
    "PANDetector",
    "MobileDetector",
    "EmailDetector",
    "UPIDetector",
    "CreditCardDetector",
    "IFSCDetector",
    "IPAddressDetector",
    # Types
    "MaskMode",
    "ScanResult",
    "FileScanResult",
    "Report",
]
