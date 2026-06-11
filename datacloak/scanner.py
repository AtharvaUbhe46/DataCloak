"""
DataCloak scanner module.

Provides :func:`scan_text` for structured PII detection without modification.
"""

from __future__ import annotations

import logging
from collections import defaultdict

from .detectors import DEFAULT_DETECTORS, BaseDetector, Detection

logger = logging.getLogger(__name__)

ScanResult = dict[str, list[str]]


def scan_text(
    text: str,
    detectors: list[BaseDetector] | None = None,
) -> ScanResult:
    """
    Scan *text* for PII and return structured findings.

    Parameters
    ----------
    text:
        The input string to scan.
    detectors:
        Custom list of detectors.  Defaults to all built-in detectors.

    Returns
    -------
    dict
        A mapping of PII type → list of detected values.

        Example::

            {
                "email": ["john@example.com"],
                "phone": ["9876543210"],
                "aadhaar": ["1234 5678 9012"],
            }
    """
    active_detectors = detectors or DEFAULT_DETECTORS
    result: dict[str, list[str]] = defaultdict(list)

    for detector in active_detectors:
        try:
            findings: list[Detection] = detector.detect(text)
            for detection in findings:
                result[detection.detector_name].append(detection.value)
                logger.debug(
                    "Found %s: %r", detection.detector_name, detection.value
                )
        except Exception as exc:  # pragma: no cover
            logger.warning("Detector %r raised an error: %s", detector.name, exc)

    # Return plain dict (not defaultdict) and only include found types
    return {k: v for k, v in result.items() if v}


def scan_summary(
    text: str,
    detectors: list[BaseDetector] | None = None,
) -> dict[str, int]:
    """
    Return a count summary of detected PII types.

    Example::

        {"email": 3, "phone": 1}
    """
    findings = scan_text(text, detectors=detectors)
    return {k: len(v) for k, v in findings.items()}
