"""
DataCloak masking engine.

Provides three masking modes:
    - ``partial``  — keep last N characters visible (default)
    - ``full``     — replace with a labelled tag, e.g. ``[EMAIL_REDACTED]``
    - ``hash``     — replace with the SHA-256 hex digest of the original value
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Literal

from .detectors import DEFAULT_DETECTORS, BaseDetector, Detection

logger = logging.getLogger(__name__)

MaskMode = Literal["partial", "full", "hash"]

# How many trailing characters to keep per PII type in partial mode
_PARTIAL_KEEP: dict[str, int] = {
    "aadhaar": 4,
    "pan": 5,
    "phone": 4,
    "email": 0,       # special handling
    "upi_id": 0,      # special handling
    "credit_card": 4,
    "ifsc": 4,
    "ip_address": 0,  # special handling
}

# Replacement tag templates for full mode
_FULL_TAGS: dict[str, str] = {
    "aadhaar": "[AADHAAR_REDACTED]",
    "pan": "[PAN_REDACTED]",
    "phone": "[PHONE_REDACTED]",
    "email": "[EMAIL_REDACTED]",
    "upi_id": "[UPI_REDACTED]",
    "credit_card": "[CARD_REDACTED]",
    "ifsc": "[IFSC_REDACTED]",
    "ip_address": "[IP_REDACTED]",
}


def _mask_partial(detection: Detection) -> str:
    """Apply partial masking — hide leading characters, keep trailing few."""
    value = detection.value
    name = detection.detector_name

    if name == "email":
        local, at, domain = value.partition("@")
        if len(local) <= 1:
            return f"*{at}{domain}"
        masked_local = local[0] + "***"
        return f"{masked_local}{at}{domain}"

    if name == "upi_id":
        local, at, handle = value.partition("@")
        if len(local) <= 2:
            return f"***{at}{handle}"
        masked_local = local[0] + "***"
        return f"{masked_local}{at}{handle}"

    if name == "ip_address":
        ip_ver = detection.metadata.get("ip_version", 4)
        if ip_ver == 4:
            parts = value.split(".")
            return f"***.***.***.{parts[-1]}"
        # IPv6: keep last group
        return "****:****:****:****:****:****:****:" + value.split(":")[-1]

    if name == "aadhaar":
        # Keep last 4 digits, preserve original spacing/hyphen pattern
        digits = re.sub(r"[\s\-]", "", value)
        visible = digits[-4:]
        # Rebuild in same format
        sep = " " if " " in value else ("-" if "-" in value else "")
        if sep:
            return f"XXXX{sep}XXXX{sep}{visible}"
        return f"XXXX XXXX {visible}"

    if name == "pan":
        # Keep last 5 chars (4 digits + check letter)
        return "XXXXX" + value[-5:]

    if name == "credit_card":
        digits = re.sub(r"[\s\-]", "", value)
        sep = " " if " " in value else ("-" if "-" in value else "")
        visible = digits[-4:]
        if sep:
            return f"XXXX{sep}XXXX{sep}XXXX{sep}{visible}"
        return "XXXX XXXX XXXX " + visible

    keep = _PARTIAL_KEEP.get(name, 4)
    if keep == 0:
        return "X" * len(value)
    mask_len = max(0, len(value) - keep)
    return "*" * mask_len + value[-keep:]


def _mask_full(detection: Detection) -> str:
    """Replace the entire value with a descriptive redaction tag."""
    return _FULL_TAGS.get(detection.detector_name, "[REDACTED]")


def _mask_hash(detection: Detection) -> str:
    """Replace value with its SHA-256 hex digest (first 16 chars for readability)."""
    digest = hashlib.sha256(detection.value.encode()).hexdigest()
    return f"[HASH:{digest[:16]}]"


_MASKERS = {
    "partial": _mask_partial,
    "full": _mask_full,
    "hash": _mask_hash,
}


def mask_text(
    text: str,
    mode: MaskMode = "partial",
    detectors: list[BaseDetector] | None = None,
) -> str:
    """
    Detect and mask all PII in *text*.

    Parameters
    ----------
    text:
        The input string to scan and mask.
    mode:
        One of ``"partial"`` (default), ``"full"``, or ``"hash"``.
    detectors:
        Custom list of detectors.  Defaults to all built-in detectors.

    Returns
    -------
    str
        The masked version of *text*.
    """
    if mode not in _MASKERS:
        raise ValueError(
            f"Unknown masking mode {mode!r}. "
            f"Valid modes: {list(_MASKERS)}"
        )

    active_detectors = detectors or DEFAULT_DETECTORS
    masker_fn = _MASKERS[mode]

    # Collect all detections across all detectors
    all_detections: list[Detection] = []
    for detector in active_detectors:
        try:
            found = detector.detect(text)
            all_detections.extend(found)
            if found:
                logger.debug(
                    "Detector %r found %d occurrence(s)", detector.name, len(found)
                )
        except Exception as exc:  # pragma: no cover
            logger.warning("Detector %r raised an error: %s", detector.name, exc)

    if not all_detections:
        return text

    # Sort by start position, resolve overlaps (longest match wins)
    all_detections.sort(key=lambda d: (d.start, -(d.end - d.start)))
    non_overlapping = _resolve_overlaps(all_detections)

    # Build result by replacing spans from right to left (preserve indices)
    result = text
    for detection in reversed(non_overlapping):
        replacement = masker_fn(detection)
        result = result[: detection.start] + replacement + result[detection.end:]

    return result


def _resolve_overlaps(detections: list[Detection]) -> list[Detection]:
    """Remove overlapping detections, keeping the one with the largest span."""
    if not detections:
        return []
    resolved: list[Detection] = [detections[0]]
    for current in detections[1:]:
        prev = resolved[-1]
        if current.start < prev.end:
            # Overlap: keep whichever is longer
            if (current.end - current.start) > (prev.end - prev.start):
                resolved[-1] = current
            # else keep prev (do nothing)
        else:
            resolved.append(current)
    return resolved
