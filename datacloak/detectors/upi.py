"""Detector for Indian UPI (Unified Payments Interface) IDs."""

from __future__ import annotations

import re

from .base import BaseDetector, Detection

# Known UPI handles / VPAs used by major providers
_KNOWN_HANDLES = {
    "okaxis", "okhdfcbank", "okicici", "oksbi",
    "ybl", "ibl", "axl", "paytm", "pthdfc", "ptaxis",
    "upi", "apl", "rapl", "waicici", "wahdfcbank",
    "naviaxis", "fbl", "ikwik", "axisbank", "hdfcbank",
    "icici", "sbi", "pnb", "cnrb", "boi", "aubank",
    "kotak", "federal", "indus", "sc", "hsbc",
    "jupiter", "sliceaxis", "fi", "niyoicici",
}


class UPIDetector(BaseDetector):
    """
    Detects Indian UPI Virtual Payment Addresses (VPAs).

    Format: ``<username>@<handle>``

    Examples:
        - ``user@okaxis``
        - ``9876543210@ybl``
        - ``firstname.lastname@paytm``
    """

    name = "upi_id"
    description = "Indian UPI Virtual Payment Address (VPA)"

    _pattern: re.Pattern = re.compile(
        r"\b"
        r"[a-zA-Z0-9._-]{3,256}"
        r"@"
        r"(?:"
        + "|".join(re.escape(h) for h in sorted(_KNOWN_HANDLES))
        + r")"
        r"\b",
        re.IGNORECASE,
    )

    # We want to avoid matching generic email domains like gmail, yahoo, etc.
    _email_domains = frozenset({
        "gmail", "yahoo", "hotmail", "outlook", "icloud",
        "protonmail", "aol", "live", "rediffmail", "ymail",
    })

    def _validate(self, value: str) -> bool:
        if "@" not in value:
            return False
        username, _, handle = value.rpartition("@")
        handle = handle.lower()
        if handle in self._email_domains:
            return False
        if handle not in _KNOWN_HANDLES:
            return False
        if len(username) < 3:
            return False
        return True
