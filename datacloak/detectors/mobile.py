"""Detector for Indian mobile phone numbers."""

from __future__ import annotations

import re

from .base import BaseDetector, Detection

# Valid first digits for Indian mobile numbers (6-9)
_VALID_PREFIXES = frozenset("6789")


class MobileDetector(BaseDetector):
    """
    Detects Indian mobile phone numbers (10 digits, starting with 6-9).

    Supports formats:
        - ``9876543210``
        - ``+91 9876543210``
        - ``+91-9876543210``
        - ``0091 9876543210``
        - ``91-9876543210``
    """

    name = "phone"
    description = "Indian mobile phone number"

    _pattern: re.Pattern = re.compile(
        r"(?<!\d)"                          # no preceding digit
        r"(?:\+91[\s\-]?|0091[\s\-]?|91[\-]?)?"  # optional country code
        r"([6-9]\d{9})"                     # 10-digit number starting 6-9
        r"(?!\d)"                           # no following digit
    )

    def _validate(self, value: str) -> bool:
        digits = re.sub(r"\D", "", value)
        # Strip country code if present
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        if digits.startswith("0091") and len(digits) == 14:
            digits = digits[4:]
        return len(digits) == 10 and digits[0] in _VALID_PREFIXES

    def detect(self, text: str) -> list[Detection]:
        results: list[Detection] = []
        for match in self._pattern.finditer(text):
            full_match = match.group()
            # Capture only the 10-digit portion for uniform masking
            core = match.group(1)
            if self._validate(core):
                results.append(
                    Detection(
                        detector_name=self.name,
                        value=full_match,
                        start=match.start(),
                        end=match.end(),
                        metadata={"core_number": core},
                    )
                )
        return results
