"""Detector for Indian Aadhaar numbers (12-digit UIDs)."""

from __future__ import annotations

import re

from .base import BaseDetector, Detection


class AadhaarDetector(BaseDetector):
    """
    Detects Indian Aadhaar numbers.

    Supports formats:
        - ``1234 5678 9012``   (space-separated groups of 4)
        - ``1234-5678-9012``   (hyphen-separated)
        - ``123456789012``     (no separator)

    Validates that the number does not start with 0 or 1 (invalid Aadhaar prefix).
    """

    name = "aadhaar"
    description = "Indian Aadhaar UID (12-digit unique identifier)"

    # Matches 12-digit numbers in groups of 4, with optional space/hyphen separators.
    _pattern: re.Pattern = re.compile(
        r"\b([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})\b"
    )

    def _validate(self, value: str) -> bool:
        digits = re.sub(r"[\s\-]", "", value)
        if len(digits) != 12:
            return False
        # Aadhaar numbers cannot start with 0 or 1
        if digits[0] in ("0", "1"):
            return False
        return True

    def detect(self, text: str) -> list[Detection]:
        results: list[Detection] = []
        for match in self._pattern.finditer(text):
            raw = match.group()
            if self._validate(raw):
                results.append(
                    Detection(
                        detector_name=self.name,
                        value=raw,
                        start=match.start(),
                        end=match.end(),
                        confidence=self._confidence(raw),
                    )
                )
        return results
