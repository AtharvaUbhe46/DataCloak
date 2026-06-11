"""Detector for Indian Permanent Account Numbers (PAN)."""

from __future__ import annotations

import re

from .base import BaseDetector, Detection

# Valid fourth-character codes mapping to entity types
_ENTITY_CODES = frozenset("ABCFGHJLPT")
# Fifth character must be the first letter of name/surname
_ALPHA = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")


class PANDetector(BaseDetector):
    """
    Detects Indian PAN card numbers.

    Format: ``AAAAA9999A``
        - 5 uppercase alpha  (first 3: issuing office, 4th: entity type, 5th: holder initial)
        - 4 digits
        - 1 uppercase alpha  (check character)

    Example: ``ABCDE1234F``
    """

    name = "pan"
    description = "Indian Permanent Account Number (PAN)"

    _pattern: re.Pattern = re.compile(
        r"\b([A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z])\b"
    )

    def _validate(self, value: str) -> bool:
        if len(value) != 10:
            return False
        fourth = value[3]
        if fourth not in _ENTITY_CODES:
            return False
        return True

    def detect(self, text: str) -> list[Detection]:
        # Run on uppercase version for matching, but keep original span
        upper_text = text.upper()
        results: list[Detection] = []
        for match in self._pattern.finditer(upper_text):
            raw = text[match.start(): match.end()]
            if self._validate(raw.upper()):
                results.append(
                    Detection(
                        detector_name=self.name,
                        value=raw,
                        start=match.start(),
                        end=match.end(),
                    )
                )
        return results
