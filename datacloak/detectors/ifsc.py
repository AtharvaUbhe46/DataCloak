"""Detector for Indian Financial System Code (IFSC)."""

from __future__ import annotations

import re

from .base import BaseDetector, Detection


class IFSCDetector(BaseDetector):
    """
    Detects Indian Financial System Codes (IFSC).

    Format: ``AAAA0XXXXXX``
        - First 4 characters: Bank code (uppercase alpha)
        - 5th character: Always ``0`` (zero)
        - Last 6 characters: Branch code (alphanumeric)

    Examples:
        - ``HDFC0001234``
        - ``SBIN0005943``
        - ``ICIC0000205``
    """

    name = "ifsc"
    description = "Indian Financial System Code (IFSC)"

    _pattern: re.Pattern = re.compile(
        r"\b([A-Z]{4}0[A-Z0-9]{6})\b"
    )

    def _validate(self, value: str) -> bool:
        if len(value) != 11:
            return False
        if value[4] != "0":
            return False
        if not value[:4].isalpha():
            return False
        if not value[5:].isalnum():
            return False
        return True

    def detect(self, text: str) -> list[Detection]:
        upper = text.upper()
        results: list[Detection] = []
        for match in self._pattern.finditer(upper):
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
