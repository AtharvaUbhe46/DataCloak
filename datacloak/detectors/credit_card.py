"""Detector for credit/debit card numbers with Luhn algorithm validation."""

from __future__ import annotations

import re

from .base import BaseDetector, Detection


def _luhn_check(number: str) -> bool:
    """Return True if *number* (digits only) passes the Luhn algorithm."""
    digits = [int(d) for d in reversed(number)]
    total = 0
    for i, digit in enumerate(digits):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


class CreditCardDetector(BaseDetector):
    """
    Detects credit and debit card numbers (13–19 digits).

    Validates using the Luhn algorithm to eliminate false positives.

    Supports formats:
        - ``4111111111111111``           (no separator)
        - ``4111 1111 1111 1111``        (space-separated)
        - ``4111-1111-1111-1111``        (hyphen-separated)

    Covers: Visa, Mastercard, Amex, RuPay, Discover, JCB, etc.
    """

    name = "credit_card"
    description = "Credit/debit card number"

    _pattern: re.Pattern = re.compile(
        r"\b"
        r"(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,4}"  # 13-16 digit
        r"(?:[\s\-]?\d{1,3})?)"                             # up to 19 digits
        r"\b"
    )

    def _validate(self, value: str) -> bool:
        digits = re.sub(r"[\s\-]", "", value)
        if not (13 <= len(digits) <= 19):
            return False
        if not digits.isdigit():
            return False
        return _luhn_check(digits)

    def _confidence(self, value: str) -> float:
        # Luhn-validated numbers get high confidence
        digits = re.sub(r"[\s\-]", "", value)
        if _luhn_check(digits):
            return 0.95
        return 0.5
