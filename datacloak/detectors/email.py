"""Detector for email addresses."""

from __future__ import annotations

import re

from .base import BaseDetector, Detection

# Common disposable/invalid TLDs to optionally flag (not filtered by default)
_MIN_TLD_LENGTH = 2


class EmailDetector(BaseDetector):
    """
    Detects RFC-5321-compatible email addresses.

    Examples:
        - ``john.doe@example.com``
        - ``user+tag@sub.domain.org``
        - ``first.last@company.co.in``
    """

    name = "email"
    description = "Email address"

    # Permissive but practical email regex
    _pattern: re.Pattern = re.compile(
        r"\b"
        r"([a-zA-Z0-9]"                         # local: must start with alnum
        r"(?:[a-zA-Z0-9._%+\-]{0,62})"          # local: body
        r"[a-zA-Z0-9])"                          # local: must end with alnum (or be 1 char)
        r"@"
        r"([a-zA-Z0-9]"                          # domain
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"  # domain labels
        r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
        r"\.[a-zA-Z]{2,})"                       # TLD
        r"\b",
        re.ASCII,
    )

    def _validate(self, value: str) -> bool:
        if "@" not in value:
            return False
        local, _, domain = value.rpartition("@")
        if not local or not domain:
            return False
        if ".." in local or ".." in domain:
            return False
        tld = domain.rsplit(".", 1)[-1]
        return len(tld) >= _MIN_TLD_LENGTH
