"""Detector for IPv4 and IPv6 addresses."""

from __future__ import annotations

import re

from .base import BaseDetector, Detection


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not (0 <= int(part) <= 255):
            return False
        # Reject zero-padded octets (e.g. 01, 001)
        if len(part) > 1 and part.startswith("0"):
            return False
    return True


class IPAddressDetector(BaseDetector):
    """
    Detects IPv4 and IPv6 addresses.

    IPv4 examples:
        - ``192.168.1.1``
        - ``10.0.0.1``
        - ``172.16.254.1``

    IPv6 examples:
        - ``2001:0db8:85a3:0000:0000:8a2e:0370:7334``
        - ``::1``
        - ``fe80::1``
    """

    name = "ip_address"
    description = "IPv4 or IPv6 address"

    _ipv4_pattern: re.Pattern = re.compile(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    )

    # Simplified IPv6 pattern covering common representations
    _ipv6_pattern: re.Pattern = re.compile(
        r"(?<![:\w])"
        r"((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"    # full
        r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"                   # trailing ::
        r"|:(?::[0-9a-fA-F]{1,4}){1,7}"                   # leading ::
        r"|::)"                                             # loopback ::
        r"(?![:\w])"
    )

    def detect(self, text: str) -> list[Detection]:
        results: list[Detection] = []

        for match in self._ipv4_pattern.finditer(text):
            val = match.group(1)
            if _valid_ipv4(val):
                results.append(
                    Detection(
                        detector_name=self.name,
                        value=val,
                        start=match.start(),
                        end=match.end(),
                        metadata={"ip_version": 4},
                    )
                )

        for match in self._ipv6_pattern.finditer(text):
            val = match.group(1)
            results.append(
                Detection(
                    detector_name=self.name,
                    value=val,
                    start=match.start(),
                    end=match.end(),
                    metadata={"ip_version": 6},
                )
            )

        results.sort(key=lambda d: d.start)
        return results
