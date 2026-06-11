"""Tests for CreditCard, IFSC, and IPAddress detectors."""

import pytest

from datacloak.detectors.credit_card import CreditCardDetector, _luhn_check
from datacloak.detectors.ifsc import IFSCDetector
from datacloak.detectors.ip_address import IPAddressDetector
from datacloak.detectors.upi import UPIDetector


# ---------------------------------------------------------------------------
# Credit Card
# ---------------------------------------------------------------------------


class TestCreditCardDetector:
    @pytest.fixture()
    def detector(self):
        return CreditCardDetector()

    def test_luhn_valid(self):
        assert _luhn_check("4111111111111111") is True

    def test_luhn_invalid(self):
        assert _luhn_check("4111111111111112") is False

    def test_visa_card(self, detector):
        result = detector.detect("Card: 4111111111111111")
        assert len(result) == 1

    def test_mastercard(self, detector):
        result = detector.detect("5500005555555559")
        assert len(result) == 1

    def test_amex(self, detector):
        result = detector.detect("378282246310005")
        assert len(result) == 1

    def test_space_separated(self, detector):
        result = detector.detect("4111 1111 1111 1111")
        assert len(result) == 1

    def test_hyphen_separated(self, detector):
        result = detector.detect("4111-1111-1111-1111")
        assert len(result) == 1

    def test_invalid_fails_luhn(self, detector):
        result = detector.detect("4111111111111112")
        assert len(result) == 0

    def test_name(self, detector):
        assert detector.name == "credit_card"


# ---------------------------------------------------------------------------
# IFSC
# ---------------------------------------------------------------------------


class TestIFSCDetector:
    @pytest.fixture()
    def detector(self):
        return IFSCDetector()

    @pytest.mark.parametrize(
        "ifsc",
        [
            "HDFC0001234",
            "SBIN0005943",
            "ICIC0000205",
            "UTIB0000001",
        ],
    )
    def test_valid_ifsc(self, detector, ifsc):
        result = detector.detect(ifsc)
        assert len(result) == 1

    def test_invalid_fifth_char_not_zero(self, detector):
        result = detector.detect("HDFC1001234")
        assert len(result) == 0

    def test_invalid_length(self, detector):
        result = detector.detect("HDFC001234")  # only 10 chars
        assert len(result) == 0

    def test_lowercase_input(self, detector):
        result = detector.detect("ifsc: hdfc0001234")
        assert len(result) == 1

    def test_name(self, detector):
        assert detector.name == "ifsc"


# ---------------------------------------------------------------------------
# IP Address
# ---------------------------------------------------------------------------


class TestIPAddressDetector:
    @pytest.fixture()
    def detector(self):
        return IPAddressDetector()

    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.254.1",
            "8.8.8.8",
        ],
    )
    def test_valid_ipv4(self, detector, ip):
        result = detector.detect(ip)
        assert len(result) == 1
        assert result[0].metadata["ip_version"] == 4

    def test_invalid_octet_too_large(self, detector):
        result = detector.detect("999.168.1.1")
        assert len(result) == 0

    def test_ipv4_in_text(self, detector):
        result = detector.detect("Server at 10.0.0.1 is down")
        assert len(result) == 1

    def test_ipv6_loopback(self, detector):
        result = detector.detect("Connect to ::1 for localhost")
        assert len(result) == 1

    def test_ipv6_full(self, detector):
        result = detector.detect("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert len(result) == 1
        assert result[0].metadata["ip_version"] == 6

    def test_name(self, detector):
        assert detector.name == "ip_address"
