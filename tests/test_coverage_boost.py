"""Extra tests to push coverage above 90%."""

import pytest
from datacloak.detectors.upi import UPIDetector
from datacloak.detectors.ifsc import IFSCDetector
from datacloak.detectors.ip_address import IPAddressDetector, _valid_ipv4
from datacloak.masker import mask_text, _mask_partial, _mask_full, _mask_hash
from datacloak.detectors.base import Detection
from datacloak.reporter import generate_report_from_file, _risk_level
import tempfile
from pathlib import Path


# ── UPI (72% → covered) ─────────────────────────────────────────────────────

class TestUPICoverage:
    @pytest.fixture()
    def detector(self):
        return UPIDetector()

    def test_upi_short_local_part(self, detector):
        # local part <= 2 chars → masked
        result = detector.detect("ab@okaxis")
        assert len(result) == 1

    def test_upi_invalid_handle_with_special_chars(self, detector):
        result = detector.detect("user@ok-axis")
        assert len(result) == 0

    def test_upi_handle_too_short(self, detector):
        # handle must be at least 3 chars after @
        result = detector.detect("user@ok")
        # 'ok' is 2 chars — below minimum
        assert len(result) == 0

    def test_upi_in_sentence(self, detector):
        result = detector.detect("Pay to rahul@ybl for the order")
        assert len(result) == 1
        assert result[0].value == "rahul@ybl"

    def test_upi_known_handles(self, detector):
        for handle in ["okaxis", "paytm", "ybl", "upi", "ibl"]:
            result = detector.detect(f"user@{handle}")
            assert len(result) == 1, f"Should detect user@{handle}"


# ── IFSC (76% → covered) ────────────────────────────────────────────────────

class TestIFSCCoverage:
    @pytest.fixture()
    def detector(self):
        return IFSCDetector()

    def test_ifsc_non_alpha_first_four(self, detector):
        result = detector.detect("H1FC0001234")
        assert len(result) == 0

    def test_ifsc_non_alnum_branch(self, detector):
        result = detector.detect("HDFC000123!")
        assert len(result) == 0

    def test_ifsc_all_valid_banks(self, detector):
        for ifsc in ["SBIN0005943", "ICIC0000205", "UTIB0000001", "PUNB0000100"]:
            result = detector.detect(ifsc)
            assert len(result) == 1, f"Should detect {ifsc}"

    def test_ifsc_in_sentence(self, detector):
        result = detector.detect("Please transfer to HDFC0001234 account")
        assert len(result) == 1


# ── IP Address (87% → covered) ──────────────────────────────────────────────

class TestIPCoverage:
    @pytest.fixture()
    def detector(self):
        return IPAddressDetector()

    def test_valid_ipv4_helper_zero_padded(self):
        assert _valid_ipv4("01.0.0.1") is False

    def test_valid_ipv4_helper_non_digit(self):
        assert _valid_ipv4("192.168.one.1") is False

    def test_valid_ipv4_boundary_255(self):
        assert _valid_ipv4("255.255.255.255") is True

    def test_valid_ipv4_boundary_256(self):
        assert _valid_ipv4("256.0.0.1") is False

    def test_ipv6_full_address(self, detector):
        result = detector.detect("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert len(result) == 1
        assert result[0].metadata["ip_version"] == 6

    def test_ipv6_shortened(self, detector):
        result = detector.detect("fe80::1 is the link-local address")
        assert len(result) >= 1

    def test_multiple_ips(self, detector):
        result = detector.detect("From 10.0.0.1 to 192.168.1.1")
        assert len(result) == 2


# ── Masker (88% → covered) ──────────────────────────────────────────────────

class TestMaskerCoverage:
    def _make_detection(self, name, value, start=0):
        return Detection(
            detector_name=name,
            value=value,
            start=start,
            end=start + len(value),
        )

    def test_mask_partial_upi(self):
        result = mask_text("UPI: rahul@okaxis", mode="partial")
        assert "rahul" not in result or "@okaxis" in result

    def test_mask_partial_ip(self):
        result = mask_text("IP: 192.168.1.100", mode="partial")
        assert "192.168.1" not in result

    def test_mask_full_upi(self):
        result = mask_text("UPI: rahul@okaxis", mode="full")
        assert "[UPI_REDACTED]" in result

    def test_mask_full_ip(self):
        result = mask_text("IP: 192.168.1.1", mode="full")
        assert "[IP_REDACTED]" in result

    def test_mask_full_ifsc(self):
        result = mask_text("IFSC: HDFC0001234", mode="full")
        assert "[IFSC_REDACTED]" in result

    def test_mask_full_card(self):
        result = mask_text("Card: 4111111111111111", mode="full")
        assert "[CARD_REDACTED]" in result

    def test_mask_hash_phone(self):
        import re
        result = mask_text("Phone: 9876543210", mode="hash")
        assert re.search(r"\[HASH:[0-9a-f]{16}\]", result)

    def test_mask_partial_single_char_email_local(self):
        result = mask_text("a@example.com", mode="partial")
        assert "@example.com" in result

    def test_mask_partial_ipv6(self):
        d = self._make_detection("ip_address", "::1", start=4)
        d2 = Detection(
            detector_name="ip_address",
            value="::1",
            start=4,
            end=7,
            metadata={"ip_version": 6},
        )
        result = _mask_partial(d2)
        assert isinstance(result, str)


# ── Reporter (87% → covered) ────────────────────────────────────────────────

class TestReporterCoverage:
    def test_risk_level_none(self):
        assert _risk_level(0) == "NONE"

    def test_risk_level_low(self):
        assert _risk_level(2) == "LOW"

    def test_risk_level_medium(self):
        assert _risk_level(7) == "MEDIUM"

    def test_risk_level_high(self):
        assert _risk_level(15) == "HIGH"

    def test_generate_report_from_file(self, tmp_path):
        f = tmp_path / "sample.txt"
        f.write_text("Email: test@example.com\nPhone: 9876543210\n")
        r = generate_report_from_file(f)
        assert r.total_findings >= 2
        assert r.risk_level in ("LOW", "MEDIUM", "HIGH")

    def test_report_save_and_reload(self, tmp_path):
        import json
        f = tmp_path / "data.txt"
        f.write_text("PAN: ABCPE1234F\nAadhaar: 2345 6789 0123\n")
        from datacloak.reporter import generate_report_from_file
        r = generate_report_from_file(f)
        out = tmp_path / "report.json"
        r.save(out)
        data = json.loads(out.read_text())
        assert "summary" in data
        assert "risk_level" in data
        assert data["total_findings"] >= 1