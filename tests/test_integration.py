"""Integration tests for the full DataCloak pipeline."""

import pytest

from datacloak import mask, report, scan
from datacloak.detectors.base import BaseDetector, Detection
from datacloak.reporter import generate_report_from_text
from datacloak.scanner import scan_summary, scan_text


FULL_SAMPLE = """
Dear Customer,

Your Aadhaar number 2345 6789 0123 and PAN ABCPE1234F have been recorded.
We will contact you at john.doe@example.com or +91 9876543210.
Your UPI ID user@okaxis has been linked.
Card 4111111111111111 is on file.
Account IFSC: HDFC0001234.
Server IP: 192.168.1.100.
"""


class TestScanIntegration:
    def test_scan_returns_all_types(self):
        result = scan(FULL_SAMPLE)
        assert "aadhaar" in result
        assert "pan" in result
        assert "email" in result
        assert "phone" in result
        assert "credit_card" in result
        assert "ifsc" in result
        assert "ip_address" in result

    def test_scan_values_are_lists(self):
        result = scan(FULL_SAMPLE)
        for values in result.values():
            assert isinstance(values, list)

    def test_scan_empty_text(self):
        assert scan("") == {}

    def test_scan_summary(self):
        summary = scan_summary(FULL_SAMPLE)
        for k, v in summary.items():
            assert isinstance(v, int)
            assert v >= 1


class TestMaskIntegration:
    def test_mask_partial_hides_all_pii(self):
        result = mask(FULL_SAMPLE, mode="partial")
        assert "john.doe@example.com" not in result
        assert "9876543210" not in result
        assert "ABCPE1234F" not in result

    def test_mask_full_tags_present(self):
        result = mask(FULL_SAMPLE, mode="full")
        assert "[EMAIL_REDACTED]" in result
        assert "[PHONE_REDACTED]" in result
        assert "[PAN_REDACTED]" in result

    def test_mask_hash_format(self):
        import re
        result = mask("Email: test@example.com", mode="hash")
        assert re.search(r"\[HASH:[0-9a-f]{16}\]", result)


class TestReportIntegration:
    def test_report_has_required_fields(self):
        r = report(FULL_SAMPLE)
        assert r.total_findings > 0
        assert r.risk_level in ("LOW", "MEDIUM", "HIGH")
        assert isinstance(r.summary, dict)
        assert isinstance(r.details, dict)

    def test_report_to_json_is_valid(self):
        import json
        r = report(FULL_SAMPLE)
        parsed = json.loads(r.to_json())
        assert "total_findings" in parsed
        assert "risk_level" in parsed
        assert "summary" in parsed

    def test_clean_text_risk_none(self):
        r = report("Hello world, no PII here.")
        assert r.risk_level == "NONE"
        assert r.total_findings == 0

    def test_report_save(self, tmp_path):
        r = report("Email: user@example.com")
        dest = tmp_path / "report.json"
        r.save(dest)
        assert dest.exists()
        import json
        data = json.loads(dest.read_text())
        assert data["total_findings"] >= 1


class TestCustomDetector:
    """Verify the extensibility contract."""

    def test_custom_detector_pluggable(self):
        class SSNDetector(BaseDetector):
            name = "us_ssn"
            description = "US Social Security Number"

            import re as _re
            _pattern = _re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

        detector = SSNDetector()
        result = detector.detect("SSN: 123-45-6789")
        assert len(result) == 1
        assert result[0].detector_name == "us_ssn"
        assert result[0].value == "123-45-6789"

    def test_custom_detector_with_scan(self):
        import re

        class PassportDetector(BaseDetector):
            name = "passport"
            description = "Indian Passport Number"
            _pattern = re.compile(r"\b[A-Z]\d{7}\b")

        detectors = [PassportDetector()]
        result = scan_text("Passport: A1234567 issued", detectors=detectors)
        assert "passport" in result
        assert "A1234567" in result["passport"]
