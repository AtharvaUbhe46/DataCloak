"""Tests for AadhaarDetector."""

import pytest

from datacloak.detectors.aadhaar import AadhaarDetector


@pytest.fixture()
def detector() -> AadhaarDetector:
    return AadhaarDetector()


class TestAadhaarDetection:
    def test_space_separated(self, detector):
        result = detector.detect("Aadhaar: 2345 6789 0123")
        assert len(result) == 1
        assert result[0].value == "2345 6789 0123"

    def test_hyphen_separated(self, detector):
        result = detector.detect("ID: 3456-7890-1234")
        assert len(result) == 1
        assert result[0].value == "3456-7890-1234"

    def test_no_separator(self, detector):
        result = detector.detect("234567890123")
        assert len(result) == 1
        assert result[0].value == "234567890123"

    def test_invalid_starts_with_0(self, detector):
        result = detector.detect("0234 5678 9012")
        assert len(result) == 0

    def test_invalid_starts_with_1(self, detector):
        result = detector.detect("1234 5678 9012")
        assert len(result) == 0

    def test_multiple_in_text(self, detector):
        text = "A: 2345 6789 0123 and B: 3456 7890 1234"
        result = detector.detect(text)
        assert len(result) == 2

    def test_too_short(self, detector):
        result = detector.detect("2345 6789 012")
        assert len(result) == 0

    def test_too_long(self, detector):
        result = detector.detect("2345 6789 01234")
        assert len(result) == 0

    def test_name(self, detector):
        assert detector.name == "aadhaar"

    def test_embedded_in_sentence(self, detector):
        result = detector.detect("Customer aadhaar is 2234567890123 please verify")
        # 13 digits - should not match
        assert len(result) == 0

    def test_valid_aadhaar_in_sentence(self, detector):
        result = detector.detect("Your aadhaar 2234 5678 9012 has been verified")
        assert len(result) == 1
