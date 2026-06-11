"""Tests for PANDetector."""

import pytest

from datacloak.detectors.pan import PANDetector


@pytest.fixture()
def detector() -> PANDetector:
    return PANDetector()


class TestPANDetection:
    def test_valid_individual_pan(self, detector):
        result = detector.detect("PAN: ABCPE1234F")
        assert len(result) == 1
        assert result[0].value.upper() == "ABCPE1234F"

    def test_valid_company_pan(self, detector):
        result = detector.detect("Company PAN: AAACB1234C")
        assert len(result) == 1

    def test_lowercase_input(self, detector):
        result = detector.detect("pan: abcpe1234f")
        assert len(result) == 1
        assert result[0].value.upper() == "ABCPE1234F"

    def test_invalid_fourth_char(self, detector):
        # 4th char 'D' is not a valid entity code
        result = detector.detect("ABCDE1234F")
        assert len(result) == 0

    def test_invalid_format_wrong_length(self, detector):
        result = detector.detect("ABCPE12345F")  # 11 chars
        assert len(result) == 0

    def test_multiple_pans(self, detector):
        text = "PAN1: ABCPE1234F, PAN2: XYZPQ9876G"
        result = detector.detect(text)
        assert len(result) == 2

    def test_name(self, detector):
        assert detector.name == "pan"

    def test_valid_entity_codes(self, detector):
        valid_codes = list("ABCFGHJLPT")
        for code in valid_codes:
            pan = f"ABC{code}E1234F"
            result = detector.detect(pan)
            assert len(result) == 1, f"Expected detection for entity code {code}"

    def test_pan_within_sentence(self, detector):
        result = detector.detect("Please submit your PAN card ABCPE1234F for KYC")
        assert len(result) == 1
