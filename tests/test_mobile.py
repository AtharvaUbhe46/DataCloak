"""Tests for MobileDetector."""

import pytest

from datacloak.detectors.mobile import MobileDetector


@pytest.fixture()
def detector() -> MobileDetector:
    return MobileDetector()


class TestMobileDetection:
    @pytest.mark.parametrize(
        "number",
        [
            "9876543210",
            "8765432109",
            "7654321098",
            "6543210987",
        ],
    )
    def test_valid_10_digit(self, detector, number):
        result = detector.detect(number)
        assert len(result) == 1

    def test_with_country_code_plus91(self, detector):
        result = detector.detect("+91 9876543210")
        assert len(result) == 1

    def test_with_country_code_0091(self, detector):
        result = detector.detect("0091 9876543210")
        assert len(result) == 1

    def test_with_country_code_91_hyphen(self, detector):
        result = detector.detect("91-9876543210")
        assert len(result) == 1

    def test_invalid_starts_with_5(self, detector):
        result = detector.detect("5876543210")
        assert len(result) == 0

    def test_invalid_starts_with_0(self, detector):
        result = detector.detect("0876543210")
        assert len(result) == 0

    def test_invalid_too_short(self, detector):
        result = detector.detect("987654321")  # 9 digits
        assert len(result) == 0

    def test_multiple_numbers(self, detector):
        text = "Call 9876543210 or 8765432109 for more info"
        result = detector.detect(text)
        assert len(result) == 2

    def test_name(self, detector):
        assert detector.name == "phone"

    def test_in_sentence(self, detector):
        result = detector.detect("Please reach Rahul on 9988776655 at your convenience.")
        assert len(result) == 1
