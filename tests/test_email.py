"""Tests for EmailDetector."""

import pytest

from datacloak.detectors.email import EmailDetector


@pytest.fixture()
def detector() -> EmailDetector:
    return EmailDetector()


class TestEmailDetection:
    @pytest.mark.parametrize(
        "address",
        [
            "john@gmail.com",
            "john.doe@example.co.in",
            "user+tag@subdomain.company.org",
            "firstname.lastname@company.com",
            "alice123@hotmail.com",
        ],
    )
    def test_valid_emails(self, detector, address):
        result = detector.detect(address)
        assert len(result) == 1
        assert result[0].value == address

    @pytest.mark.parametrize(
        "bad",
        [
            "@nodomain.com",
            "noatsign.com",
            "user@",
            "double..dot@example.com",
        ],
    )
    def test_invalid_emails(self, detector, bad):
        result = detector.detect(bad)
        assert len(result) == 0

    def test_multiple_emails(self, detector):
        text = "Contact alice@example.com or bob@example.org for support"
        result = detector.detect(text)
        assert len(result) == 2
        values = {d.value for d in result}
        assert "alice@example.com" in values
        assert "bob@example.org" in values

    def test_email_in_sentence(self, detector):
        result = detector.detect("Send invoice to billing@acme.com please.")
        assert len(result) == 1
        assert result[0].value == "billing@acme.com"

    def test_name(self, detector):
        assert detector.name == "email"

    def test_detection_span(self, detector):
        text = "email: test@example.com here"
        result = detector.detect(text)
        assert len(result) == 1
        assert text[result[0].start: result[0].end] == "test@example.com"
