"""Tests for masking modes (partial, full, hash)."""

import hashlib
import re

import pytest

from datacloak import mask
from datacloak.masker import mask_text


SAMPLE_TEXT = """
Aadhaar: 2345 6789 0123
PAN: ABCPE1234F
Email: john@gmail.com
Phone: 9876543210
Card: 4111111111111111
IFSC: HDFC0001234
"""


class TestPartialMasking:
    def test_email_partial(self):
        result = mask("Email: john@gmail.com", mode="partial")
        assert "j***@gmail.com" in result

    def test_phone_partial(self):
        result = mask("Phone: 9876543210", mode="partial")
        assert "******3210" in result

    def test_aadhaar_partial(self):
        result = mask("Aadhaar: 2345 6789 0123", mode="partial")
        assert "0123" in result
        assert "XXXX" in result

    def test_pan_partial(self):
        result = mask("PAN: ABCPE1234F", mode="partial")
        assert "1234F" in result
        assert "XXXXX" in result

    def test_credit_card_partial(self):
        result = mask("Card: 4111111111111111", mode="partial")
        assert "1111" in result

    def test_all_pii_masked(self):
        result = mask(SAMPLE_TEXT, mode="partial")
        # Originals should not appear
        assert "john@gmail.com" not in result
        assert "9876543210" not in result
        assert "2345 6789 0123" not in result

    def test_non_pii_preserved(self):
        result = mask("Hello World: 9876543210", mode="partial")
        assert "Hello World:" in result


class TestFullMasking:
    def test_email_full_tag(self):
        result = mask("Email: john@gmail.com", mode="full")
        assert "[EMAIL_REDACTED]" in result

    def test_phone_full_tag(self):
        result = mask("Phone: 9876543210", mode="full")
        assert "[PHONE_REDACTED]" in result

    def test_aadhaar_full_tag(self):
        result = mask("Aadhaar: 2345 6789 0123", mode="full")
        assert "[AADHAAR_REDACTED]" in result

    def test_pan_full_tag(self):
        result = mask("PAN: ABCPE1234F", mode="full")
        assert "[PAN_REDACTED]" in result

    def test_ifsc_full_tag(self):
        result = mask("IFSC: HDFC0001234", mode="full")
        assert "[IFSC_REDACTED]" in result

    def test_card_full_tag(self):
        result = mask("Card: 4111111111111111", mode="full")
        assert "[CARD_REDACTED]" in result


class TestHashMasking:
    def test_hash_format(self):
        result = mask("Email: john@gmail.com", mode="hash")
        assert re.search(r"\[HASH:[0-9a-f]{16}\]", result)

    def test_hash_deterministic(self):
        text = "Phone: 9876543210"
        assert mask(text, mode="hash") == mask(text, mode="hash")

    def test_hash_different_values(self):
        r1 = mask("Email: john@gmail.com", mode="hash")
        r2 = mask("Email: jane@gmail.com", mode="hash")
        assert r1 != r2

    def test_hash_value_matches_sha256(self):
        # The hash of the email should match SHA256
        email = "john@gmail.com"
        expected_hash = hashlib.sha256(email.encode()).hexdigest()[:16]
        result = mask(f"Email: {email}", mode="hash")
        assert expected_hash in result


class TestInvalidMode:
    def test_invalid_mode_raises(self):
        with pytest.raises(ValueError, match="Unknown masking mode"):
            mask_text("test", mode="bogus")  # type: ignore


class TestEdgeCases:
    def test_empty_string(self):
        assert mask("") == ""

    def test_no_pii_unchanged(self):
        text = "Hello, this is a normal sentence with no PII."
        assert mask(text) == text

    def test_default_mode_is_partial(self):
        result = mask("Phone: 9876543210")
        assert "******3210" in result

    def test_overlapping_handled(self):
        # Text where multiple patterns might overlap — should not crash
        result = mask("9876543210@paytm", mode="full")
        assert isinstance(result, str)
