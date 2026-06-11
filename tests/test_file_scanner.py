"""Tests for file scanning functionality."""

import csv
import tempfile
from pathlib import Path

import pytest

from datacloak.file_scanner import FileScanResult, mask_file, scan_file


@pytest.fixture()
def temp_txt_file(tmp_path: Path) -> Path:
    content = """
Customer Report
===============
Name: John Doe
Email: john.doe@example.com
Phone: 9876543210
Aadhaar: 2345 6789 0123
PAN: ABCPE1234F
Account IFSC: HDFC0001234
"""
    p = tmp_path / "customers.txt"
    p.write_text(content, encoding="utf-8")
    return p


@pytest.fixture()
def temp_csv_file(tmp_path: Path) -> Path:
    rows = [
        {"name": "Alice", "email": "alice@example.com", "phone": "9876543210"},
        {"name": "Bob", "email": "bob@example.org", "phone": "8765432109"},
        {"name": "Charlie", "email": "charlie@company.co.in", "phone": "7654321098"},
    ]
    p = tmp_path / "data.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "email", "phone"])
        writer.writeheader()
        writer.writerows(rows)
    return p


@pytest.fixture()
def clean_txt_file(tmp_path: Path) -> Path:
    p = tmp_path / "clean.txt"
    p.write_text("No PII here. Just plain text.", encoding="utf-8")
    return p


class TestScanFile:
    def test_txt_file_finds_email(self, temp_txt_file):
        result = scan_file(temp_txt_file)
        assert "email" in result.by_type
        assert "john.doe@example.com" in result.by_type["email"]

    def test_txt_file_finds_phone(self, temp_txt_file):
        result = scan_file(temp_txt_file)
        assert "phone" in result.by_type

    def test_txt_file_finds_aadhaar(self, temp_txt_file):
        result = scan_file(temp_txt_file)
        assert "aadhaar" in result.by_type

    def test_txt_file_finds_pan(self, temp_txt_file):
        result = scan_file(temp_txt_file)
        assert "pan" in result.by_type

    def test_csv_file_finds_emails(self, temp_csv_file):
        result = scan_file(temp_csv_file)
        assert "email" in result.by_type
        assert len(result.by_type["email"]) == 3

    def test_csv_file_finds_phones(self, temp_csv_file):
        result = scan_file(temp_csv_file)
        assert "phone" in result.by_type

    def test_findings_have_line_numbers(self, temp_txt_file):
        result = scan_file(temp_txt_file)
        for finding in result.findings:
            assert finding.line_number is not None

    def test_csv_findings_have_column_names(self, temp_csv_file):
        result = scan_file(temp_csv_file)
        email_findings = [f for f in result.findings if f.pii_type == "email"]
        assert all(f.column_name is not None for f in email_findings)

    def test_clean_file_no_findings(self, clean_txt_file):
        result = scan_file(clean_txt_file)
        assert not result.findings
        assert result.summary == {}

    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            scan_file(tmp_path / "nonexistent.txt")

    def test_result_summary(self, temp_txt_file):
        result = scan_file(temp_txt_file)
        assert isinstance(result.summary, dict)
        for k, v in result.summary.items():
            assert isinstance(v, int)
            assert v > 0

    def test_file_scan_result_bool_true(self, temp_txt_file):
        result = scan_file(temp_txt_file)
        assert bool(result) is True

    def test_file_scan_result_bool_false(self, clean_txt_file):
        result = scan_file(clean_txt_file)
        assert bool(result) is False


class TestMaskFile:
    def test_mask_file_creates_output(self, temp_txt_file, tmp_path):
        output = tmp_path / "masked.txt"
        dest = mask_file(temp_txt_file, output_path=output)
        assert dest.exists()

    def test_mask_file_removes_pii(self, temp_txt_file, tmp_path):
        output = tmp_path / "masked.txt"
        mask_file(temp_txt_file, output_path=output, mode="full")
        content = output.read_text(encoding="utf-8")
        assert "john.doe@example.com" not in content
        assert "[EMAIL_REDACTED]" in content

    def test_mask_file_default_output_name(self, temp_txt_file):
        dest = mask_file(temp_txt_file)
        assert dest.exists()
        assert "masked" in dest.stem
        # Cleanup
        dest.unlink()
