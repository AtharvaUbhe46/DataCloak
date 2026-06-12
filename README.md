# DataCloak 🔒

> **Privacy protection for Python applications** — detect and mask PII in text, logs, files, and data pipelines.

[![PyPI version](https://img.shields.io/pypi/v/datacloak.svg)](https://pypi.org/project/datacloak/)
[![Python](https://img.shields.io/pypi/pyversions/datacloak.svg)](https://pypi.org/project/datacloak/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/datacloak/datacloak/actions/workflows/ci.yml/badge.svg)](https://github.com/datacloak/datacloak/actions)
[![Coverage](https://img.shields.io/codecov/c/github/datacloak/datacloak)](https://codecov.io/gh/datacloak/datacloak)

---

DataCloak is a production-ready Python library for **automatically detecting and masking Personally Identifiable Information (PII)** — built for India-first compliance use cases (Aadhaar, PAN, UPI) while covering universal types like email and credit cards.

## ✨ Features

| Capability | Description |
|---|---|
| **8 built-in detectors** | Aadhaar, PAN, Mobile, Email, UPI ID, Credit Card (Luhn), IFSC, IPv4/IPv6 |
| **3 masking modes** | `partial` (keep trailing chars), `full` (redaction tags), `hash` (SHA-256) |
| **File scanning** | `.txt`, `.log`, `.csv` — extensible to PDF, DOCX, and more |
| **Structured scan** | Returns findings dict without modifying original text |
| **JSON reports** | Risk-level classified reports with per-type counts |
| **CLI** | `datacloak scan / mask / report` commands |
| **Pluggable detectors** | Subclass `BaseDetector` to add your own PII types |

---

## 🚀 Installation

```bash
pip install datacloak
```

Requires Python 3.11+.

---

## ⚡ Quick Start

```python
from datacloak import mask, scan

text = """
Aadhaar: 2345 6789 0123
PAN: ABCPE1234F
Email: alice@example.com
Phone: 9876543210
"""

# Partial masking (default) — keeps trailing characters visible
print(mask(text))
```

**Output:**
```
Aadhaar: XXXX XXXX 0123
PAN: XXXXX1234F
Email: a***@example.com
Phone: ******3210
```

---

## 📖 Usage Guide

### 1. Masking Modes

```python
from datacloak import mask

text = "Contact: alice@example.com | Phone: 9876543210"

# Partial — show trailing characters (default)
mask(text, mode="partial")
# → 'Contact: a***@example.com | Phone: ******3210'

# Full — replace with descriptive redaction tags
mask(text, mode="full")
# → 'Contact: [EMAIL_REDACTED] | Phone: [PHONE_REDACTED]'

# Hash — SHA-256 digest (deterministic, reversible with original)
mask(text, mode="hash")
# → 'Contact: [HASH:142d78e466cacab3] | Phone: [HASH:7619ee8cea49187f]'
```

### 2. Scan Without Masking

```python
from datacloak import scan

findings = scan("Send invoice to billing@acme.com, call 9876543210")
print(findings)
# {
#   "email": ["billing@acme.com"],
#   "phone": ["9876543210"]
# }
```

### 3. File Scanning

```python
from datacloak import scan_file

# Scan a plain text or log file
result = scan_file("application.log")

# Scan a CSV (each cell is scanned individually)
result = scan_file("customers.csv")

print(result.summary)
# {"email": 142, "phone": 38, "aadhaar": 5}

print(result.findings[0])
# FileFinding(email='alice@example.com' @customers.csv:line=2)
```

### 4. Report Generation

```python
from datacloak import report

r = report(text, source_label="user_input")
print(r.to_json())
```

```json
{
  "generated_at": "2025-06-01T10:23:00+00:00",
  "source": "user_input",
  "total_findings": 4,
  "summary": {
    "aadhaar": 1,
    "email": 1,
    "phone": 1,
    "pan": 1
  },
  "details": { ... },
  "risk_level": "MEDIUM"
}
```

Save to disk:
```python
r.save("pii_report.json")
```

---

## 🖥️ Command-Line Interface

DataCloak ships a full CLI via `datacloak`:

```bash
# Scan a file and display findings as a table
datacloak scan customers.txt

# Scan with JSON output
datacloak scan --format json customers.txt

# Mask a file (writes customers.masked.txt by default)
datacloak mask customers.txt

# Mask with full-redaction mode, specify output file
datacloak mask customers.txt --mode full --output clean.txt

# Print masked output to stdout (pipe-friendly)
datacloak mask customers.txt --stdout | grep "REDACTED"

# Generate a JSON report
datacloak report customers.txt

# Save report to file
datacloak report customers.txt --output report.json

# Verbose logging
datacloak -v scan customers.txt
```

---

## 🔌 Writing a Custom Detector

DataCloak's detector framework is designed for extension. Subclass `BaseDetector`, set `_pattern`, and optionally override `_validate()`:

```python
import re
from datacloak.detectors import BaseDetector, Detection
from datacloak import scan

class PassportDetector(BaseDetector):
    name = "indian_passport"
    description = "Indian Passport Number (A-Z followed by 7 digits)"
    _pattern = re.compile(r"\b[A-Z]\d{7}\b")

# Use alongside built-in detectors
from datacloak.detectors import DEFAULT_DETECTORS

my_detectors = DEFAULT_DETECTORS + [PassportDetector()]
findings = scan("Passport: A1234567", detectors=my_detectors)
# {"indian_passport": ["A1234567"]}
```

### Adding a new file format

```python
from datacloak.file_scanner import FileHandler, register_handler
from pathlib import Path

class PDFHandler(FileHandler):
    extensions = (".pdf",)

    def extract_chunks(self, path: Path):
        # Use any PDF library (pdfplumber, PyMuPDF, etc.)
        import pdfplumber
        with pdfplumber.open(path) as pdf:
            for page_num, page in enumerate(pdf.pages, start=1):
                text = page.extract_text() or ""
                yield page_num, None, text

register_handler(PDFHandler())

# Now scan_file("document.pdf") works automatically
```

---

## 🕵️ Supported PII Types

| Detector | Example | Validation |
|---|---|---|
| `aadhaar` | `2345 6789 0123` | 12 digits, starts 2-9, space/hyphen/plain |
| `pan` | `ABCPE1234F` | AAAAA9999A format, valid entity code |
| `phone` | `9876543210`, `+91 9876543210` | 10 digits, starts 6-9, optional country code |
| `email` | `alice@example.com` | RFC-5321 compliant |
| `upi_id` | `user@okaxis` | VPA format, non-email handles only |
| `credit_card` | `4111 1111 1111 1111` | 13-19 digits, Luhn algorithm validated |
| `ifsc` | `HDFC0001234` | 4-alpha + 0 + 6-alphanumeric |
| `ip_address` | `192.168.1.1`, `::1` | IPv4 (range-validated) and IPv6 |

---

## 🧪 Running Tests

```bash
# Clone the repo
git clone https://github.com/datacloak/datacloak.git
cd datacloak

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=datacloak --cov-report=term-missing
```

Target: **≥ 90% coverage**.

---

**Design principles applied:**
- Single Responsibility — each detector, masker, scanner, and reporter is self-contained
- Open/Closed — extend via `BaseDetector` or `FileHandler` without modifying core
- Liskov Substitution — any `BaseDetector` subclass drops in transparently
- Dependency Injection — all public functions accept `detectors=` for testability
- Logging — structured `logging` throughout, silent by default (NullHandler)

---

## 📦 Publishing to PyPI

See [PUBLISHING.md](PUBLISHING.md) for a complete step-by-step guide.

```bash
# Quick summary
pip install build twine
python -m build
twine upload dist/*
```

---

## 📄 License

[MIT License](LICENSE) — Copyright © 2025 DataCloak Contributors.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Please read the contributing guide and open a pull request.

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-detector`
3. Write your code and tests
4. Run `pytest` and ensure coverage stays ≥ 90%
5. Open a pull request

---

*DataCloak — because privacy is not optional.*
