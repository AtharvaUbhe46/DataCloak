# Changelog

All notable changes to DataCloak will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.1] — 2025-06-01

### Added
- Initial release of DataCloak
- Built-in detectors: Aadhaar, PAN, Indian Mobile, Email, UPI ID, Credit Card (Luhn-validated), IFSC, IPv4/IPv6
- Three masking modes: `partial`, `full`, `hash`
- `scan()` API for structured PII detection without modification
- `scan_file()` supporting `.txt`, `.log`, and `.csv` files
- Extensible `FileHandler` interface for adding new file format support
- JSON report generation with risk-level classification
- `datacloak` CLI with `scan`, `mask`, and `report` commands
- Custom detector framework via `BaseDetector`
- Full pytest test suite (>85% coverage)
- Typed codebase (PEP 561 compliant)
