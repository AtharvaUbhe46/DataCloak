"""
DataCloak file scanning module.

Supports scanning of text files, CSV files, and log files.
Designed with an extensible FileHandler interface for adding new formats
(e.g. PDF, DOCX, XLSX) without modifying core logic.
"""

from __future__ import annotations

import csv
import io
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .detectors import DEFAULT_DETECTORS, BaseDetector
from .scanner import ScanResult, scan_text

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------


@dataclass
class FileFinding:
    """A single PII finding within a file."""

    file_path: str
    line_number: int | None
    column_name: str | None
    pii_type: str
    value: str

    def __repr__(self) -> str:
        loc = f"line={self.line_number}" if self.line_number else "inline"
        return f"FileFinding({self.pii_type}={self.value!r} @{self.file_path}:{loc})"


@dataclass
class FileScanResult:
    """Aggregated results for a full file scan."""

    file_path: str
    findings: list[FileFinding] = field(default_factory=list)
    error: str | None = None

    # ------------------------------------------------------------------

    @property
    def summary(self) -> dict[str, int]:
        """Count of findings per PII type."""
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.pii_type] = counts.get(f.pii_type, 0) + 1
        return counts

    @property
    def by_type(self) -> dict[str, list[str]]:
        """Values grouped by PII type."""
        grouped: dict[str, list[str]] = {}
        for f in self.findings:
            grouped.setdefault(f.pii_type, []).append(f.value)
        return grouped

    def __bool__(self) -> bool:
        return bool(self.findings)


# ---------------------------------------------------------------------------
# Handler interface
# ---------------------------------------------------------------------------


class FileHandler(ABC):
    """Abstract base class for file format handlers."""

    #: File extensions this handler supports (lowercase, with dot)
    extensions: tuple[str, ...] = ()

    @abstractmethod
    def extract_chunks(self, path: Path) -> Iterator[tuple[int | None, str | None, str]]:
        """
        Yield ``(line_number, column_name, text_chunk)`` tuples from *path*.

        ``line_number`` and ``column_name`` may be ``None`` for formats
        without meaningful line/column structure.
        """


class PlainTextHandler(FileHandler):
    """Handles ``.txt``, ``.log``, ``.md``, ``.rst`` and similar text files."""

    extensions = (".txt", ".log", ".md", ".rst", ".csv.bak", "")

    def extract_chunks(
        self, path: Path
    ) -> Iterator[tuple[int | None, str | None, str]]:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                yield lineno, None, line.rstrip("\n")


class CSVHandler(FileHandler):
    """Handles ``.csv`` files, scanning each cell individually."""

    extensions = (".csv",)

    def extract_chunks(
        self, path: Path
    ) -> Iterator[tuple[int | None, str | None, str]]:
        with path.open(newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for rownum, row in enumerate(reader, start=2):  # 1-indexed, header = 1
                for col_name, cell_value in row.items():
                    if cell_value:
                        yield rownum, col_name, cell_value


# ---------------------------------------------------------------------------
# Handler registry
# ---------------------------------------------------------------------------


_HANDLER_REGISTRY: list[FileHandler] = [
    CSVHandler(),
    PlainTextHandler(),
]


def register_handler(handler: FileHandler) -> None:
    """
    Register a custom file handler.

    The handler is inserted at the front of the registry so it takes
    precedence over built-in handlers for its declared extensions.

    Example::

        from datacloak.file_scanner import register_handler, FileHandler

        class PDFHandler(FileHandler):
            extensions = (".pdf",)

            def extract_chunks(self, path):
                # ... extract text from PDF
                yield None, None, text_content

        register_handler(PDFHandler())
    """
    _HANDLER_REGISTRY.insert(0, handler)


def _get_handler(path: Path) -> FileHandler:
    suffix = path.suffix.lower()
    for handler in _HANDLER_REGISTRY:
        if suffix in handler.extensions:
            return handler
    # Fallback to plain text
    return PlainTextHandler()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_file(
    file_path: str | Path,
    detectors: list[BaseDetector] | None = None,
) -> FileScanResult:
    """
    Scan a file for PII and return structured findings.

    Parameters
    ----------
    file_path:
        Path to the file to scan.  Supports ``.txt``, ``.log``, ``.csv``.
    detectors:
        Custom detector list.  Defaults to all built-in detectors.

    Returns
    -------
    :class:`FileScanResult`
        Contains all :class:`FileFinding` instances and a summary.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    """
    path = Path(file_path)
    result = FileScanResult(file_path=str(path))

    if not path.exists():
        result.error = f"File not found: {path}"
        logger.error(result.error)
        raise FileNotFoundError(result.error)

    handler = _get_handler(path)
    active_detectors = detectors or DEFAULT_DETECTORS

    try:
        for line_no, col_name, chunk in handler.extract_chunks(path):
            found: ScanResult = scan_text(chunk, detectors=active_detectors)
            for pii_type, values in found.items():
                for val in values:
                    result.findings.append(
                        FileFinding(
                            file_path=str(path),
                            line_number=line_no,
                            column_name=col_name,
                            pii_type=pii_type,
                            value=val,
                        )
                    )
    except Exception as exc:
        result.error = str(exc)
        logger.exception("Error scanning file %s: %s", path, exc)

    logger.info(
        "Scanned %s — %d finding(s) across %d PII type(s)",
        path.name,
        len(result.findings),
        len(result.summary),
    )
    return result


def mask_file(
    input_path: str | Path,
    output_path: str | Path | None = None,
    mode: str = "partial",
    detectors: list[BaseDetector] | None = None,
) -> Path:
    """
    Mask all PII in a plain-text file and write the result.

    Parameters
    ----------
    input_path:
        Source file path.
    output_path:
        Destination path.  Defaults to ``<input>.masked<ext>``.
    mode:
        Masking mode (``"partial"``, ``"full"``, ``"hash"``).
    detectors:
        Custom detectors.

    Returns
    -------
    Path
        The path of the masked output file.
    """
    from .masker import mask_text  # local import to avoid circulars

    src = Path(input_path)
    if output_path is None:
        dst = src.with_stem(src.stem + ".masked")
    else:
        dst = Path(output_path)

    content = src.read_text(encoding="utf-8", errors="replace")
    masked = mask_text(content, mode=mode, detectors=detectors)
    dst.write_text(masked, encoding="utf-8")
    logger.info("Masked file written to %s", dst)
    return dst
