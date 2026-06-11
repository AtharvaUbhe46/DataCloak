"""
Base detector interface for DataCloak PII detection framework.
All custom detectors must subclass BaseDetector.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Iterator


@dataclass(frozen=True)
class Detection:
    """Represents a single PII detection result."""

    detector_name: str
    value: str
    start: int
    end: int
    confidence: float = 1.0
    metadata: dict = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"Detection(type={self.detector_name!r}, value={self.value!r}, "
            f"span=({self.start}, {self.end}), confidence={self.confidence:.2f})"
        )


class BaseDetector(ABC):
    """
    Abstract base class for all PII detectors.

    Subclass this and implement :meth:`detect` to create a pluggable detector.

    Attributes:
        name: Unique identifier for this detector (e.g. ``"email"``).
        description: Human-readable description of what this detector finds.
    """

    name: str = ""
    description: str = ""

    # Optional compiled regex — subclasses may set this to get detect() for free.
    _pattern: re.Pattern | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, text: str) -> list[Detection]:
        """
        Detect all PII occurrences in *text*.

        Returns a list of :class:`Detection` instances sorted by position.
        The default implementation uses :attr:`_pattern` if set.
        Subclasses may override for more complex logic.
        """
        if self._pattern is None:
            raise NotImplementedError(
                f"{self.__class__.__name__} must implement detect() "
                "or set _pattern."
            )
        results: list[Detection] = []
        for match in self._pattern.finditer(text):
            if self._validate(match.group()):
                results.append(
                    Detection(
                        detector_name=self.name,
                        value=match.group(),
                        start=match.start(),
                        end=match.end(),
                        confidence=self._confidence(match.group()),
                    )
                )
        return results

    def detect_iter(self, text: str) -> Iterator[Detection]:
        """Lazy iterator variant of :meth:`detect`."""
        yield from self.detect(text)

    # ------------------------------------------------------------------
    # Optional hooks
    # ------------------------------------------------------------------

    def _validate(self, value: str) -> bool:  # noqa: ARG002
        """Secondary validation hook.  Return ``False`` to reject a regex match."""
        return True

    def _confidence(self, value: str) -> float:  # noqa: ARG002
        """Return a confidence score in [0, 1] for the detected value."""
        return 1.0

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"
