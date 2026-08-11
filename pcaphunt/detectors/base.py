"""Base detector class for PcapHunt."""

from abc import ABC, abstractmethod
from typing import Any


class BaseDetector(ABC):
    """Abstract base class for all PcapHunt detectors."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize detector with optional config.

        Args:
            config: Configuration dictionary.
        """
        self.config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the detector name."""
        ...

    @abstractmethod
    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Run detection on data.

        Args:
            data: Byte string to analyze.
            context: Metadata context dict.

        Returns:
            List of finding dictionaries.
        """
        ...

    def create_finding(
        self,
        context: dict[str, Any],
        original: str,
        decoded: str | None = None,
        ftype: str | None = None,
        offset: int = 0,
        confidence: float = 1.0,
        **extra: Any,
    ) -> dict[str, Any]:
        """Create a standardized finding dict.

        Args:
            context: Metadata context.
            original: Original detected value.
            decoded: Decoded value if applicable.
            ftype: Finding type.
            offset: Byte offset in packet/stream.
            confidence: Confidence score (0-1).
            **extra: Extra fields.

        Returns:
            Finding dictionary.
        """
        from pcaphunt.utils import stable_fingerprint

        finding: dict[str, Any] = {
            "type": ftype or self.name,
            "packet_numbers": context.get("packet_numbers", []),
            "protocol": context.get("protocol", "Unknown"),
            "source": context.get("source", ""),
            "destination": context.get("destination", ""),
            "offset": offset,
            "original": original,
            "confidence": confidence,
        }
        if decoded is not None:
            finding["decoded"] = decoded
        finding.update(extra)
        finding["fingerprint"] = stable_fingerprint(finding)
        return finding
