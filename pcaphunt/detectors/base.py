"""Base detector class for PcapHunt."""

from abc import ABC, abstractmethod
from typing import Any


class BaseDetector(ABC):
    """Abstract base class for all PcapHunt detectors."""

    def __init__(self, config: dict[str, Any] | None = None):
        """Initialize detector with optional config."""
        self.config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the detector name."""
        ...

    @abstractmethod
    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Run detection on data."""
        ...

    def create_finding(
        self,
        context: dict[str, Any],
        original: str,
        decoded: str | None = None,
        ftype: str | None = None,
        offset: int = 0,
        confidence: float = 1.0,
        severity: str = "info",
        **extra: Any,
    ) -> dict[str, Any]:
        """Create a standardized finding dict."""
        from pcaphunt.utils import stable_fingerprint

        pkt_nums = context.get("packet_numbers", [])
        finding: dict[str, Any] = {
            "type": ftype or self.name,
            "packet_numbers": list(pkt_nums),
            "first_seen_packet": context.get("first_seen_packet", pkt_nums[0] if pkt_nums else None),
            "protocol": context.get("protocol", "Unknown"),
            "source": context.get("source", ""),
            "destination": context.get("destination", ""),
            "offset": offset,
            "original": original,
            "confidence": confidence,
            "severity": severity,
            "timestamp": context.get("timestamp"),
            "stream_id": context.get("stream_id"),
        }
        if decoded is not None:
            finding["decoded"] = decoded
        finding.update(extra)
        finding["fingerprint"] = stable_fingerprint(finding)
        return finding
