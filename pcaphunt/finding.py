"""Normalized finding model for PcapHunt."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """A normalized finding from any detector or protocol extractor.

    This is the single source of truth consumed by all output generators
    (TXT, JSON, HTML).
    """

    type: str
    original: str
    decoded: str | None = None
    packet_numbers: list[int] = field(default_factory=list)
    first_seen_packet: int | None = None
    protocol: str = "Unknown"
    source: str = ""
    destination: str = ""
    offset: int = 0
    confidence: float = 1.0
    severity: str = "info"  # info, low, medium, high, critical
    stream_id: str | None = None
    timestamp: float | None = None
    notes: str = ""
    decoding_steps: list[dict[str, Any]] = field(default_factory=list)
    file_type: str | None = None
    entropy: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    score: int = 0  # 0-100 risk score
    score_reasons: list[str] = field(default_factory=list)
    score_factors: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a plain dictionary for JSON serialization."""
        d: dict[str, Any] = {
            "type": self.type,
            "original": self.original,
            "packet_numbers": self.packet_numbers,
            "first_seen_packet": self.first_seen_packet,
            "protocol": self.protocol,
            "source": self.source,
            "destination": self.destination,
            "offset": self.offset,
            "confidence": self.confidence,
            "severity": self.severity,
            "notes": self.notes,
            "fingerprint": self.fingerprint,
        }
        if self.decoded is not None:
            d["decoded"] = self.decoded
        if self.stream_id is not None:
            d["stream_id"] = self.stream_id
        if self.timestamp is not None:
            d["timestamp"] = self.timestamp
        if self.decoding_steps:
            d["decoding_steps"] = self.decoding_steps
        if self.file_type is not None:
            d["file_type"] = self.file_type
        if self.entropy is not None:
            d["entropy"] = self.entropy
        if self.metadata:
            d["metadata"] = self.metadata
        if self.score > 0:
            d["score"] = self.score
        if self.score_reasons:
            d["score_reasons"] = self.score_reasons
        if self.score_factors:
            d["score_factors"] = self.score_factors
        return d
