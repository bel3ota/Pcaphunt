"""Suspicious data detector for PcapHunt."""

import math
from typing import Any

from pcaphunt.detectors.base import BaseDetector
from pcaphunt.utils import calculate_entropy


class SuspiciousDetector(BaseDetector):
    """Detect suspicious high-entropy or compressed/encrypted data."""

    MIN_SIZE = 64
    ENTROPY_THRESHOLD = 7.5

    @property
    def name(self) -> str:
        return "suspicious"

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect suspicious high-entropy data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data or len(data) < self.MIN_SIZE:
            return results

        entropy = calculate_entropy(data)
        if entropy >= self.ENTROPY_THRESHOLD:
            # Try to guess what it might be
            notes = "High entropy data - possibly compressed or encrypted"
            if data[:2] == b"\x1f\x8b":
                notes = "Likely gzip compressed data"
            elif data[:2] == b"PK":
                notes = "Likely ZIP archive data"
            elif data[:4] == b"\x78\x9c":
                notes = "Likely zlib compressed data"

            results.append(
                self.create_finding(
                    context,
                    original=f"[{len(data)} bytes of high-entropy data]",
                    decoded="",
                    offset=0,
                    confidence=0.85,
                    entropy=round(entropy, 2),
                    notes=notes,
                )
            )

        return results
