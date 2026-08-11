"""Hash detector for PcapHunt."""

import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class HashDetector(BaseDetector):
    """Detect likely hash strings (MD5, SHA1, SHA256, SHA512)."""

    # Lengths: MD5=32, SHA1=40, SHA256=64, SHA512=128
    HASH_RE = re.compile(
        rb"(?:^|[^0-9a-fA-F])"
        rb"([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})"
        rb"(?:[^0-9a-fA-F]|$)",
    )

    CONTEXT_PATTERNS = [
        rb"(?i)(?:md5|sha1|sha-1|sha256|sha-256|sha512|sha-512|hash|checksum)",
        rb"(?i)(?:password|secret|token|api_key)",
        rb"(?i)(?:hmac|digest|signature|verify)",
    ]

    @property
    def name(self) -> str:
        return "hashes"

    def _classify_hash(self, h: str) -> str:
        """Classify hash by length.

        Args:
            h: Hex string.

        Returns:
            Hash type name.
        """
        length = len(h)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 64:
            return "SHA256"
        elif length == 128:
            return "SHA512"
        return "Unknown"

    def _has_hash_context(self, data: bytes, offset: int) -> bool:
        """Check if surrounding bytes contain hash-related keywords.

        Args:
            data: Full data bytes.
            offset: Offset of the hash.

        Returns:
            True if hash context found.
        """
        window_start = max(0, offset - 50)
        window_end = min(len(data), offset + 100)
        window = data[window_start:window_end]
        for pattern in self.CONTEXT_PATTERNS:
            if re.search(pattern, window):
                return True
        return False

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect hash strings in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data:
            return results

        seen: set[str] = set()

        for match in self.HASH_RE.finditer(data):
            h = match.group(1).decode("ascii", errors="ignore")
            offset = match.start(1)
            h_lower = h.lower()

            if h_lower in seen:
                continue
            seen.add(h_lower)

            hash_type = self._classify_hash(h)
            confidence = 0.75

            # Boost confidence if context keywords nearby
            if self._has_hash_context(data, offset):
                confidence = 0.92
            # Boost if it doesn't look like a UUID or MAC address
            if hash_type == "MD5" and h.count("0") > 20:
                confidence -= 0.1
            if hash_type == "SHA1" and h.count("0") > 25:
                confidence -= 0.1

            results.append(
                self.create_finding(
                    context,
                    original=h,
                    decoded=f"{hash_type}: {h}",
                    offset=offset,
                    confidence=max(0.6, confidence),
                    notes=f"Hash type: {hash_type}",
                )
            )

        return results
