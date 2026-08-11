"""Hex detector for PcapHunt."""

import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class HexDetector(BaseDetector):
    """Detect hexadecimal-encoded strings."""

    HEX_RE = re.compile(rb"[0-9a-fA-F]{8,}")

    @property
    def name(self) -> str:
        return "hex"

    def _decoded_is_meaningful(self, decoded: bytes) -> bool:
        """Check if decoded bytes look meaningful.

        Args:
            decoded: Decoded bytes.

        Returns:
            True if meaningful.
        """
        if not decoded or len(decoded) < 2:
            return False
        printable_count = sum(1 for b in decoded if 32 <= b < 127)
        whitespace_count = sum(1 for b in decoded if b in (9, 10, 13))
        total = len(decoded)
        ratio = (printable_count + whitespace_count) / total
        return ratio > 0.6 or (total > 10 and all(b < 128 for b in decoded))

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect hex strings in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data:
            return results

        for match in self.HEX_RE.finditer(data):
            raw = match.group()
            offset = match.start()
            text = raw.decode("ascii", errors="ignore")

            # Must be even length
            if len(text) % 2 != 0:
                continue

            try:
                decoded = bytes.fromhex(text)
            except Exception:
                continue

            if not self._decoded_is_meaningful(decoded):
                continue

            decoded_str = decoded.decode("utf-8", errors="replace")
            confidence = 0.9

            # Check for recursive decoding
            from pcaphunt.utils import recursive_decode

            steps = recursive_decode(decoded_str, max_depth=self.config.get("max_decode_depth", 3))
            if steps:
                final = steps[-1]["result"]
                results.append(
                    self.create_finding(
                        context,
                        original=text,
                        decoded=final,
                        offset=offset,
                        confidence=confidence,
                        decoding_steps=[{"method": "Hex", "result": decoded_str}] + steps,
                    )
                )
            else:
                results.append(
                    self.create_finding(
                        context,
                        original=text,
                        decoded=decoded_str,
                        offset=offset,
                        confidence=confidence,
                    )
                )

        return results
