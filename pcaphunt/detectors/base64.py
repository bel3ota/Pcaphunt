"""Base64 detector for PcapHunt."""

import base64
import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class Base64Detector(BaseDetector):
    """Detect likely Base64-encoded strings."""

    B64_RE = re.compile(rb"[A-Za-z0-9+/]{8,}={0,2}")
    B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")

    @property
    def name(self) -> str:
        return "base64"

    def _is_valid_b64(self, text: str) -> bool:
        """Check if text is valid Base64.

        Args:
            text: Candidate string.

        Returns:
            True if valid Base64.
        """
        if not text:
            return False
        if len(text) % 4 != 0 and not text.endswith("="):
            # Try with padding
            padding = 4 - len(text) % 4
            text += "=" * padding
        if len(text) < 4:
            return False
        try:
            result = base64.b64decode(text, validate=True)
            return len(result) > 0
        except Exception:
            return False

    def _decoded_is_meaningful(self, decoded: bytes) -> bool:
        """Check if decoded bytes look meaningful.

        Args:
            decoded: Decoded bytes.

        Returns:
            True if meaningful.
        """
        if not decoded:
            return False
        # Allow printable, tabs, newlines, some binary
        printable_count = sum(1 for b in decoded if 32 <= b < 127)
        whitespace_count = sum(1 for b in decoded if b in (9, 10, 13))
        total = len(decoded)
        if total == 0:
            return False
        ratio = (printable_count + whitespace_count) / total
        # High printable ratio = meaningful
        # Or if it starts with common file signatures
        if ratio > 0.7:
            return True
        # Allow binary data if it's a reasonable length (maybe compressed/encrypted)
        if total > 20 and all(b < 128 or b in (9, 10, 13) for b in decoded):
            return True
        return False

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect Base64 strings in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data:
            return results

        for match in self.B64_RE.finditer(data):
            raw = match.group()
            offset = match.start()
            text = raw.decode("ascii", errors="ignore")

            # Skip if too short
            if len(text) < 8:
                continue

            # Check valid chars
            if not all(c in self.B64_CHARS for c in text):
                continue

            if not self._is_valid_b64(text):
                continue

            try:
                decoded = base64.b64decode(text, validate=True)
            except Exception:
                continue

            if not self._decoded_is_meaningful(decoded):
                continue

            decoded_str = decoded.decode("utf-8", errors="replace")
            confidence = 0.95 if all(c in self.B64_CHARS for c in text) else 0.8

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
                        decoding_steps=[{"method": "Base64", "result": decoded_str}] + steps,
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
