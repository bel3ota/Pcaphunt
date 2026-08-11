"""URL-encoded detector for PcapHunt."""

import re
import urllib.parse
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class URLEncodedDetector(BaseDetector):
    """Detect URL-encoded strings."""

    URL_RE = re.compile(rb"(?:%[0-9a-fA-F]{2}){3,}")
    MIXED_RE = re.compile(rb"(?:[A-Za-z0-9_\-\.~!$&'()*+,;=/]|%[0-9a-fA-F]{2}){4,}")

    @property
    def name(self) -> str:
        return "url_encoded"

    def _is_meaningful(self, decoded: str) -> bool:
        """Check if decoded string is meaningful.

        Args:
            decoded: Decoded string.

        Returns:
            True if meaningful.
        """
        if not decoded or len(decoded) < 3:
            return False
        printable_count = sum(1 for c in decoded if c.isprintable() or c.isspace())
        return printable_count / len(decoded) > 0.7

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect URL-encoded strings in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data:
            return results

        # First find sequences of percent-encoded bytes
        for match in self.URL_RE.finditer(data):
            raw = match.group()
            offset = match.start()
            text = raw.decode("ascii", errors="ignore")

            try:
                decoded = urllib.parse.unquote(text)
            except Exception:
                continue

            if not self._is_meaningful(decoded):
                continue

            if decoded == text:
                continue

            # Check for recursive decoding
            from pcaphunt.utils import recursive_decode

            steps = recursive_decode(decoded, max_depth=self.config.get("max_decode_depth", 3))
            if steps:
                final = steps[-1]["result"]
                results.append(
                    self.create_finding(
                        context,
                        original=text,
                        decoded=final,
                        offset=offset,
                        confidence=0.9,
                        decoding_steps=[{"method": "URL Decode", "result": decoded}] + steps,
                    )
                )
            else:
                results.append(
                    self.create_finding(
                        context,
                        original=text,
                        decoded=decoded,
                        offset=offset,
                        confidence=0.9,
                    )
                )

        # Also find mixed strings like hello%20world
        seen_offsets = {r["offset"] for r in results}
        for match in self.MIXED_RE.finditer(data):
            offset = match.start()
            if offset in seen_offsets:
                continue
            raw = match.group()
            text = raw.decode("ascii", errors="ignore")
            if "%" not in text or len(text) < 6:
                continue

            try:
                decoded = urllib.parse.unquote(text)
            except Exception:
                continue

            if not self._is_meaningful(decoded):
                continue
            if decoded == text:
                continue

            results.append(
                self.create_finding(
                    context,
                    original=text,
                    decoded=decoded,
                    offset=offset,
                    confidence=0.85,
                )
            )

        return results
