"""Plaintext detector for PcapHunt."""

import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class PlaintextDetector(BaseDetector):
    """Detect printable ASCII/UTF-8 strings in packet data."""

    @property
    def name(self) -> str:
        return "plaintext"

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect plaintext strings in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        min_length = self.config.get("min_length", 6)
        results: list[dict[str, Any]] = []
        if not data:
            return results

        # ASCII printable
        ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
        for match in ascii_re.finditer(data):
            offset = match.start()
            text = match.group().decode("ascii", errors="ignore")
            results.append(
                self.create_finding(
                    context,
                    original=text,
                    decoded=text,
                    offset=offset,
                    confidence=1.0,
                )
            )

        # UTF-8 with some higher chars (only if distinct from ASCII)
        try:
            decoded = data.decode("utf-8", errors="ignore")
            utf8_re = re.compile(r"[\x20-\x7e\x80-\xff]{%d,}" % min_length)
            for match in utf8_re.finditer(decoded):
                offset = match.start()
                text = match.group()
                # Skip if pure ASCII (already handled)
                if all(ord(c) < 128 for c in text):
                    continue
                # Avoid overlap with ASCII findings
                overlap = False
                for r in results:
                    if abs(r["offset"] - offset) < len(text):
                        overlap = True
                        break
                if not overlap:
                    results.append(
                        self.create_finding(
                            context,
                            original=text,
                            decoded=text,
                            offset=offset,
                            confidence=0.9,
                        )
                    )
        except Exception:
            pass

        return results
