"""Flag detector for PcapHunt."""

import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class FlagDetector(BaseDetector):
    """Detect CTF flag patterns in packet data."""

    DEFAULT_PATTERNS = [
        r"flag\{[^}]{3,100}\}",
        r"FLAG\{[^}]{3,100}\}",
        r"CTF\{[^}]{3,100}\}",
        r"ctf\{[^}]{3,100}\}",
        r"ICT\{[^}]{3,100}\}",
        r"HTB\{[^}]{3,100}\}",
        r"picoCTF\{[^}]{3,100}\}",
    ]

    @property
    def name(self) -> str:
        return "flags"

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect flag patterns in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data:
            return results

        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return results

        patterns = self.config.get("flag_patterns", self.DEFAULT_PATTERNS)
        seen: set[str] = set()

        for pattern in patterns:
            for match in re.finditer(pattern, text):
                flag = match.group()
                offset = match.start()

                if flag in seen:
                    continue
                seen.add(flag)

                results.append(
                    self.create_finding(
                        context,
                        original=flag,
                        decoded=flag,
                        offset=offset,
                        confidence=1.0,
                    )
                )

        return results
