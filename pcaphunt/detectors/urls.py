"""URL detector for PcapHunt."""

import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class URLDetector(BaseDetector):
    """Detect URLs in packet data."""

    URL_RE = re.compile(
        rb"(?:https?|ftp|sftp|file|dict|gopher|ldap|mailto|news|telnet|ssh)://"
        rb"[A-Za-z0-9_\-\.~:/?#\[\]@!$&'()*+,;=%]+",
        re.IGNORECASE,
    )

    @property
    def name(self) -> str:
        return "urls"

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect URLs in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data:
            return results

        for match in self.URL_RE.finditer(data):
            raw = match.group()
            offset = match.start()
            text = raw.decode("ascii", errors="ignore")
            if len(text) < 8:
                continue
            results.append(
                self.create_finding(
                    context,
                    original=text,
                    decoded=text,
                    offset=offset,
                    confidence=0.95,
                )
            )

        return results
