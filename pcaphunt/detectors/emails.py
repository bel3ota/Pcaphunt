"""Email detector for PcapHunt."""

import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class EmailDetector(BaseDetector):
    """Detect email addresses in packet data."""

    EMAIL_RE = re.compile(
        rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        rb"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    )

    @property
    def name(self) -> str:
        return "emails"

    def _is_valid_email(self, email: str) -> bool:
        """Validate email with simple heuristics.

        Args:
            email: Email string.

        Returns:
            True if valid.
        """
        if "@" not in email or "." not in email:
            return False
        local, domain = email.rsplit("@", 1)
        if len(local) > 64 or len(domain) > 255:
            return False
        if len(local) < 1 or len(domain) < 3:
            return False
        if domain.startswith(".") or domain.endswith("."):
            return False
        if ".." in domain:
            return False
        return True

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect email addresses in data.

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

        for match in self.EMAIL_RE.finditer(data):
            raw = match.group()
            offset = match.start()
            text = raw.decode("ascii", errors="ignore")

            if text in seen:
                continue
            if not self._is_valid_email(text):
                continue

            seen.add(text)
            results.append(
                self.create_finding(
                    context,
                    original=text,
                    decoded=text,
                    offset=offset,
                    confidence=0.9,
                )
            )

        return results
