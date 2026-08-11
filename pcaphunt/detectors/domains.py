"""Domain detector for PcapHunt."""

import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class DomainDetector(BaseDetector):
    """Detect domain names in packet data."""

    # Avoid matching common false positives like filenames
    DOMAIN_RE = re.compile(
        rb"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        rb"[a-zA-Z]{2,63}",
        re.IGNORECASE,
    )

    # TLDs that are commonly real
    COMMON_TLDS = {
        "com", "org", "net", "edu", "gov", "mil", "int",
        "io", "co", "info", "biz", "name", "pro", "aero",
        "asia", "cat", "jobs", "mobi", "tel", "travel",
        "uk", "us", "de", "fr", "jp", "cn", "ru", "br",
        "au", "in", "it", "nl", "ca", "es", "pl", "id",
        "top", "xyz", "club", "online", "site", "store",
        "app", "dev", "cloud", "tech", "blog", "news",
        "localhost", "local", "lan", "home", "internal",
    }

    @property
    def name(self) -> str:
        return "domains"

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain with heuristics.

        Args:
            domain: Domain string.

        Returns:
            True if valid domain.
        """
        parts = domain.lower().split(".")
        tld = parts[-1] if parts else ""

        # Must have a TLD
        if len(tld) < 2:
            return False

        # Check for common false positives
        if len(parts) == 2 and len(parts[0]) <= 1:
            return False

        # Avoid hex-looking domains unless common TLD
        if tld not in self.COMMON_TLDS:
            # Allow if it looks like a real word
            if all(c.isdigit() or c in "abcdef" for c in tld) and len(tld) <= 4:
                return False

        # Reject obvious file extensions masquerading as TLDs
        fake_tlds = {
            "exe", "dll", "pdf", "png", "jpg", "jpeg", "gif",
            "zip", "tar", "gz", "bz2", "7z", "rar", "xml",
            "json", "csv", "txt", "log", "sql", "db", "ini",
        }
        if tld in fake_tlds:
            return False

        # Max label length
        for part in parts:
            if len(part) > 63:
                return False
            if part.startswith("-") or part.endswith("-"):
                return False

        return True

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect domain names in data.

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

        for match in self.DOMAIN_RE.finditer(data):
            raw = match.group()
            offset = match.start()
            text = raw.decode("ascii", errors="ignore")

            if text in seen:
                continue
            if not self._is_valid_domain(text):
                continue

            seen.add(text)
            results.append(
                self.create_finding(
                    context,
                    original=text,
                    decoded=text,
                    offset=offset,
                    confidence=0.85,
                )
            )

        return results
