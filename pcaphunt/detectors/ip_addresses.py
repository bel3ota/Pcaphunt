"""IP address detector for PcapHunt."""

import ipaddress
import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class IPAddressDetector(BaseDetector):
    """Detect IPv4 and IPv6 addresses in packet data."""

    IPV4_RE = re.compile(
        rb"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        rb"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    )
    # Simple IPv6 regex - not exhaustive but catches common forms
    IPV6_RE = re.compile(
        rb"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
        rb"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
        rb"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
        rb"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
        rb"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
        rb"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
        rb"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
        rb"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
        rb"::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|"
        rb"::[0-9a-fA-F]{1,4}|"
        rb"::(?:[fF]{4}:)?(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
        re.IGNORECASE,
    )

    @property
    def name(self) -> str:
        return "ip_addresses"

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect IP addresses in data.

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

        for match in self.IPV4_RE.finditer(data):
            raw = match.group()
            offset = match.start()
            text = raw.decode("ascii", errors="ignore")
            if text in seen:
                continue
            try:
                ipaddress.IPv4Address(text)
                seen.add(text)
                results.append(
                    self.create_finding(
                        context,
                        original=text,
                        decoded=text,
                        offset=offset,
                        confidence=0.98,
                    )
                )
            except Exception:
                continue

        for match in self.IPV6_RE.finditer(data):
            raw = match.group()
            offset = match.start()
            text = raw.decode("ascii", errors="ignore")
            if text in seen:
                continue
            try:
                ipaddress.IPv6Address(text)
                seen.add(text)
                results.append(
                    self.create_finding(
                        context,
                        original=text,
                        decoded=text,
                        offset=offset,
                        confidence=0.95,
                    )
                )
            except Exception:
                continue

        return results
