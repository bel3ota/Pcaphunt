"""Advanced search and filtering for PcapHunt findings.

Supports combined logical AND filtering across multiple fields.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class FilterCriteria:
    """Represents a set of filter criteria for findings."""

    def __init__(
        self,
        search_text: str | None = None,
        category: str | None = None,
        protocol: str | None = None,
        ip: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        port: int | None = None,
        src_port: int | None = None,
        dst_port: int | None = None,
        stream_id: str | None = None,
        packet: int | None = None,
        severity: str | None = None,
        min_score: int | None = None,
    ):
        self.search_text = search_text
        self.category = category
        self.protocol = protocol
        self.ip = ip
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.port = port
        self.src_port = src_port
        self.dst_port = dst_port
        self.stream_id = stream_id
        self.packet = packet
        self.severity = severity
        self.min_score = min_score

    def is_empty(self) -> bool:
        """Return True if no filters are set."""
        return all(
            v is None or (isinstance(v, str) and not v)
            for v in [
                self.search_text,
                self.category,
                self.protocol,
                self.ip,
                self.src_ip,
                self.dst_ip,
                self.port,
                self.src_port,
                self.dst_port,
                self.stream_id,
                self.packet,
                self.severity,
                self.min_score,
            ]
        )


def filter_findings(
    findings: list[dict[str, Any]],
    criteria: FilterCriteria,
) -> list[dict[str, Any]]:
    """Filter findings based on criteria.

    All specified criteria are combined with logical AND.

    Args:
        findings: List of finding dictionaries.
        criteria: FilterCriteria instance.

    Returns:
        Filtered list of findings.
    """
    if criteria.is_empty():
        return findings

    result: list[dict[str, Any]] = []
    for finding in findings:
        if _matches(finding, criteria):
            result.append(finding)
    return result


def _matches(finding: dict[str, Any], criteria: FilterCriteria) -> bool:
    """Check if a single finding matches all criteria."""

    # Text search across original, decoded, notes, metadata
    if criteria.search_text is not None and criteria.search_text:
        search_lower = criteria.search_text.lower()
        texts = [
            str(finding.get("original", "")),
            str(finding.get("decoded", "")),
            str(finding.get("notes", "")),
        ]
        # Also search in metadata values
        for v in finding.get("metadata", {}).values():
            texts.append(str(v))
        if not any(search_lower in t.lower() for t in texts):
            return False

    # Category / type
    if criteria.category is not None and criteria.category:
        if finding.get("type", "") != criteria.category:
            return False

    # Protocol
    if criteria.protocol is not None and criteria.protocol:
        if finding.get("protocol", "").lower() != criteria.protocol.lower():
            return False

    # IP (matches either source or destination)
    if criteria.ip is not None and criteria.ip:
        src = finding.get("source", "")
        dst = finding.get("destination", "")
        ip_clean = criteria.ip
        if ip_clean not in src and ip_clean not in dst:
            return False

    # Source IP
    if criteria.src_ip is not None and criteria.src_ip:
        if criteria.src_ip not in finding.get("source", ""):
            return False

    # Destination IP
    if criteria.dst_ip is not None and criteria.dst_ip:
        if criteria.dst_ip not in finding.get("destination", ""):
            return False

    # Port (matches either source or destination port)
    if criteria.port is not None:
        src = finding.get("source", "")
        dst = finding.get("destination", "")
        port_str = f":{criteria.port}"
        if not (src.endswith(port_str) or dst.endswith(port_str)):
            return False

    # Source port
    if criteria.src_port is not None:
        src = finding.get("source", "")
        if not src.endswith(f":{criteria.src_port}"):
            return False

    # Destination port
    if criteria.dst_port is not None:
        dst = finding.get("destination", "")
        if not dst.endswith(f":{criteria.dst_port}"):
            return False

    # Stream ID
    if criteria.stream_id is not None and criteria.stream_id:
        if finding.get("stream_id") != criteria.stream_id:
            return False

    # Packet number
    if criteria.packet is not None:
        pkt_nums = finding.get("packet_numbers", [])
        first = finding.get("first_seen_packet")
        if criteria.packet not in pkt_nums and criteria.packet != first:
            return False

    # Severity
    if criteria.severity is not None and criteria.severity:
        # Support >= severity semantics
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        target_level = severity_order.get(criteria.severity.lower(), 0)
        finding_level = severity_order.get(finding.get("severity", "info").lower(), 0)
        if finding_level < target_level:
            return False

    # Minimum score
    if criteria.min_score is not None:
        score = finding.get("score", 0)
        if score < criteria.min_score:
            return False

    return True
