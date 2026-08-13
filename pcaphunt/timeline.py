"""Timeline generation for PcapHunt.

Creates a chronological event timeline from meaningful network activity.
"""

from __future__ import annotations

import logging
from typing import Any

from pcaphunt.models import TimelineEvent

logger = logging.getLogger(__name__)


def build_timeline(
    packets: list[tuple[int, Any]],
    findings: list[dict[str, Any]],
    artifacts: list[Any] = None,
    streams: list[dict[str, Any]] = None,
) -> list[TimelineEvent]:
    """Build an investigation timeline from packets, findings, and artifacts.

    Args:
        packets: List of (packet_number, packet) tuples.
        findings: List of finding dictionaries.
        artifacts: Optional list of FileArtifact objects.
        streams: Optional list of stream metadata dicts.

    Returns:
        Chronologically sorted list of TimelineEvents.
    """
    events: list[TimelineEvent] = []

    # Key packet events — limit to avoid overwhelming timelines
    # We create events for:
    # - First packet per TCP stream
    # - DNS queries
    # - HTTP requests
    # - FTP commands
    # - SMTP activity
    seen_streams: set[str] = set()
    packet_limit = min(len(packets), 5000)

    for pkt_num, pkt in packets[:packet_limit]:
        try:
            ts = _get_timestamp(pkt)
            src_ip = _get_src_ip(pkt)
            dst_ip = _get_dst_ip(pkt)
            proto = _get_protocol(pkt)
            sport = _get_src_port(pkt)
            dport = _get_dst_port(pkt)

            # Stream creation event
            stream_id = _stream_id(pkt)
            if stream_id and stream_id not in seen_streams:
                seen_streams.add(stream_id)
                events.append(
                    TimelineEvent(
                        timestamp=ts,
                        event_type="stream_creation",
                        description=f"{proto} stream started: {src_ip}:{sport} -> {dst_ip}:{dport}",
                        packet_number=pkt_num,
                        source_ip=src_ip or "",
                        destination_ip=dst_ip or "",
                        source_port=sport,
                        destination_port=dport,
                        protocol=proto,
                        stream_id=stream_id,
                    )
                )

            # Protocol-specific events
            if proto == "DNS":
                qname = _get_dns_query(pkt)
                if qname:
                    events.append(
                        TimelineEvent(
                            timestamp=ts,
                            event_type="dns_query",
                            description=f"DNS query: {qname}",
                            packet_number=pkt_num,
                            source_ip=src_ip or "",
                            destination_ip=dst_ip or "",
                            source_port=sport,
                            destination_port=dport,
                            protocol="DNS",
                            stream_id=stream_id,
                        )
                    )

            if proto == "HTTP":
                method, path = _get_http_request(pkt)
                if method:
                    events.append(
                        TimelineEvent(
                            timestamp=ts,
                            event_type="http_request",
                            description=f"HTTP {method} {path or ''}",
                            packet_number=pkt_num,
                            source_ip=src_ip or "",
                            destination_ip=dst_ip or "",
                            source_port=sport,
                            destination_port=dport,
                            protocol="HTTP",
                            stream_id=stream_id,
                        )
                    )

            if proto == "FTP":
                cmd = _get_ftp_command(pkt)
                if cmd:
                    events.append(
                        TimelineEvent(
                            timestamp=ts,
                            event_type="ftp_command",
                            description=f"FTP: {cmd[:80]}",
                            packet_number=pkt_num,
                            source_ip=src_ip or "",
                            destination_ip=dst_ip or "",
                            source_port=sport,
                            destination_port=dport,
                            protocol="FTP",
                            stream_id=stream_id,
                        )
                    )

            if proto == "SMTP":
                smtp = _get_smtp_line(pkt)
                if smtp:
                    events.append(
                        TimelineEvent(
                            timestamp=ts,
                            event_type="smtp_activity",
                            description=f"SMTP: {smtp[:80]}",
                            packet_number=pkt_num,
                            source_ip=src_ip or "",
                            destination_ip=dst_ip or "",
                            source_port=sport,
                            destination_port=dport,
                            protocol="SMTP",
                            stream_id=stream_id,
                        )
                    )

        except Exception as exc:
            logger.debug("Timeline packet error %d: %s", pkt_num, exc)

    # Finding events
    for finding in findings:
        ftype = finding.get("type", "")
        if ftype in ("flags", "credentials"):
            # High-value findings always go on timeline
            events.append(
                TimelineEvent(
                    timestamp=finding.get("timestamp"),
                    event_type="finding",
                    description=_finding_description(finding),
                    packet_number=finding.get("first_seen_packet"),
                    source_ip=_get_ip_from_addr(finding.get("source", "")),
                    destination_ip=_get_ip_from_addr(finding.get("destination", "")),
                    protocol=finding.get("protocol", ""),
                    stream_id=finding.get("stream_id"),
                    finding_id=finding.get("fingerprint"),
                    severity=finding.get("severity", "info"),
                )
            )
        elif ftype == "suspicious" and finding.get("severity") in ("high", "critical"):
            events.append(
                TimelineEvent(
                    timestamp=finding.get("timestamp"),
                    event_type="suspicious_activity",
                    description=_finding_description(finding),
                    packet_number=finding.get("first_seen_packet"),
                    source_ip=_get_ip_from_addr(finding.get("source", "")),
                    destination_ip=_get_ip_from_addr(finding.get("destination", "")),
                    protocol=finding.get("protocol", ""),
                    stream_id=finding.get("stream_id"),
                    finding_id=finding.get("fingerprint"),
                    severity=finding.get("severity", "info"),
                )
            )

    # File extraction events
    if artifacts:
        for artifact in artifacts:
            if artifact.complete:
                events.append(
                    TimelineEvent(
                        timestamp=artifact.timestamp,
                        event_type="file_extracted",
                        description=f"File extracted: {artifact.filename} ({artifact.file_type})",
                        packet_number=artifact.first_packet,
                        source_ip=artifact.source_ip,
                        destination_ip=artifact.destination_ip,
                        source_port=artifact.source_port,
                        destination_port=artifact.destination_port,
                        protocol=artifact.protocol,
                        stream_id=artifact.stream_id,
                        file_id=artifact.sha256,
                        severity="info",
                    )
                )

    # Sort chronologically, handling missing timestamps gracefully
    events.sort(key=lambda e: (e.timestamp if e.timestamp is not None else float("inf"), e.event_type))

    return events


def _get_timestamp(pkt: Any) -> float | None:
    if hasattr(pkt, "time"):
        try:
            return float(pkt.time)
        except Exception:
            pass
    return None


def _get_src_ip(pkt: Any) -> str:
    from scapy.all import IP, IPv6
    if pkt.haslayer(IP):
        return pkt[IP].src
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src
    return ""


def _get_dst_ip(pkt: Any) -> str:
    from scapy.all import IP, IPv6
    if pkt.haslayer(IP):
        return pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].dst
    return ""


def _get_src_port(pkt: Any) -> int | None:
    from scapy.all import TCP, UDP
    if pkt.haslayer(TCP):
        return int(pkt[TCP].sport)
    if pkt.haslayer(UDP):
        return int(pkt[UDP].sport)
    return None


def _get_dst_port(pkt: Any) -> int | None:
    from scapy.all import TCP, UDP
    if pkt.haslayer(TCP):
        return int(pkt[TCP].dport)
    if pkt.haslayer(UDP):
        return int(pkt[UDP].dport)
    return None


def _get_protocol(pkt: Any) -> str:
    from scapy.all import TCP, UDP, DNS
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(DNS):
        return "DNS"
    return "Other"


def _stream_id(pkt: Any) -> str | None:
    from scapy.all import TCP, UDP, IP, IPv6
    src_ip = _get_src_ip(pkt)
    dst_ip = _get_dst_ip(pkt)
    if pkt.haslayer(TCP):
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        return f"tcp_{src_ip}:{sport}->{dst_ip}:{dport}"
    if pkt.haslayer(UDP):
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        return f"udp_{src_ip}:{sport}->{dst_ip}:{dport}"
    return None


def _get_dns_query(pkt: Any) -> str | None:
    from scapy.all import DNS
    if not pkt.haslayer(DNS):
        return None
    try:
        qd = pkt[DNS].qd
        if qd and hasattr(qd, "qname"):
            qname = qd.qname
            if isinstance(qname, bytes):
                return qname.decode("utf-8", errors="ignore").rstrip(".")
            return str(qname).rstrip(".")
    except Exception:
        pass
    return None


def _get_http_request(pkt: Any) -> tuple[str | None, str | None]:
    from scapy.all import TCP
    if not pkt.haslayer(TCP):
        return None, None
    payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
    if not payload:
        return None, None
    try:
        first_line_end = payload.find(b"\r\n")
        if first_line_end == -1:
            first_line_end = payload.find(b"\n")
        if first_line_end > 0:
            first_line = payload[:first_line_end].decode("utf-8", errors="ignore")
            parts = first_line.split()
            if len(parts) >= 2 and parts[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
                return parts[0], parts[1]
    except Exception:
        pass
    return None, None


def _get_ftp_command(pkt: Any) -> str | None:
    from scapy.all import TCP
    if not pkt.haslayer(TCP):
        return None
    payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
    if not payload:
        return None
    try:
        line = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore").strip()
        if line and line[:4].isupper():
            return line
    except Exception:
        pass
    return None


def _get_smtp_line(pkt: Any) -> str | None:
    from scapy.all import TCP
    if not pkt.haslayer(TCP):
        return None
    payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
    if not payload:
        return None
    try:
        line = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore").strip()
        if line:
            return line
    except Exception:
        pass
    return None


def _finding_description(finding: dict[str, Any]) -> str:
    ftype = finding.get("type", "finding")
    content = finding.get("decoded") or finding.get("original", "")
    if len(content) > 100:
        content = content[:100] + "..."
    return f"{ftype}: {content}"


def _get_ip_from_addr(addr: str) -> str:
    if not addr:
        return ""
    if ":" in addr:
        parts = addr.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[0]
    return addr
