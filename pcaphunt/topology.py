"""Network topology graph generation for PcapHunt.

Builds a communication graph of hosts and their relationships.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from typing import Any

from pcaphunt.models import NetworkEdge, NetworkNode

logger = logging.getLogger(__name__)


def build_topology(
    packets: list[tuple[int, Any]],
    findings: list[dict[str, Any]] = None,
) -> tuple[list[NetworkNode], list[NetworkEdge]]:
    """Build network topology from packets.

    Args:
        packets: List of (packet_number, packet) tuples.
        findings: Optional findings list to mark suspicious nodes.

    Returns:
        Tuple of (nodes, edges).
    """
    nodes: dict[str, NetworkNode] = {}
    edges_data: dict[tuple[str, str, str, int | None], dict[str, Any]] = defaultdict(
        lambda: {"connection_count": 0, "packet_count": 0, "byte_count": 0}
    )

    # Collect hostnames from findings if available
    hostnames: dict[str, str] = {}
    suspicious_ips: set[str] = set()
    suspicion_reasons: dict[str, str] = {}

    if findings:
        for finding in findings:
            ftype = finding.get("type", "")
            src = finding.get("source", "")
            dst = finding.get("destination", "")
            src_ip = _get_ip(src)
            dst_ip = _get_ip(dst)

            # DNS-based hostnames
            if ftype == "protocol_dns":
                domain = finding.get("metadata", {}).get("domain", "")
                answers = finding.get("metadata", {}).get("answers", [])
                for ans in answers:
                    if isinstance(ans, str):
                        hostnames[ans] = domain

            # Mark suspicious
            if ftype in ("flags", "credentials") or finding.get("severity") in ("high", "critical"):
                if src_ip:
                    suspicious_ips.add(src_ip)
                    suspicion_reasons[src_ip] = ftype
                if dst_ip:
                    suspicious_ips.add(dst_ip)
                    suspicion_reasons[dst_ip] = ftype

    for pkt_num, pkt in packets:
        try:
            from scapy.all import IP, IPv6, TCP, UDP

            src_ip = ""
            dst_ip = ""
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            if not src_ip or not dst_ip:
                continue

            pkt_len = len(bytes(pkt))
            proto = "Other"
            port: int | None = None

            if pkt.haslayer(TCP):
                proto = "TCP"
                port = int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                port = int(pkt[UDP].dport)
            elif pkt.haslayer(DNS):
                proto = "DNS"

            # Update nodes
            for ip in (src_ip, dst_ip):
                if ip not in nodes:
                    nodes[ip] = NetworkNode(ip=ip)
                nodes[ip].packet_count += 1
                nodes[ip].byte_count += pkt_len

            # Update edges
            edge_key = (src_ip, dst_ip, proto, port)
            edges_data[edge_key]["connection_count"] += 1
            edges_data[edge_key]["packet_count"] += 1
            edges_data[edge_key]["byte_count"] += pkt_len

        except Exception as exc:
            logger.debug("Topology build error on packet %d: %s", pkt_num, exc)

    # Mark suspicious nodes
    for ip in suspicious_ips:
        if ip in nodes:
            nodes[ip].is_suspicious = True
            nodes[ip].suspicion_reason = suspicion_reasons.get(ip, "suspicious finding")

    # Add hostnames
    for ip, hostname in hostnames.items():
        if ip in nodes:
            nodes[ip].hostname = hostname

    # Build edge list
    edge_list: list[NetworkEdge] = []
    for (src_ip, dst_ip, proto, port), data in edges_data.items():
        is_suspicious = src_ip in suspicious_ips or dst_ip in suspicious_ips
        reason = ""
        if is_suspicious:
            if src_ip in suspicion_reasons:
                reason = f"source: {suspicion_reasons[src_ip]}"
            elif dst_ip in suspicion_reasons:
                reason = f"destination: {suspicion_reasons[dst_ip]}"

        edge_list.append(
            NetworkEdge(
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=proto,
                port=port,
                connection_count=data["connection_count"],
                packet_count=data["packet_count"],
                byte_count=data["byte_count"],
                is_suspicious=is_suspicious,
                suspicion_reason=reason,
            )
        )

    # Sort edges by packet count descending
    edge_list.sort(key=lambda e: e.packet_count, reverse=True)

    # Limit edges for performance on huge captures
    max_edges = 5000
    if len(edge_list) > max_edges:
        # Keep all suspicious edges and top edges by packet count
        suspicious_edges = [e for e in edge_list if e.is_suspicious]
        normal_edges = [e for e in edge_list if not e.is_suspicious][: max_edges - len(suspicious_edges)]
        edge_list = suspicious_edges + normal_edges
        edge_list.sort(key=lambda e: e.packet_count, reverse=True)

    return list(nodes.values()), edge_list


def _get_ip(addr: str) -> str:
    if not addr or ":" not in addr:
        return addr
    parts = addr.rsplit(":", 1)
    if parts[1].isdigit():
        return parts[0]
    return addr
