"""PCAP profile generation for PcapHunt.

Builds a comprehensive statistical profile of a PCAP capture.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, DNS, Raw, Ether
from scapy.packet import Packet

from pcaphunt.models import NetworkProfile

logger = logging.getLogger(__name__)


def build_profile(
    packets: list[tuple[int, Packet]],
    pcap_name: str = "",
) -> NetworkProfile:
    """Build a complete network profile from parsed packets.

    Args:
        packets: List of (packet_number, packet) tuples.
        pcap_name: Name of the PCAP file.

    Returns:
        NetworkProfile with statistics.
    """
    profile = NetworkProfile(pcap_name=pcap_name)
    profile.total_packets = len(packets)

    src_ip_counter: Counter = Counter()
    dst_ip_counter: Counter = Counter()
    port_counter: Counter = Counter()
    protocol_counter: Counter = Counter()
    conversation_counter: Counter = Counter()
    domain_counter: Counter = Counter()
    dns_query_counter: Counter = Counter()
    http_host_counter: Counter = Counter()
    http_path_counter: Counter = Counter()

    tcp_flows: set[tuple] = set()
    udp_flows: set[tuple] = set()

    timestamps: list[float] = []

    for pkt_num, pkt in packets:
        try:
            # Packet size
            pkt_len = len(bytes(pkt))
            profile.total_bytes += pkt_len

            # Timestamp
            if hasattr(pkt, "time"):
                try:
                    ts = float(pkt.time)
                    timestamps.append(ts)
                except Exception:
                    pass

            # IP addresses
            src_ip = ""
            dst_ip = ""
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                profile.unique_ips.add(src_ip)
                profile.unique_ips.add(dst_ip)
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                profile.unique_ips.add(src_ip)
                profile.unique_ips.add(dst_ip)

            # MAC addresses (only from Ethernet layer)
            if pkt.haslayer(Ether):
                profile.unique_macs.add(pkt[Ether].src)
                profile.unique_macs.add(pkt[Ether].dst)

            # Protocol and ports
            proto = "Other"
            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                port_counter[sport] += 1
                port_counter[dport] += 1

                # Track TCP flows
                flow_key = _normalize_flow(src_ip, sport, dst_ip, dport)
                tcp_flows.add(flow_key)
                conversation_counter[(src_ip, dst_ip, "TCP", dport)] += 1

                # HTTP detection
                payload = _get_tcp_payload(pkt)
                if payload:
                    if payload.startswith(b"GET ") or payload.startswith(b"POST ") or payload.startswith(b"HTTP/"):
                        proto = "HTTP"
                        profile.http_requests += 1
                        host, path = _parse_http_host_path(payload)
                        if host:
                            http_host_counter[host] += 1
                        if path:
                            http_path_counter[path] += 1

            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
                port_counter[sport] += 1
                port_counter[dport] += 1

                flow_key = _normalize_flow(src_ip, sport, dst_ip, dport)
                udp_flows.add(flow_key)
                conversation_counter[(src_ip, dst_ip, "UDP", dport)] += 1

                # DNS detection
                if pkt.haslayer(DNS):
                    proto = "DNS"
                    profile.dns_queries += 1
                    try:
                        if pkt[DNS].qd:
                            qname = _dns_qname(pkt[DNS].qd)
                            if qname:
                                dns_query_counter[qname] += 1
                                domain_counter[qname] += 1
                        if pkt[DNS].an:
                            for answer in pkt[DNS].an:
                                rname = getattr(answer, "rrname", b"").decode("utf-8", errors="ignore") if hasattr(answer, "rrname") else ""
                                if rname:
                                    domain_counter[rname] += 1
                    except Exception:
                        pass

            elif pkt.haslayer(DNS):
                proto = "DNS"
                profile.dns_queries += 1

            # Layer-based protocol inference
            for layer_name in _get_packet_layers(pkt):
                if layer_name in ("ICMP", "ICMPv6"):
                    proto = "ICMP"
                    break
                elif layer_name in ("HTTP", "HTTPRequest", "HTTPResponse"):
                    proto = "HTTP"
                    break
                elif layer_name == "TLS":
                    proto = "TLS"
                    break
                elif layer_name == "FTP":
                    proto = "FTP"
                    break
                elif layer_name == "SMTP":
                    proto = "SMTP"
                    break
                elif layer_name == "DHCP":
                    proto = "DHCP"
                    break
                elif layer_name == "IRC":
                    proto = "IRC"
                    break

            protocol_counter[proto] += 1

            if src_ip:
                src_ip_counter[src_ip] += 1
            if dst_ip:
                dst_ip_counter[dst_ip] += 1

        except Exception as exc:
            logger.debug("Profile build error on packet %d: %s", pkt_num, exc)

    # Timestamps
    if timestamps:
        profile.first_timestamp = min(timestamps)
        profile.last_timestamp = max(timestamps)
        profile.capture_duration_seconds = profile.last_timestamp - profile.first_timestamp

    # TCP/UDP streams
    profile.tcp_streams = len(tcp_flows)
    profile.udp_conversations = len(udp_flows)
    profile.protocols = dict(protocol_counter)

    # Top stats
    profile.top_source_ips = src_ip_counter.most_common(10)
    profile.top_destination_ips = dst_ip_counter.most_common(10)
    profile.top_ports = port_counter.most_common(10)
    profile.top_protocols = protocol_counter.most_common(10)
    profile.top_domains = domain_counter.most_common(10)
    profile.top_dns_queries = dns_query_counter.most_common(10)
    profile.top_http_hosts = http_host_counter.most_common(10)
    profile.top_http_paths = http_path_counter.most_common(10)

    # Top conversations
    top_conv = conversation_counter.most_common(10)
    profile.top_conversations = [
        {
            "source_ip": c[0][0],
            "destination_ip": c[0][1],
            "protocol": c[0][2],
            "port": c[0][3],
            "packet_count": c[1],
        }
        for c in top_conv
    ]

    return profile


def _normalize_flow(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple:
    """Normalize flow direction for deduplication."""
    if (src_ip, src_port) > (dst_ip, dst_port):
        return (dst_ip, dst_port, src_ip, src_port)
    return (src_ip, src_port, dst_ip, dst_port)


def _get_packet_layers(pkt: Packet) -> list[str]:
    """Get list of layer names in a packet."""
    layers: list[str] = []
    layer = pkt
    while layer:
        name = layer.name if hasattr(layer, "name") else type(layer).__name__
        layers.append(name)
        layer = layer.payload if hasattr(layer, "payload") else None
        if layer == pkt:
            break
    return layers


def _get_tcp_payload(pkt: Packet) -> bytes:
    """Extract TCP payload bytes."""
    if not pkt.haslayer(TCP):
        return b""
    tcp = pkt[TCP]
    if tcp.payload:
        try:
            return bytes(tcp.payload)
        except Exception:
            pass
    return b""


def _parse_http_host_path(payload: bytes) -> tuple[str | None, str | None]:
    """Parse HTTP host and path from payload."""
    host = None
    path = None
    try:
        # First line: GET /path HTTP/1.1
        first_line_end = payload.find(b"\r\n")
        if first_line_end == -1:
            first_line_end = payload.find(b"\n")
        if first_line_end > 0:
            first_line = payload[:first_line_end].decode("utf-8", errors="ignore")
            parts = first_line.split()
            if len(parts) >= 2 and parts[0] in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"):
                path = parts[1]

        # Host header
        host_match = re.search(rb"Host:\s*([^\r\n]+)", payload, re.IGNORECASE)
        if host_match:
            host = host_match.group(1).decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    return host, path


def _dns_qname(qd: Any) -> str | None:
    """Extract DNS query name."""
    try:
        if hasattr(qd, "qname"):
            qname = qd.qname
        elif hasattr(qd, "fields") and "qname" in qd.fields:
            qname = qd.fields["qname"]
        else:
            return None
        if isinstance(qname, bytes):
            return qname.decode("utf-8", errors="ignore").rstrip(".")
        return str(qname).rstrip(".")
    except Exception:
        return None
