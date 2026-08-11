"""TCP stream reassembly for PcapHunt."""

import logging
from typing import Any

from scapy.all import IP, IPv6, TCP
from scapy.packet import Packet

logger = logging.getLogger(__name__)


def get_stream_key(pkt: Packet) -> tuple[str, int, str, int] | None:
    """Generate a consistent stream key for a TCP packet.

    Args:
        pkt: Scapy packet.

    Returns:
        Tuple of (src_ip, src_port, dst_ip, dst_port) or None if not TCP.
    """
    if not pkt.haslayer(TCP):
        return None
    tcp = pkt[TCP]
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
    else:
        return None

    src_port = int(tcp.sport)
    dst_port = int(tcp.dport)

    # Normalize direction for stream grouping
    if (src_ip, src_port) > (dst_ip, dst_port):
        return (dst_ip, dst_port, src_ip, src_port)
    return (src_ip, src_port, dst_ip, dst_port)


def reassemble_streams(packets: list[tuple[int, Packet]]) -> dict[tuple[str, int, str, int], list[tuple[int, bytes]]]:
    """Reassemble TCP streams from packets.

    Args:
        packets: List of (packet_number, packet) tuples.

    Returns:
        Dictionary mapping stream keys to list of (packet_number, payload_bytes).
    """
    streams: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = {}

    for pkt_num, pkt in packets:
        key = get_stream_key(pkt)
        if key is None:
            continue
        payload = b""
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            try:
                payload = bytes(pkt[TCP].payload)
            except Exception:
                pass
        if not payload:
            continue
        if key not in streams:
            streams[key] = []
        streams[key].append((pkt_num, payload))

    return streams


def get_stream_payloads(
    packets: list[tuple[int, Packet]],
) -> dict[tuple[str, int, str, int], list[dict[str, Any]]]:
    """Get detailed stream payloads with metadata.

    Args:
        packets: List of (packet_number, packet) tuples.

    Returns:
        Dictionary mapping stream keys to list of payload metadata dicts.
    """
    streams: dict[tuple[str, int, str, int], list[dict[str, Any]]] = {}

    for pkt_num, pkt in packets:
        key = get_stream_key(pkt)
        if key is None:
            continue
        payload = b""
        if pkt.haslayer(TCP) and pkt[TCP].payload:
            try:
                payload = bytes(pkt[TCP].payload)
            except Exception:
                pass
        if not payload:
            continue

        src_ip = key[0]
        src_port = key[1]
        dst_ip = key[2]
        dst_port = key[3]

        if key not in streams:
            streams[key] = []
        streams[key].append({
            "packet_number": pkt_num,
            "payload": payload,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
        })

    return streams


def get_reassembled_bytes(
    stream_data: list[dict[str, Any]],
) -> tuple[bytes, list[int]]:
    """Concatenate a stream's payloads into a single bytes object.

    Args:
        stream_data: List of payload metadata dicts.

    Returns:
        Tuple of (reassembled_bytes, packet_numbers).
    """
    data = b""
    pkt_nums: list[int] = []
    for item in stream_data:
        data += item["payload"]
        if item["packet_number"] not in pkt_nums:
            pkt_nums.append(item["packet_number"])
    return data, pkt_nums
