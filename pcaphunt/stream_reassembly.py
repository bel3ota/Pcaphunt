"""TCP stream reassembly and UDP conversation reconstruction for PcapHunt."""

import logging
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP
from scapy.packet import Packet

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Flow keys
# ---------------------------------------------------------------------------

def _get_tcp_flow_key(pkt: Packet) -> tuple[str, int, str, int] | None:
    """Generate a consistent flow key for a TCP packet.

    Args:
        pkt: Scapy packet.

    Returns:
        Tuple of (src_ip, src_port, dst_ip, dst_port) or None.
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

    # Normalize direction for grouping
    if (src_ip, src_port) > (dst_ip, dst_port):
        return (dst_ip, dst_port, src_ip, src_port)
    return (src_ip, src_port, dst_ip, dst_port)


def _get_udp_flow_key(pkt: Packet) -> tuple[str, int, str, int] | None:
    """Generate a consistent flow key for a UDP packet.

    Args:
        pkt: Scapy packet.

    Returns:
        Tuple of (src_ip, src_port, dst_ip, dst_port) or None.
    """
    if not pkt.haslayer(UDP):
        return None
    udp = pkt[UDP]
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
    else:
        return None

    src_port = int(udp.sport)
    dst_port = int(udp.dport)

    if (src_ip, src_port) > (dst_ip, dst_port):
        return (dst_ip, dst_port, src_ip, src_port)
    return (src_ip, src_port, dst_ip, dst_port)


# ---------------------------------------------------------------------------
# TCP segment tracking
# ---------------------------------------------------------------------------

class TCPSegment:
    """Represents a single TCP segment for reassembly."""

    def __init__(
        self,
        seq: int,
        payload: bytes,
        pkt_num: int,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        flags: int = 0,
    ):
        self.seq = seq
        self.payload = payload
        self.pkt_num = pkt_num
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.flags = flags


def _extract_tcp_segments(
    packets: list[tuple[int, Packet]],
) -> dict[tuple[str, int, str, int], list[TCPSegment]]:
    """Extract TCP segments grouped by flow, preserving sequence numbers.

    Args:
        packets: List of (packet_number, packet) tuples.

    Returns:
        Dictionary mapping flow keys to list of segments.
    """
    flows: dict[tuple[str, int, str, int], list[TCPSegment]] = {}

    for pkt_num, pkt in packets:
        if not pkt.haslayer(TCP):
            continue

        tcp = pkt[TCP]
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            continue

        src_port = int(tcp.sport)
        dst_port = int(tcp.dport)
        seq = int(tcp.seq) if hasattr(tcp, "seq") else 0
        flags = int(tcp.flags) if hasattr(tcp, "flags") else 0

        payload = b""
        if tcp.payload:
            try:
                payload = bytes(tcp.payload)
            except Exception:
                pass

        if not payload:
            # Still track empty segments for FIN/RST awareness
            pass

        key = _get_tcp_flow_key(pkt)
        if key is None:
            continue

        segment = TCPSegment(
            seq=seq,
            payload=payload,
            pkt_num=pkt_num,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            flags=flags,
        )

        if key not in flows:
            flows[key] = []
        flows[key].append(segment)

    return flows


def _reassemble_flow(segments: list[TCPSegment]) -> tuple[bytes, list[int]]:
    """Reassemble a single TCP flow from segments.

    Handles out-of-order segments and deduplicates retransmissions.
    Missing segments leave gaps (zeros are not inserted).

    Args:
        segments: List of segments for one flow.

    Returns:
        Tuple of (reassembled_bytes, sorted_packet_numbers).
    """
    if not segments:
        return b"", []

    # Sort by sequence number
    segments.sort(key=lambda s: s.seq)

    # Deduplicate by (seq, payload) to handle retransmissions
    seen: set[tuple[int, bytes]] = set()
    unique: list[TCPSegment] = []
    pkt_nums: set[int] = set()

    for seg in segments:
        key = (seg.seq, seg.payload)
        if key in seen:
            continue
        seen.add(key)
        unique.append(seg)
        pkt_nums.add(seg.pkt_num)

    if not unique:
        return b"", []

    # Relative sequence numbering: find the minimum seq
    base_seq = unique[0].seq
    reassembled = bytearray()
    last_end = base_seq

    for seg in unique:
        if not seg.payload:
            continue
        seg_start = seg.seq
        seg_end = seg.seq + len(seg.payload)

        if seg_start >= last_end:
            # No overlap or gap — append
            reassembled.extend(seg.payload)
            last_end = seg_end
        elif seg_end > last_end:
            # Overlap — append only the new trailing bytes
            overlap = last_end - seg_start
            reassembled.extend(seg.payload[overlap:])
            last_end = seg_end
        # else: fully contained retransmission — ignore

    return bytes(reassembled), sorted(pkt_nums)


# ---------------------------------------------------------------------------
# Public API: TCP stream reassembly
# ---------------------------------------------------------------------------

def reassemble_tcp_streams(
    packets: list[tuple[int, Packet]],
) -> dict[tuple[str, int, str, int], tuple[bytes, list[int]]]:
    """Reassemble all TCP streams from packets.

    Args:
        packets: List of (packet_number, packet) tuples.

    Returns:
        Dictionary mapping flow keys to (reassembled_bytes, packet_numbers).
    """
    flows = _extract_tcp_segments(packets)
    result: dict[tuple[str, int, str, int], tuple[bytes, list[int]]] = {}
    for key, segments in flows.items():
        data, pkt_nums = _reassemble_flow(segments)
        if data:
            result[key] = (data, pkt_nums)
    return result


def get_tcp_stream_payloads(
    packets: list[tuple[int, Packet]],
) -> dict[tuple[str, int, str, int], list[dict[str, Any]]]:
    """Get detailed TCP stream payloads with metadata.

    Args:
        packets: List of (packet_number, packet) tuples.

    Returns:
        Dictionary mapping flow keys to list of payload metadata dicts.
    """
    flows = _extract_tcp_segments(packets)
    result: dict[tuple[str, int, str, int], list[dict[str, Any]]] = {}
    for key, segments in flows.items():
        for seg in segments:
            if key not in result:
                result[key] = []
            if seg.payload:
                result[key].append({
                    "packet_number": seg.pkt_num,
                    "payload": seg.payload,
                    "src_ip": seg.src_ip,
                    "src_port": seg.src_port,
                    "dst_ip": seg.dst_ip,
                    "dst_port": seg.dst_port,
                    "seq": seg.seq,
                    "flags": seg.flags,
                })
    return result


# ---------------------------------------------------------------------------
# UDP conversation reconstruction
# ---------------------------------------------------------------------------

def get_udp_conversations(
    packets: list[tuple[int, Packet]],
) -> dict[tuple[str, int, str, int], list[dict[str, Any]]]:
    """Group UDP packets into conversations by flow key.

    Args:
        packets: List of (packet_number, packet) tuples.

    Returns:
        Dictionary mapping flow keys to list of packet metadata dicts.
    """
    conversations: dict[tuple[str, int, str, int], list[dict[str, Any]]] = {}

    for pkt_num, pkt in packets:
        key = _get_udp_flow_key(pkt)
        if key is None:
            continue

        udp = pkt[UDP]
        payload = b""
        if udp.payload:
            try:
                payload = bytes(udp.payload)
            except Exception:
                pass

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            continue

        if key not in conversations:
            conversations[key] = []

        conversations[key].append({
            "packet_number": pkt_num,
            "payload": payload,
            "src_ip": src_ip,
            "src_port": int(udp.sport),
            "dst_ip": dst_ip,
            "dst_port": int(udp.dport),
        })

    return conversations


def get_reassembled_udp_bytes(
    conv_data: list[dict[str, Any]],
) -> tuple[bytes, list[int]]:
    """Concatenate UDP conversation payloads.

    Args:
        conv_data: List of packet metadata dicts.

    Returns:
        Tuple of (concatenated_bytes, packet_numbers).
    """
    data = b""
    pkt_nums: list[int] = []
    for item in conv_data:
        data += item["payload"]
        if item["packet_number"] not in pkt_nums:
            pkt_nums.append(item["packet_number"])
    return data, sorted(pkt_nums)
