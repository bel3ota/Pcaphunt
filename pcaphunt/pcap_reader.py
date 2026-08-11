"""PCAP/PCAPNG reading with Scapy."""

import logging
from pathlib import Path
from typing import Iterator

from scapy.all import rdpcap, Raw
from scapy.packet import Packet

logger = logging.getLogger(__name__)


def read_pcap(path: str) -> Iterator[tuple[int, Packet]]:
    """Read a PCAP/PCAPNG file and yield packets with their numbers.

    Args:
        path: Path to the PCAP file.

    Yields:
        Tuples of (packet_number, packet).
    """
    pcap_path = Path(path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {path}")
    if not pcap_path.is_file():
        raise ValueError(f"Not a file: {path}")

    try:
        packets = rdpcap(str(pcap_path))
    except Exception as exc:
        raise ValueError(f"Failed to read PCAP file: {exc}") from exc

    for i, pkt in enumerate(packets, start=1):
        yield i, pkt


def get_packet_layers(pkt: Packet) -> list[str]:
    """Get list of layer names for a packet.

    Args:
        pkt: Scapy packet.

    Returns:
        List of layer names.
    """
    layers: list[str] = []
    current = pkt
    while current is not None:
        layers.append(current.name)
        current = current.payload if current.payload != current else None
    return layers


def get_packet_payload(pkt: Packet) -> bytes:
    """Extract raw payload bytes from a packet.

    Args:
        pkt: Scapy packet.

    Returns:
        Raw payload bytes.
    """
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw].load)
    return b""
