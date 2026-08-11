"""Core packet processing engine for PcapHunt."""

import logging
import re
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, DNS, Raw
from scapy.packet import Packet

from pcaphunt.pcap_reader import get_packet_layers, get_packet_payload
from pcaphunt.stream_reassembly import (
    get_reassembled_bytes,
    get_stream_payloads,
    reassemble_streams,
)

logger = logging.getLogger(__name__)


def get_packet_metadata(pkt: Packet, pkt_num: int) -> dict[str, Any]:
    """Extract metadata from a packet.

    Args:
        pkt: Scapy packet.
        pkt_num: Packet number.

    Returns:
        Dictionary of packet metadata.
    """
    meta: dict[str, Any] = {
        "packet_number": pkt_num,
        "protocol": "Unknown",
        "source_ip": None,
        "source_port": None,
        "destination_ip": None,
        "destination_port": None,
        "layers": get_packet_layers(pkt),
    }

    # Determine IP
    if pkt.haslayer(IP):
        meta["source_ip"] = pkt[IP].src
        meta["destination_ip"] = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        meta["source_ip"] = pkt[IPv6].src
        meta["destination_ip"] = pkt[IPv6].dst

    # Determine transport protocol and ports
    if pkt.haslayer(TCP):
        meta["protocol"] = "TCP"
        meta["source_port"] = int(pkt[TCP].sport)
        meta["destination_port"] = int(pkt[TCP].dport)
    elif pkt.haslayer(UDP):
        meta["protocol"] = "UDP"
        meta["source_port"] = int(pkt[UDP].sport)
        meta["destination_port"] = int(pkt[UDP].dport)
    elif pkt.haslayer(DNS):
        meta["protocol"] = "DNS"
    else:
        # Try to infer from layers
        for layer_name in meta["layers"]:
            if layer_name in ("ICMP", "ICMPv6"):
                meta["protocol"] = "ICMP"
                break
            elif layer_name in ("HTTP", "HTTPRequest", "HTTPResponse"):
                meta["protocol"] = "HTTP"
                break
            elif layer_name == "TLS":
                meta["protocol"] = "TLS"
                break
            elif layer_name == "FTP":
                meta["protocol"] = "FTP"
                break
            elif layer_name == "SMTP":
                meta["protocol"] = "SMTP"
                break
            elif layer_name == "POP3":
                meta["protocol"] = "POP3"
                break
            elif layer_name == "IMAP":
                meta["protocol"] = "IMAP"
                break
            elif layer_name == "IRC":
                meta["protocol"] = "IRC"
                break
            elif layer_name == "DHCP":
                meta["protocol"] = "DHCP"
                break

    return meta


def format_source(meta: dict[str, Any]) -> str:
    """Format source string from metadata.

    Args:
        meta: Packet metadata dictionary.

    Returns:
        Formatted source string.
    """
    if meta.get("source_ip") and meta.get("source_port"):
        return f"{meta['source_ip']}:{meta['source_port']}"
    return meta.get("source_ip") or ""


def format_destination(meta: dict[str, Any]) -> str:
    """Format destination string from metadata.

    Args:
        meta: Packet metadata dictionary.

    Returns:
        Formatted destination string.
    """
    if meta.get("destination_ip") and meta.get("destination_port"):
        return f"{meta['destination_ip']}:{meta['destination_port']}"
    return meta.get("destination_ip") or ""


def extract_printable_strings(data: bytes, min_length: int = 6) -> list[tuple[int, str]]:
    """Extract printable ASCII and UTF-8 strings from bytes.

    Args:
        data: Bytes to search.
        min_length: Minimum string length.

    Returns:
        List of (offset, string) tuples.
    """
    results: list[tuple[int, str]] = []
    if not data:
        return results

    # Try ASCII first
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    for match in ascii_re.finditer(data):
        offset = match.start()
        text = match.group().decode("ascii", errors="ignore")
        results.append((offset, text))

    # Try UTF-8 where valid
    try:
        decoded = data.decode("utf-8", errors="ignore")
        # Find sequences of printable chars
        printable_re = re.compile(r"[\x20-\x7e\x80-\xff]{%d,}" % min_length)
        for match in printable_re.finditer(decoded):
            offset = match.start()
            text = match.group()
            # Only include if it has some non-ASCII or if not already found
            if any(ord(c) >= 128 for c in text):
                # Check if this overlaps with ASCII results
                overlap = False
                for ao, at in results:
                    if abs(ao - offset) < len(text):
                        overlap = True
                        break
                if not overlap:
                    results.append((offset, text))
    except Exception:
        pass

    # Sort by offset
    results.sort(key=lambda x: x[0])
    return results


def build_context(meta: dict[str, Any]) -> dict[str, Any]:
    """Build a context dict for detectors from metadata.

    Args:
        meta: Packet metadata.

    Returns:
        Context dictionary.
    """
    return {
        "packet_numbers": [meta["packet_number"]],
        "protocol": meta.get("protocol", "Unknown"),
        "source": format_source(meta),
        "destination": format_destination(meta),
    }
