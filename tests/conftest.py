"""Test fixtures and helpers for PcapHunt."""

import os
import tempfile
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Raw, wrpcap


def create_synthetic_pcap(filename: str, packets: list) -> str:
    """Create a synthetic PCAP file for testing.

    Args:
        filename: Output filename.
        packets: List of Scapy packets.

    Returns:
        Path to created PCAP file.
    """
    filepath = Path(__file__).parent / "fixtures" / filename
    filepath.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(filepath), packets)
    return str(filepath)


@pytest.fixture
def simple_tcp_pcap() -> str:
    """Create a simple PCAP with TCP packets containing various data."""
    packets = []
    # Packet 1: Plaintext
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"Hello this is a test message for CTF")
    packets.append(pkt1)

    # Packet 2: Base64
    import base64
    b64_data = base64.b64encode(b"Base64 encoded secret").decode()
    pkt2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b64_data.encode())
    packets.append(pkt2)

    # Packet 3: Hex
    hex_data = "48656c6c6f20435446"  # "Hello CTF"
    pkt3 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(hex_data.encode())
    packets.append(pkt3)

    # Packet 4: URL encoded
    pkt4 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"flag%7Burl_encoded_flag%7D")
    packets.append(pkt4)

    # Packet 5: Flag
    pkt5 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"Here is the flag{test_flag_123}")
    packets.append(pkt5)

    # Packet 6: Email
    pkt6 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"Contact: admin@example.com for help")
    packets.append(pkt6)

    # Packet 7: URL
    pkt7 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"Visit https://ctf.example.com/challenge")
    packets.append(pkt7)

    # Packet 8: IP address
    pkt8 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"Server at 192.168.1.100 is up")
    packets.append(pkt8)

    # Packet 9: Domain
    pkt9 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"Domain: malicious.example.com detected")
    packets.append(pkt9)

    # Packet 10: Credentials
    pkt10 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b'{"username":"admin","password":"secret123"}')
    packets.append(pkt10)

    # Packet 11: Hash
    pkt11 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"hash: 5f4dcc3b5aa765d61d8327deb882cf99")
    packets.append(pkt11)

    # Packet 12: JWT
    import base64
    import json
    header = base64.b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).decode().rstrip("=")
    payload = base64.b64encode(json.dumps({"sub":"123","admin":True}).encode()).decode().rstrip("=")
    jwt = f"{header}.{payload}.signature12345"
    pkt12 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(jwt.encode())
    packets.append(pkt12)

    # Packet 13: File signature (PNG)
    png_sig = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    pkt13 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(png_sig)
    packets.append(pkt13)

    # Packet 14: High entropy
    import random
    random.seed(42)
    entropy_data = bytes(random.randint(0, 255) for _ in range(500))
    pkt14 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(entropy_data)
    packets.append(pkt14)

    return create_synthetic_pcap("simple_tcp.pcap", packets)


@pytest.fixture
def split_flag_pcap() -> str:
    """Create a PCAP with a flag split across two TCP packets."""
    packets = []
    # Packet 1: first half of flag
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000) / Raw(b"CTF{this_is_")
    packets.append(pkt1)

    # Packet 2: second half of flag
    pkt2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1012) / Raw(b"a_flag}")
    packets.append(pkt2)

    return create_synthetic_pcap("split_flag.pcap", packets)


@pytest.fixture
def malformed_pcap() -> str:
    """Create a PCAP with some malformed/empty packets."""
    packets = []
    # Normal packet
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"Normal data")
    packets.append(pkt1)

    # Empty packet
    pkt2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80)
    packets.append(pkt2)

    # Packet with non-TCP
    pkt3 = IP(src="10.0.0.1", dst="10.0.0.2") / Raw(b"No transport layer")
    packets.append(pkt3)

    return create_synthetic_pcap("malformed.pcap", packets)


@pytest.fixture
def duplicate_content_pcap() -> str:
    """Create a PCAP with duplicate content in different packets and streams."""
    packets = []
    # Packet 1: same plaintext as packet 2, different source
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=80) / Raw(b"duplicate_flag{same_content}")
    packets.append(pkt1)

    # Packet 2: identical content, different IPs
    pkt2 = IP(src="192.168.1.5", dst="192.168.1.10") / TCP(sport=22222, dport=443) / Raw(b"duplicate_flag{same_content}")
    packets.append(pkt2)

    # Packet 3: same content again, different protocol layer context
    pkt3 = IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=33333, dport=8080) / Raw(b"duplicate_flag{same_content}")
    packets.append(pkt3)

    # Packet 4: similar but NOT identical content
    pkt4 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=80) / Raw(b"duplicate_flag{same_content!}")
    packets.append(pkt4)

    # Packet 5: different content entirely
    pkt5 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=80) / Raw(b"unique_flag{different}")
    packets.append(pkt5)

    return create_synthetic_pcap("duplicate_content.pcap", packets)


@pytest.fixture
def empty_pcap() -> str:
    """Create an empty PCAP with no interesting data."""
    packets = []
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"\x00\x00\x00")
    packets.append(pkt1)
    return create_synthetic_pcap("empty.pcap", packets)


@pytest.fixture
def tmp_output_dir() -> str:
    """Create a temporary output directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir
