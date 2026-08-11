"""Tests for TCP stream reassembly."""

import pytest
from scapy.all import IP, TCP, Raw

from pcaphunt.stream_reassembly import (
    get_reassembled_bytes,
    get_stream_key,
    get_stream_payloads,
    reassemble_streams,
)


class TestStreamReassembly:
    def test_get_stream_key_tcp(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80)
        key = get_stream_key(pkt)
        assert key == ("10.0.0.1", 12345, "10.0.0.2", 80)

    def test_get_stream_key_normalizes_direction(self):
        pkt = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345)
        key = get_stream_key(pkt)
        # Should normalize to the same key regardless of direction
        expected = ("10.0.0.1", 12345, "10.0.0.2", 80)
        assert key == expected

    def test_get_stream_key_non_tcp(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / Raw(b"data")
        key = get_stream_key(pkt)
        assert key is None

    def test_reassemble_streams(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"Hello ")),
            (2, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"World!")),
        ]
        streams = reassemble_streams(packets)
        key = ("10.0.0.1", 12345, "10.0.0.2", 80)
        assert key in streams
        data = b"".join(item[1] for item in streams[key])
        assert data == b"Hello World!"

    def test_get_reassembled_bytes(self):
        stream_data = [
            {"packet_number": 1, "payload": b"Part1", "src_ip": "10.0.0.1", "src_port": 12345, "dst_ip": "10.0.0.2", "dst_port": 80},
            {"packet_number": 2, "payload": b"Part2", "src_ip": "10.0.0.1", "src_port": 12345, "dst_ip": "10.0.0.2", "dst_port": 80},
        ]
        data, pkt_nums = get_reassembled_bytes(stream_data)
        assert data == b"Part1Part2"
        assert pkt_nums == [1, 2]

    def test_get_stream_payloads(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"A")),
            (2, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"B")),
        ]
        streams = get_stream_payloads(packets)
        key = ("10.0.0.1", 12345, "10.0.0.2", 80)
        assert key in streams
        assert len(streams[key]) == 2
        assert streams[key][0]["packet_number"] == 1
