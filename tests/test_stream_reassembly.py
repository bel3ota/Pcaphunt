"""Tests for TCP stream reassembly and UDP conversation reconstruction."""

import pytest
from scapy.all import IP, TCP, UDP, Raw

from pcaphunt.stream_reassembly import (
    _get_tcp_flow_key,
    _get_udp_flow_key,
    get_reassembled_udp_bytes,
    get_tcp_stream_payloads,
    get_udp_conversations,
    reassemble_tcp_streams,
)


class TestTCPStreamReassembly:
    def test_tcp_flow_key(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80)
        key = _get_tcp_flow_key(pkt)
        assert key == ("10.0.0.1", 12345, "10.0.0.2", 80)

    def test_tcp_flow_key_normalizes_direction(self):
        pkt = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345)
        key = _get_tcp_flow_key(pkt)
        expected = ("10.0.0.1", 12345, "10.0.0.2", 80)
        assert key == expected

    def test_tcp_flow_key_non_tcp(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / Raw(b"data")
        key = _get_tcp_flow_key(pkt)
        assert key is None

    def test_reassemble_simple_stream(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000) / Raw(b"Hello ")),
            (2, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1006) / Raw(b"World!")),
        ]
        streams = reassemble_tcp_streams(packets)
        key = ("10.0.0.1", 12345, "10.0.0.2", 80)
        assert key in streams
        data, pkt_nums = streams[key]
        assert data == b"Hello World!"
        assert pkt_nums == [1, 2]

    def test_reassemble_out_of_order(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1006) / Raw(b"World!")),
            (2, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000) / Raw(b"Hello ")),
        ]
        streams = reassemble_tcp_streams(packets)
        key = ("10.0.0.1", 12345, "10.0.0.2", 80)
        data, _ = streams[key]
        assert data == b"Hello World!"

    def test_reassemble_dedup_retransmissions(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000) / Raw(b"Hello")),
            (2, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000) / Raw(b"Hello")),
            (3, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1005) / Raw(b"World")),
        ]
        streams = reassemble_tcp_streams(packets)
        key = ("10.0.0.1", 12345, "10.0.0.2", 80)
        data, pkt_nums = streams[key]
        assert data == b"HelloWorld"
        # Should deduplicate the retransmission
        assert sorted(pkt_nums) == [1, 3]

    def test_reassemble_multiple_streams(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000) / Raw(b"A")),
            (2, IP(src="10.0.0.3", dst="10.0.0.4") / TCP(sport=54321, dport=443, seq=2000) / Raw(b"B")),
        ]
        streams = reassemble_tcp_streams(packets)
        assert len(streams) == 2

    def test_reassemble_with_overlap(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000) / Raw(b"Hello World")),
            (2, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1006) / Raw(b"World!")),
        ]
        streams = reassemble_tcp_streams(packets)
        key = ("10.0.0.1", 12345, "10.0.0.2", 80)
        data, _ = streams[key]
        # Overlap should be handled: "Hello" + " World!"
        assert data == b"Hello World!"

    def test_reassemble_with_fin_rst(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000, flags="FA") / Raw(b"data")),
            (2, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1004, flags="R")),
        ]
        streams = reassemble_tcp_streams(packets)
        key = ("10.0.0.1", 12345, "10.0.0.2", 80)
        assert key in streams

    def test_tcp_stream_payloads(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000) / Raw(b"A")),
            (2, IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1001) / Raw(b"B")),
        ]
        streams = get_tcp_stream_payloads(packets)
        key = ("10.0.0.1", 12345, "10.0.0.2", 80)
        assert key in streams
        assert len(streams[key]) == 2
        assert streams[key][0]["packet_number"] == 1
        assert "seq" in streams[key][0]


class TestUDPConversations:
    def test_udp_flow_key(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53)
        key = _get_udp_flow_key(pkt)
        assert key == ("10.0.0.1", 12345, "10.0.0.2", 53)

    def test_udp_conversation_grouping(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53) / Raw(b"query1")),
            (2, IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=12345) / Raw(b"response1")),
            (3, IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53) / Raw(b"query2")),
        ]
        convs = get_udp_conversations(packets)
        key = ("10.0.0.1", 12345, "10.0.0.2", 53)
        assert key in convs
        assert len(convs[key]) == 3

    def test_udp_reassemble_bytes(self):
        conv_data = [
            {"packet_number": 1, "payload": b"Part1", "src_ip": "10.0.0.1", "src_port": 12345, "dst_ip": "10.0.0.2", "dst_port": 53},
            {"packet_number": 2, "payload": b"Part2", "src_ip": "10.0.0.1", "src_port": 12345, "dst_ip": "10.0.0.2", "dst_port": 53},
        ]
        data, pkt_nums = get_reassembled_udp_bytes(conv_data)
        assert data == b"Part1Part2"
        assert pkt_nums == [1, 2]

    def test_udp_multiple_conversations(self):
        packets = [
            (1, IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53) / Raw(b"dns")),
            (2, IP(src="10.0.0.3", dst="10.0.0.4") / UDP(sport=54321, dport=123) / Raw(b"ntp")),
        ]
        convs = get_udp_conversations(packets)
        assert len(convs) == 2
