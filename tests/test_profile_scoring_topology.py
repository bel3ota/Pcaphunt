"""Tests for PcapHunt profile, scoring, topology, and filters."""

from __future__ import annotations

import tempfile

import pytest
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

from pcaphunt.filters import FilterCriteria, filter_findings
from pcaphunt.profile import build_profile
from pcaphunt.scoring import score_finding, apply_scores
from pcaphunt.topology import build_topology


@pytest.fixture
def mixed_pcap():
    """Create a PCAP with mixed traffic for profile/topology tests."""
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
        IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=12345) / Raw(b"HTTP/1.1 200 OK\r\n"),
        IP(src="10.0.0.1", dst="10.0.0.3") / UDP(sport=12345, dport=53) / DNS(qd=DNSQR(qname=b"example.com")),
        IP(src="10.0.0.1", dst="10.0.0.4") / TCP(sport=12346, dport=443) / Raw(b"\x16\x03\x01"),
    ]
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, packets)
        yield f.name


class TestProfile:
    def test_packet_count(self, mixed_pcap):
        from pcaphunt.pcap_reader import read_pcap
        packets = list(read_pcap(mixed_pcap))
        profile = build_profile(packets)
        assert profile.total_packets == 4

    def test_unique_ips(self, mixed_pcap):
        from pcaphunt.pcap_reader import read_pcap
        packets = list(read_pcap(mixed_pcap))
        profile = build_profile(packets)
        assert len(profile.unique_ips) >= 2
        assert "10.0.0.1" in profile.unique_ips

    def test_protocols(self, mixed_pcap):
        from pcaphunt.pcap_reader import read_pcap
        packets = list(read_pcap(mixed_pcap))
        profile = build_profile(packets)
        assert "HTTP" in profile.protocols
        assert profile.protocols["HTTP"] >= 1
        assert "DNS" in profile.protocols
        assert profile.protocols["DNS"] >= 1

    def test_top_source_ips(self, mixed_pcap):
        from pcaphunt.pcap_reader import read_pcap
        packets = list(read_pcap(mixed_pcap))
        profile = build_profile(packets)
        assert len(profile.top_source_ips) > 0
        assert profile.top_source_ips[0][0] == "10.0.0.1"

    def test_top_ports(self, mixed_pcap):
        from pcaphunt.pcap_reader import read_pcap
        packets = list(read_pcap(mixed_pcap))
        profile = build_profile(packets)
        ports = [p[0] for p in profile.top_ports]
        assert 80 in ports

    def test_to_dict(self, mixed_pcap):
        from pcaphunt.pcap_reader import read_pcap
        packets = list(read_pcap(mixed_pcap))
        profile = build_profile(packets)
        d = profile.to_dict()
        assert d["total_packets"] == 4
        assert "top_source_ips" in d


class TestScoring:
    def test_flag_score_critical(self):
        finding = {
            "type": "flags",
            "original": "flag{test}",
            "decoded": "flag{test}",
            "severity": "info",
            "confidence": 1.0,
        }
        score = score_finding(finding)
        assert score.score >= 80
        assert score.severity == "critical"
        assert "flag_detected" in score.factors
        assert len(score.reasons) > 0

    def test_credential_score_high(self):
        finding = {
            "type": "credentials",
            "original": "password=secret123",
            "severity": "high",
            "confidence": 1.0,
        }
        score = score_finding(finding)
        assert score.score >= 60
        assert "password_plaintext" in score.factors or "high_confidence_credential" in score.factors

    def test_bearer_token_score(self):
        finding = {
            "type": "credentials",
            "original": "Authorization: Bearer abc123",
            "severity": "high",
            "confidence": 1.0,
        }
        score = score_finding(finding)
        assert score.score >= 60

    def test_plaintext_low_score(self):
        finding = {
            "type": "plaintext",
            "original": "Hello world",
            "severity": "info",
            "confidence": 0.5,
        }
        score = score_finding(finding)
        assert score.score < 20
        assert score.severity in ("info", "low")

    def test_suspicious_medium_score(self):
        finding = {
            "type": "suspicious",
            "original": "[500 bytes of high-entropy data]",
            "severity": "medium",
            "confidence": 0.9,
            "entropy": 7.8,
        }
        score = score_finding(finding)
        assert score.score >= 35

    def test_apply_scores(self):
        findings = [
            {"type": "flags", "original": "flag{test}", "severity": "info", "confidence": 1.0},
            {"type": "plaintext", "original": "hello", "severity": "info", "confidence": 0.5},
        ]
        apply_scores(findings)
        assert findings[0].get("score", 0) >= 80
        assert findings[0]["severity"] == "critical"
        assert "score_reasons" in findings[0]

    def test_score_with_unusual_port(self):
        finding = {
            "type": "suspicious",
            "original": "data",
            "severity": "medium",
            "confidence": 0.9,
            "source": "10.0.0.1:4444",
            "destination": "10.0.0.2:80",
        }
        score = score_finding(finding)
        assert "unusual_port" in score.factors


class TestTopology:
    def test_nodes_created(self, mixed_pcap):
        from pcaphunt.pcap_reader import read_pcap
        packets = list(read_pcap(mixed_pcap))
        nodes, edges = build_topology(packets)
        ips = {n.ip for n in nodes}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_edges_created(self, mixed_pcap):
        from pcaphunt.pcap_reader import read_pcap
        packets = list(read_pcap(mixed_pcap))
        nodes, edges = build_topology(packets)
        assert len(edges) > 0
        edge = edges[0]
        assert edge.source_ip in ("10.0.0.1", "10.0.0.2")

    def test_suspicious_nodes(self, mixed_pcap):
        findings = [
            {"type": "flags", "source": "10.0.0.1:12345", "destination": "10.0.0.2:80", "severity": "critical"},
        ]
        from pcaphunt.pcap_reader import read_pcap
        packets = list(read_pcap(mixed_pcap))
        nodes, edges = build_topology(packets, findings)
        suspicious = [n for n in nodes if n.is_suspicious]
        assert len(suspicious) > 0
        assert "10.0.0.1" in [n.ip for n in suspicious]


class TestFilters:
    def test_empty_filter(self):
        findings = [{"type": "flags", "original": "flag{test}"}]
        criteria = FilterCriteria()
        result = filter_findings(findings, criteria)
        assert len(result) == 1

    def test_category_filter(self):
        findings = [
            {"type": "flags", "original": "flag{test}"},
            {"type": "plaintext", "original": "hello"},
        ]
        criteria = FilterCriteria(category="flags")
        result = filter_findings(findings, criteria)
        assert len(result) == 1
        assert result[0]["type"] == "flags"

    def test_protocol_filter(self):
        findings = [
            {"type": "flags", "original": "flag{test}", "protocol": "TCP"},
            {"type": "flags", "original": "flag{test}", "protocol": "UDP"},
        ]
        criteria = FilterCriteria(protocol="TCP")
        result = filter_findings(findings, criteria)
        assert len(result) == 1
        assert result[0]["protocol"] == "TCP"

    def test_ip_filter(self):
        findings = [
            {"type": "flags", "original": "a", "source": "10.0.0.1:12345", "destination": "10.0.0.2:80"},
            {"type": "flags", "original": "b", "source": "10.0.0.3:12345", "destination": "10.0.0.4:80"},
        ]
        criteria = FilterCriteria(ip="10.0.0.1")
        result = filter_findings(findings, criteria)
        assert len(result) == 1

    def test_severity_filter(self):
        findings = [
            {"type": "flags", "original": "a", "severity": "critical"},
            {"type": "plaintext", "original": "b", "severity": "info"},
        ]
        criteria = FilterCriteria(severity="high")
        result = filter_findings(findings, criteria)
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_min_score_filter(self):
        findings = [
            {"type": "flags", "original": "a", "score": 85},
            {"type": "plaintext", "original": "b", "score": 5},
        ]
        criteria = FilterCriteria(min_score=50)
        result = filter_findings(findings, criteria)
        assert len(result) == 1
        assert result[0]["score"] == 85

    def test_search_text_filter(self):
        findings = [
            {"type": "flags", "original": "flag{secret}", "decoded": "flag{secret}"},
            {"type": "plaintext", "original": "hello world"},
        ]
        criteria = FilterCriteria(search_text="secret")
        result = filter_findings(findings, criteria)
        assert len(result) == 1

    def test_combined_filters(self):
        findings = [
            {"type": "flags", "original": "a", "protocol": "TCP", "severity": "critical", "score": 85},
            {"type": "flags", "original": "b", "protocol": "UDP", "severity": "critical", "score": 85},
            {"type": "plaintext", "original": "c", "protocol": "TCP", "severity": "info", "score": 5},
        ]
        criteria = FilterCriteria(protocol="TCP", severity="high")
        result = filter_findings(findings, criteria)
        assert len(result) == 1
        assert result[0]["type"] == "flags"
