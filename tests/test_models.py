"""Tests for PcapHunt Phase 2 data models."""

from __future__ import annotations

import pytest

from pcaphunt.models import (
    AnalysisResult,
    FileArtifact,
    NetworkEdge,
    NetworkNode,
    NetworkProfile,
    RiskScore,
    RuleMatch,
    TimelineEvent,
    YaraMatch,
)


class TestRiskScore:
    def test_from_score_info(self):
        rs = RiskScore.from_score(10)
        assert rs.score == 10
        assert rs.severity == "info"

    def test_from_score_low(self):
        rs = RiskScore.from_score(25)
        assert rs.severity == "low"

    def test_from_score_medium(self):
        rs = RiskScore.from_score(45)
        assert rs.severity == "medium"

    def test_from_score_high(self):
        rs = RiskScore.from_score(65)
        assert rs.severity == "high"

    def test_from_score_critical(self):
        rs = RiskScore.from_score(85)
        assert rs.severity == "critical"

    def test_to_dict(self):
        rs = RiskScore(score=50, severity="medium", reasons=["test"], factors={"a": 10})
        d = rs.to_dict()
        assert d["score"] == 50
        assert d["severity"] == "medium"
        assert d["reasons"] == ["test"]
        assert d["factors"] == {"a": 10}


class TestFileArtifact:
    def test_to_dict(self):
        art = FileArtifact(
            filename="test.png",
            file_type="image/png",
            size=1234,
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            complete=True,
            md5="abc",
            sha1="def",
            sha256="ghi",
        )
        d = art.to_dict()
        assert d["filename"] == "test.png"
        assert d["file_type"] == "image/png"
        assert d["size"] == 1234
        assert d["complete"] is True
        assert d["md5"] == "abc"

    def test_optional_fields_omitted(self):
        art = FileArtifact(
            filename="test.bin",
            file_type="application/octet-stream",
            size=0,
            source_ip="",
            destination_ip="",
        )
        d = art.to_dict()
        assert "source_port" not in d
        assert "stream_id" not in d


class TestTimelineEvent:
    def test_to_dict(self):
        te = TimelineEvent(
            timestamp=1234567890.0,
            event_type="dns_query",
            description="query example.com",
            packet_number=5,
            severity="low",
        )
        d = te.to_dict()
        assert d["timestamp"] == 1234567890.0
        assert d["event_type"] == "dns_query"
        assert d["severity"] == "low"


class TestNetworkNode:
    def test_to_dict(self):
        node = NetworkNode(ip="192.168.1.1", hostname="router", packet_count=10, byte_count=1024)
        d = node.to_dict()
        assert d["ip"] == "192.168.1.1"
        assert d["hostname"] == "router"
        assert d["packet_count"] == 10


class TestNetworkEdge:
    def test_to_dict(self):
        edge = NetworkEdge(
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            protocol="TCP",
            port=80,
            connection_count=5,
        )
        d = edge.to_dict()
        assert d["source_ip"] == "10.0.0.1"
        assert d["protocol"] == "TCP"
        assert d["port"] == 80


class TestNetworkProfile:
    def test_to_dict(self):
        prof = NetworkProfile(
            pcap_name="test.pcap",
            total_packets=100,
            unique_ips={"10.0.0.1", "10.0.0.2"},
        )
        d = prof.to_dict()
        assert d["pcap_name"] == "test.pcap"
        assert d["total_packets"] == 100
        assert d["unique_ips_count"] == 2
        assert "unique_ips" in d


class TestRuleMatch:
    def test_to_dict(self):
        rm = RuleMatch(
            rule_name="test_rule",
            category="flag",
            matched_text="FLAG{test}",
            severity="high",
            confidence=0.95,
        )
        d = rm.to_dict()
        assert d["rule_name"] == "test_rule"
        assert d["matched_text"] == "FLAG{test}"


class TestYaraMatch:
    def test_to_dict(self):
        ym = YaraMatch(
            rule_name="Suspicious",
            target="payload.bin",
            tags=["malware"],
            severity="critical",
        )
        d = ym.to_dict()
        assert d["rule_name"] == "Suspicious"
        assert d["tags"] == ["malware"]


class TestAnalysisResult:
    def test_to_dict_structure(self):
        result = AnalysisResult(
            findings=[{"type": "flags", "original": "flag{test}"}],
            profile=NetworkProfile(total_packets=10),
            timeline=[TimelineEvent(timestamp=1.0, event_type="test", description="d")],
        )
        d = result.to_dict()
        assert "findings" in d
        assert "profile" in d
        assert "timeline" in d
        assert "artifacts" not in d  # empty list omitted
