"""Normalized data models for PcapHunt.

All models support JSON serialization via to_dict() and integrate cleanly
with the existing Finding model from pcaphunt.finding.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FileArtifact:
    """Represents an extracted or reconstructed file from network traffic."""

    filename: str
    file_type: str  # MIME type or magic description
    size: int
    source_ip: str
    destination_ip: str
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str = "Unknown"
    stream_id: str | None = None
    first_packet: int | None = None
    last_packet: int | None = None
    timestamp: float | None = None
    extraction_method: str = "unknown"
    complete: bool = True
    completeness_reason: str = ""
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    detected_filename: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        d: dict[str, Any] = {
            "filename": self.filename,
            "file_type": self.file_type,
            "size": self.size,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "complete": self.complete,
            "extraction_method": self.extraction_method,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
        }
        if self.source_port is not None:
            d["source_port"] = self.source_port
        if self.destination_port is not None:
            d["destination_port"] = self.destination_port
        if self.stream_id is not None:
            d["stream_id"] = self.stream_id
        if self.first_packet is not None:
            d["first_packet"] = self.first_packet
        if self.last_packet is not None:
            d["last_packet"] = self.last_packet
        if self.timestamp is not None:
            d["timestamp"] = self.timestamp
        if self.completeness_reason:
            d["completeness_reason"] = self.completeness_reason
        if self.detected_filename is not None:
            d["detected_filename"] = self.detected_filename
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class TimelineEvent:
    """A single event in the investigation timeline."""

    timestamp: float | None
    event_type: str
    description: str
    packet_number: int | None = None
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str = ""
    stream_id: str | None = None
    finding_id: str | None = None
    file_id: str | None = None
    severity: str = "info"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        d: dict[str, Any] = {
            "event_type": self.event_type,
            "description": self.description,
            "severity": self.severity,
        }
        if self.timestamp is not None:
            d["timestamp"] = self.timestamp
        if self.packet_number is not None:
            d["packet_number"] = self.packet_number
        if self.source_ip:
            d["source_ip"] = self.source_ip
        if self.destination_ip:
            d["destination_ip"] = self.destination_ip
        if self.source_port is not None:
            d["source_port"] = self.source_port
        if self.destination_port is not None:
            d["destination_port"] = self.destination_port
        if self.protocol:
            d["protocol"] = self.protocol
        if self.stream_id is not None:
            d["stream_id"] = self.stream_id
        if self.finding_id is not None:
            d["finding_id"] = self.finding_id
        if self.file_id is not None:
            d["file_id"] = self.file_id
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class NetworkNode:
    """A node in the network topology graph."""

    ip: str
    hostname: str | None = None
    mac: str | None = None
    is_suspicious: bool = False
    suspicion_reason: str = ""
    packet_count: int = 0
    byte_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"ip": self.ip, "packet_count": self.packet_count, "byte_count": self.byte_count}
        if self.hostname is not None:
            d["hostname"] = self.hostname
        if self.mac is not None:
            d["mac"] = self.mac
        if self.is_suspicious:
            d["is_suspicious"] = True
        if self.suspicion_reason:
            d["suspicion_reason"] = self.suspicion_reason
        return d


@dataclass
class NetworkEdge:
    """An edge (communication link) in the network topology graph."""

    source_ip: str
    destination_ip: str
    protocol: str = ""
    port: int | None = None
    connection_count: int = 0
    byte_count: int = 0
    packet_count: int = 0
    is_suspicious: bool = False
    suspicion_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "connection_count": self.connection_count,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }
        if self.protocol:
            d["protocol"] = self.protocol
        if self.port is not None:
            d["port"] = self.port
        if self.is_suspicious:
            d["is_suspicious"] = True
        if self.suspicion_reason:
            d["suspicion_reason"] = self.suspicion_reason
        return d


@dataclass
class RiskScore:
    """Risk score for a finding with explanation."""

    score: int  # 0-100
    severity: str  # info, low, medium, high, critical
    reasons: list[str] = field(default_factory=list)
    factors: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "severity": self.severity,
            "reasons": self.reasons,
            "factors": self.factors,
        }

    @classmethod
    def from_score(cls, score: int) -> "RiskScore":
        """Create a RiskScore with severity automatically mapped."""
        if score >= 80:
            severity = "critical"
        elif score >= 60:
            severity = "high"
        elif score >= 40:
            severity = "medium"
        elif score >= 20:
            severity = "low"
        else:
            severity = "info"
        return cls(score=score, severity=severity)


@dataclass
class RuleMatch:
    """Result of a custom detection rule match."""

    rule_name: str
    category: str
    matched_text: str
    severity: str
    confidence: float
    description: str = ""
    packet_number: int | None = None
    source: str = ""
    destination: str = ""
    protocol: str = ""
    stream_id: str | None = None
    offset: int = 0
    timestamp: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "rule_name": self.rule_name,
            "category": self.category,
            "matched_text": self.matched_text,
            "severity": self.severity,
            "confidence": self.confidence,
        }
        if self.description:
            d["description"] = self.description
        if self.packet_number is not None:
            d["packet_number"] = self.packet_number
        if self.source:
            d["source"] = self.source
        if self.destination:
            d["destination"] = self.destination
        if self.protocol:
            d["protocol"] = self.protocol
        if self.stream_id is not None:
            d["stream_id"] = self.stream_id
        if self.offset:
            d["offset"] = self.offset
        if self.timestamp is not None:
            d["timestamp"] = self.timestamp
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass
class YaraMatch:
    """Result of a YARA rule match."""

    rule_name: str
    target: str  # filename or description of what was scanned
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    strings: list[dict[str, Any]] = field(default_factory=list)
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "target": self.target,
            "tags": self.tags,
            "meta": self.meta,
            "strings": self.strings,
            "severity": self.severity,
        }


@dataclass
class AnalysisResult:
    """Complete result of a PCAP analysis."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    profile: NetworkProfile | None = None
    timeline: list[TimelineEvent] = field(default_factory=list)
    artifacts: list[FileArtifact] = field(default_factory=list)
    nodes: list[NetworkNode] = field(default_factory=list)
    edges: list[NetworkEdge] = field(default_factory=list)
    yara_matches: list[YaraMatch] = field(default_factory=list)
    rule_matches: list[RuleMatch] = field(default_factory=list)
    plugins: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"findings": self.findings}
        if self.profile is not None:
            d["profile"] = self.profile.to_dict()
        if self.timeline:
            d["timeline"] = [e.to_dict() for e in self.timeline]
        if self.artifacts:
            d["artifacts"] = [a.to_dict() for a in self.artifacts]
        if self.nodes:
            d["network"] = {
                "nodes": [n.to_dict() for n in self.nodes],
                "edges": [e.to_dict() for e in self.edges],
            }
        if self.yara_matches:
            d["yara"] = [m.to_dict() for m in self.yara_matches]
        if self.rule_matches:
            d["rules"] = [m.to_dict() for m in self.rule_matches]
        if self.plugins:
            d["plugins"] = self.plugins
        return d


@dataclass
class NetworkProfile:
    """Complete profile of a PCAP capture."""

    pcap_name: str = ""
    total_packets: int = 0
    total_bytes: int = 0
    capture_duration_seconds: float = 0.0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    unique_ips: set[str] = field(default_factory=set)
    unique_macs: set[str] = field(default_factory=set)
    unique_ports: set[int] = field(default_factory=set)
    tcp_streams: int = 0
    udp_conversations: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    http_requests: int = 0
    dns_queries: int = 0
    files_extracted: int = 0
    findings_count: int = 0
    flags_count: int = 0
    credentials_count: int = 0
    encoded_data_count: int = 0
    top_source_ips: list[tuple[str, int]] = field(default_factory=list)
    top_destination_ips: list[tuple[str, int]] = field(default_factory=list)
    top_ports: list[tuple[int, int]] = field(default_factory=list)
    top_protocols: list[tuple[str, int]] = field(default_factory=list)
    top_conversations: list[dict[str, Any]] = field(default_factory=list)
    top_domains: list[tuple[str, int]] = field(default_factory=list)
    top_dns_queries: list[tuple[str, int]] = field(default_factory=list)
    top_http_hosts: list[tuple[str, int]] = field(default_factory=list)
    top_http_paths: list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "pcap_name": self.pcap_name,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "capture_duration_seconds": self.capture_duration_seconds,
            "unique_ips_count": len(self.unique_ips),
            "unique_macs_count": len(self.unique_macs),
            "unique_ports_count": len(self.unique_ports),
            "tcp_streams": self.tcp_streams,
            "udp_conversations": self.udp_conversations,
            "protocols": dict(self.protocols),
            "http_requests": self.http_requests,
            "dns_queries": self.dns_queries,
            "files_extracted": self.files_extracted,
            "findings_count": self.findings_count,
            "flags_count": self.flags_count,
            "credentials_count": self.credentials_count,
            "encoded_data_count": self.encoded_data_count,
            "top_source_ips": self.top_source_ips,
            "top_destination_ips": self.top_destination_ips,
            "top_ports": self.top_ports,
            "top_protocols": self.top_protocols,
            "top_conversations": self.top_conversations,
            "top_domains": self.top_domains,
            "top_dns_queries": self.top_dns_queries,
            "top_http_hosts": self.top_http_hosts,
            "top_http_paths": self.top_http_paths,
        }
        if self.first_timestamp is not None:
            d["first_timestamp"] = self.first_timestamp
        if self.last_timestamp is not None:
            d["last_timestamp"] = self.last_timestamp
        if self.unique_ips:
            d["unique_ips"] = sorted(self.unique_ips)
        if self.unique_macs:
            d["unique_macs"] = sorted(self.unique_macs)
        if self.unique_ports:
            d["unique_ports"] = sorted(self.unique_ports)
        return d
