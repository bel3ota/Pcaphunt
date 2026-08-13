"""Analysis engine for PcapHunt."""

from __future__ import annotations

import logging
from typing import Any

from pcaphunt.config import Config
from pcaphunt.core import build_context, get_packet_metadata
from pcaphunt.extraction import (
    extract_files_from_payload,
    extract_http_files,
    reset_artifact_counter,
)
from pcaphunt.filters import FilterCriteria, filter_findings
from pcaphunt.models import AnalysisResult, FileArtifact
from pcaphunt.pcap_reader import get_packet_payload, read_pcap
from pcaphunt.plugins import (
    discover_plugins,
    finalize_plugins,
    load_plugins,
    run_plugins_on_packet,
    run_plugins_on_stream,
)
from pcaphunt.profile import build_profile
from pcaphunt.rules import RuleEngine, rules_to_findings
from pcaphunt.scoring import apply_scores
from pcaphunt.timeline import build_timeline
from pcaphunt.topology import build_topology
from pcaphunt.yara_scanner import scan_data, yara_to_findings
from pcaphunt.detectors.base64 import Base64Detector
from pcaphunt.detectors.credentials import CredentialsDetector
from pcaphunt.detectors.domains import DomainDetector
from pcaphunt.detectors.emails import EmailDetector
from pcaphunt.detectors.files import FileDetector
from pcaphunt.detectors.flags import FlagDetector
from pcaphunt.detectors.hashes import HashDetector
from pcaphunt.detectors.hex import HexDetector
from pcaphunt.detectors.ip_addresses import IPAddressDetector
from pcaphunt.detectors.jwt import JWTDetector
from pcaphunt.detectors.plaintext import PlaintextDetector
from pcaphunt.detectors.suspicious import SuspiciousDetector
from pcaphunt.detectors.url_encoded import URLEncodedDetector
from pcaphunt.detectors.urls import URLDetector
from pcaphunt.protocols.extractor import extract_protocols
from pcaphunt.stream_reassembly import (
    get_reassembled_udp_bytes,
    get_udp_conversations,
    reassemble_tcp_streams,
)
from pcaphunt.utils import stable_fingerprint

logger = logging.getLogger(__name__)

DETECTOR_MAP = {
    "plaintext": PlaintextDetector,
    "base64": Base64Detector,
    "hex": HexDetector,
    "url_encoded": URLEncodedDetector,
    "urls": URLDetector,
    "ip_addresses": IPAddressDetector,
    "domains": DomainDetector,
    "emails": EmailDetector,
    "credentials": CredentialsDetector,
    "flags": FlagDetector,
    "hashes": HashDetector,
    "jwt": JWTDetector,
    "files": FileDetector,
    "suspicious": SuspiciousDetector,
}


def create_detectors(config: Config) -> list[Any]:
    """Create detector instances based on config."""
    detectors = []
    enabled = config.enabled_detectors
    detector_config = {
        "min_length": config.min_length,
        "flag_patterns": config.flag_patterns,
        "max_decode_depth": config.max_decode_depth,
    }
    for name in enabled:
        cls = DETECTOR_MAP.get(name)
        if cls:
            detectors.append(cls(detector_config))
    return detectors


def _add_finding(
    finding: dict[str, Any],
    dedup_map: dict[str, dict[str, Any]],
    deduplicate: bool,
) -> None:
    """Add a finding to the deduplication map.

    When deduplication is enabled, findings with identical content are merged:
    packet numbers are combined, and the first_seen_packet of the earliest
    discovery is preserved.
    """
    fp = finding.get("fingerprint")

    if not deduplicate or not fp:
        if not fp:
            fp = stable_fingerprint(finding)
        unique_fp = fp
        counter = 1
        while unique_fp in dedup_map:
            unique_fp = f"{fp}:{counter}"
            counter += 1
        dedup_map[unique_fp] = finding
        return

    if fp in dedup_map:
        existing = dedup_map[fp]
        existing_pkt_nums = set(existing.get("packet_numbers", []))
        for pn in finding.get("packet_numbers", []):
            existing_pkt_nums.add(pn)
        existing["packet_numbers"] = sorted(existing_pkt_nums)

        existing_first = existing.get("first_seen_packet")
        new_first = finding.get("first_seen_packet")
        if new_first is not None:
            if existing_first is None or new_first < existing_first:
                existing["first_seen_packet"] = new_first
                existing["offset"] = finding.get("offset", existing.get("offset"))
                existing["source"] = finding.get("source", existing.get("source"))
                existing["destination"] = finding.get("destination", existing.get("destination"))
                existing["timestamp"] = finding.get("timestamp", existing.get("timestamp"))
                existing["stream_id"] = finding.get("stream_id") or existing.get("stream_id")
    else:
        dedup_map[fp] = finding


# ---------------------------------------------------------------------------
# Core packet analysis (shared by both old and new APIs)
# ---------------------------------------------------------------------------

def _analyze_from_packets(
    packets: list[tuple[int, Any]],
    config: Config,
    detectors: list[Any],
    dedup_map: dict[str, dict[str, Any]],
    deep: bool = False,
    progress_callback=None,
    rule_engine: RuleEngine | None = None,
    plugins: list[Any] | None = None,
    artifacts_out: list[FileArtifact] | None = None,
) -> list[dict[str, Any]]:
    """Analyze a list of pre-read packets and return findings.

    This is the internal engine that both analyze_packets and analyze_pcap use.
    """
    total = len(packets)

    for i, (pkt_num, pkt) in enumerate(packets):
        if progress_callback:
            progress_callback(i + 1, total)

        try:
            meta = get_packet_metadata(pkt, pkt_num)
            context = build_context(meta)
            payload = get_packet_payload(pkt)

            # Run generic detectors on payload
            if payload:
                for detector in detectors:
                    try:
                        findings = detector.detect(payload, context)
                        for finding in findings:
                            _add_finding(finding, dedup_map, config.deduplication)
                    except Exception as exc:
                        logger.debug("Detector %s failed on packet %d: %s", detector.name, pkt_num, exc)

                # Custom rules
                if rule_engine is not None:
                    try:
                        rule_matches = rule_engine.scan(payload, context)
                        rule_findings = rules_to_findings(rule_matches)
                        for rf in rule_findings:
                            _add_finding(rf, dedup_map, config.deduplication)
                    except Exception as exc:
                        logger.debug("Rule engine error on packet %d: %s", pkt_num, exc)

                # File extraction (per-packet)
                # In deep mode we skip per-packet extraction — TCP stream and UDP
                # conversation reassembly produce complete files without truncation.
                if config.get("extract_files", True) and artifacts_out is not None and not deep:
                    try:
                        art_list = extract_files_from_payload(payload, context)
                        artifacts_out.extend(art_list)
                        # HTTP-specific extraction
                        if meta.get("protocol") in ("HTTP", "TCP"):
                            http_arts = extract_http_files(payload, context)
                            for raw_bytes, art in http_arts:
                                artifacts_out.append(art)
                                # Also store raw bytes for later writing
                                art.metadata["_raw_bytes"] = raw_bytes.hex()
                    except Exception as exc:
                        logger.debug("File extraction error on packet %d: %s", pkt_num, exc)

                # YARA on payload
                yara_path = config.get("yara_rules_path", "")
                if yara_path and artifacts_out is not None:
                    try:
                        yara_matches = scan_data(payload, yara_path)
                        yara_findings = yara_to_findings(yara_matches)
                        for yf in yara_findings:
                            _add_finding(yf, dedup_map, config.deduplication)
                    except Exception as exc:
                        logger.debug("YARA scan error on packet %d: %s", pkt_num, exc)

                # Plugins
                if plugins:
                    try:
                        plugin_findings = run_plugins_on_packet(plugins, pkt_num, pkt, payload, context)
                        for pf in plugin_findings:
                            _add_finding(pf, dedup_map, config.deduplication)
                    except Exception as exc:
                        logger.debug("Plugin error on packet %d: %s", pkt_num, exc)

            # Run protocol-aware extractors on the packet itself
            try:
                proto_findings = extract_protocols(pkt, payload)
                for pf in proto_findings:
                    pf["packet_numbers"] = [pkt_num]
                    pf["first_seen_packet"] = pkt_num
                    pf["protocol"] = pf.get("protocol", meta.get("protocol", "Unknown"))
                    pf["source"] = context.get("source", "")
                    pf["destination"] = context.get("destination", "")
                    pf["timestamp"] = meta.get("timestamp")
                    pf["fingerprint"] = stable_fingerprint(pf)
                    _add_finding(pf, dedup_map, config.deduplication)
            except Exception as exc:
                logger.debug("Protocol extraction failed on packet %d: %s", pkt_num, exc)

        except Exception as exc:
            logger.debug("Error processing packet %d: %s", pkt_num, exc)
            continue

    # Deep mode: TCP stream reassembly + UDP conversations
    if deep:
        if progress_callback:
            progress_callback(0, 0)

        # TCP streams
        tcp_streams = reassemble_tcp_streams(packets)
        stream_count = len(tcp_streams)
        for idx, (stream_key, (reassembled, pkt_nums)) in enumerate(tcp_streams.items()):
            if progress_callback:
                progress_callback(idx + 1, stream_count)

            if not reassembled:
                continue

            stream_id = f"tcp_{stream_key[0]}:{stream_key[1]}->{stream_key[2]}:{stream_key[3]}"
            stream_context = {
                "packet_numbers": pkt_nums,
                "first_seen_packet": min(pkt_nums) if pkt_nums else None,
                "protocol": "TCP",
                "source": f"{stream_key[0]}:{stream_key[1]}",
                "destination": f"{stream_key[2]}:{stream_key[3]}",
                "stream_id": stream_id,
            }

            for detector in detectors:
                try:
                    findings = detector.detect(reassembled, stream_context)
                    for finding in findings:
                        _add_finding(finding, dedup_map, config.deduplication)
                except Exception as exc:
                    logger.debug("Detector %s failed on TCP stream: %s", detector.name, exc)

            # Protocol extraction on reassembled TCP stream
            try:
                proto_findings = extract_protocols(None, reassembled)
                for pf in proto_findings:
                    pf["packet_numbers"] = list(pkt_nums)
                    pf["first_seen_packet"] = min(pkt_nums) if pkt_nums else None
                    pf["protocol"] = "TCP"
                    pf["source"] = stream_context["source"]
                    pf["destination"] = stream_context["destination"]
                    pf["stream_id"] = stream_id
                    pf["fingerprint"] = stable_fingerprint(pf)
                    _add_finding(pf, dedup_map, config.deduplication)
            except Exception as exc:
                logger.debug("Protocol extraction failed on TCP stream: %s", exc)

            # File extraction from reassembled stream
            if config.get("extract_files", True) and artifacts_out is not None:
                try:
                    art_list = extract_files_from_payload(reassembled, stream_context, "TCP")
                    artifacts_out.extend(art_list)
                except Exception as exc:
                    logger.debug("File extraction error on TCP stream: %s", exc)

            # Rules on stream
            if rule_engine is not None:
                try:
                    rule_matches = rule_engine.scan(reassembled, stream_context)
                    rule_findings = rules_to_findings(rule_matches)
                    for rf in rule_findings:
                        _add_finding(rf, dedup_map, config.deduplication)
                except Exception as exc:
                    logger.debug("Rule engine error on TCP stream: %s", exc)

            # Plugins on stream
            if plugins:
                try:
                    plugin_findings = run_plugins_on_stream(plugins, stream_id, reassembled, stream_context)
                    for pf in plugin_findings:
                        _add_finding(pf, dedup_map, config.deduplication)
                except Exception as exc:
                    logger.debug("Plugin error on TCP stream %s: %s", stream_id, exc)

        # UDP conversations
        udp_convs = get_udp_conversations(packets)
        for conv_key, conv_data in udp_convs.items():
            if not conv_data:
                continue
            reassembled, pkt_nums = get_reassembled_udp_bytes(conv_data)
            if not reassembled:
                continue

            stream_id = f"udp_{conv_key[0]}:{conv_key[1]}->{conv_key[2]}:{conv_key[3]}"
            conv_context = {
                "packet_numbers": pkt_nums,
                "first_seen_packet": min(pkt_nums) if pkt_nums else None,
                "protocol": "UDP",
                "source": f"{conv_key[0]}:{conv_key[1]}",
                "destination": f"{conv_key[2]}:{conv_key[3]}",
                "stream_id": stream_id,
            }

            for detector in detectors:
                try:
                    findings = detector.detect(reassembled, conv_context)
                    for finding in findings:
                        _add_finding(finding, dedup_map, config.deduplication)
                except Exception as exc:
                    logger.debug("Detector %s failed on UDP conversation: %s", detector.name, exc)

            try:
                proto_findings = extract_protocols(None, reassembled)
                for pf in proto_findings:
                    pf["packet_numbers"] = list(pkt_nums)
                    pf["first_seen_packet"] = min(pkt_nums) if pkt_nums else None
                    pf["protocol"] = "UDP"
                    pf["source"] = conv_context["source"]
                    pf["destination"] = conv_context["destination"]
                    pf["stream_id"] = stream_id
                    pf["fingerprint"] = stable_fingerprint(pf)
                    _add_finding(pf, dedup_map, config.deduplication)
            except Exception as exc:
                logger.debug("Protocol extraction failed on UDP conversation: %s", exc)

            # File extraction from UDP
            if config.get("extract_files", True) and artifacts_out is not None:
                try:
                    art_list = extract_files_from_payload(reassembled, conv_context, "UDP")
                    artifacts_out.extend(art_list)
                except Exception as exc:
                    logger.debug("File extraction error on UDP conversation: %s", exc)

            # Rules on UDP
            if rule_engine is not None:
                try:
                    rule_matches = rule_engine.scan(reassembled, conv_context)
                    rule_findings = rules_to_findings(rule_matches)
                    for rf in rule_findings:
                        _add_finding(rf, dedup_map, config.deduplication)
                except Exception as exc:
                    logger.debug("Rule engine error on UDP conversation: %s", exc)

    # Convert dedup_map values to list
    all_findings = list(dedup_map.values())
    all_findings.sort(key=lambda f: f.get("first_seen_packet") or 0)
    return all_findings


# ---------------------------------------------------------------------------
# Legacy API (backwards compatible)
# ---------------------------------------------------------------------------

def analyze_packets(
    pcap_path: str,
    config: Config,
    deep: bool = False,
    progress_callback=None,
) -> list[dict[str, Any]]:
    """Analyze a PCAP file and return findings.

    This is the Phase 1 API preserved for backwards compatibility.
    """
    detectors = create_detectors(config)
    dedup_map: dict[str, dict[str, Any]] = {}
    packets = list(read_pcap(pcap_path))
    return _analyze_from_packets(
        packets=packets,
        config=config,
        detectors=detectors,
        dedup_map=dedup_map,
        deep=deep,
        progress_callback=progress_callback,
    )


# ---------------------------------------------------------------------------
# Phase 2 Full Analysis API
# ---------------------------------------------------------------------------

def analyze_pcap(
    pcap_path: str,
    config: Config,
    deep: bool = False,
    progress_callback=None,
    filter_criteria: FilterCriteria | None = None,
) -> AnalysisResult:
    """Perform a complete PCAP analysis with all Phase 2 features.

    Args:
        pcap_path: Path to PCAP file.
        config: PcapHunt configuration.
        deep: Enable deep mode.
        progress_callback: Optional progress callback.
        filter_criteria: Optional post-analysis filter criteria.

    Returns:
        AnalysisResult with findings, profile, timeline, artifacts, topology, etc.
    """
    reset_artifact_counter()

    detectors = create_detectors(config)
    dedup_map: dict[str, dict[str, Any]] = {}
    artifacts: list[FileArtifact] = []

    # Load custom rules
    rules_path = config.get("custom_rules", "")
    rule_engine: RuleEngine | None = None
    if rules_path and isinstance(rules_path, str) and rules_path.strip():
        rule_engine = RuleEngine.from_yaml(rules_path)
    elif isinstance(rules_path, list) and rules_path:
        rule_engine = RuleEngine.from_dict_list(rules_path)

    # Load plugins
    plugin_instances = []
    plugins_config = config.get("plugins", [])
    if plugins_config:
        try:
            plugin_classes = discover_plugins()
            plugin_instances = load_plugins(plugin_classes, {})
            for p in plugin_instances:
                p.initialize(config._data if hasattr(config, "_data") else {})
        except Exception as exc:
            logger.debug("Plugin loading error: %s", exc)

    # Read packets once
    packets = list(read_pcap(pcap_path))

    # Core analysis
    findings = _analyze_from_packets(
        packets=packets,
        config=config,
        detectors=detectors,
        dedup_map=dedup_map,
        deep=deep,
        progress_callback=progress_callback,
        rule_engine=rule_engine,
        plugins=plugin_instances,
        artifacts_out=artifacts,
    )

    # Plugin finalization
    if plugin_instances:
        try:
            final_findings = finalize_plugins(plugin_instances)
            for pf in final_findings:
                _add_finding(pf, dedup_map, config.deduplication)
            # Re-convert in case new findings were added
            findings = list(dedup_map.values())
            findings.sort(key=lambda f: f.get("first_seen_packet") or 0)
        except Exception as exc:
            logger.debug("Plugin finalize error: %s", exc)

    # Scoring
    if config.get("enable_scoring", True):
        findings = apply_scores(findings)

    # Profile
    profile = None
    if config.get("enable_profile", True):
        try:
            profile = build_profile(packets, pcap_path)
            profile.findings_count = len(findings)
            profile.flags_count = sum(1 for f in findings if f.get("type") == "flags")
            profile.credentials_count = sum(1 for f in findings if f.get("type") == "credentials")
            profile.files_extracted = len(artifacts)
            profile.encoded_data_count = sum(
                1 for f in findings if f.get("type") in ("base64", "hex", "url_encoded")
            )
        except Exception as exc:
            logger.debug("Profile build error: %s", exc)

    # Topology
    nodes: list[Any] = []
    edges: list[Any] = []
    if config.get("enable_topology", True):
        try:
            nodes, edges = build_topology(packets, findings)
        except Exception as exc:
            logger.debug("Topology build error: %s", exc)

    # Timeline
    timeline = []
    if config.get("enable_timeline", True):
        try:
            timeline = build_timeline(packets, findings, artifacts)
        except Exception as exc:
            logger.debug("Timeline build error: %s", exc)

    # YARA on artifacts
    yara_matches = []
    yara_path = config.get("yara_rules_path", "")
    if yara_path and artifacts:
        from pcaphunt.yara_scanner import scan_data
        for art in artifacts:
            try:
                raw_hex = art.metadata.get("_raw_bytes", "")
                if raw_hex:
                    raw_bytes = bytes.fromhex(raw_hex)
                    matches = scan_data(raw_bytes, yara_path)
                    yara_matches.extend(matches)
            except Exception as exc:
                logger.debug("YARA artifact scan error: %s", exc)

    # Rule matches from engine
    rule_matches = []
    if rule_engine is not None:
        # We don't have a direct list, but rule findings are already in findings
        pass

    # Post-analysis filtering
    if filter_criteria is not None and not filter_criteria.is_empty():
        findings = filter_findings(findings, filter_criteria)

    return AnalysisResult(
        findings=findings,
        profile=profile,
        timeline=timeline,
        artifacts=artifacts,
        nodes=nodes,
        edges=edges,
        yara_matches=yara_matches,
        rule_matches=rule_matches,
    )
