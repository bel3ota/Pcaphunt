"""Analysis engine for PcapHunt."""

import logging
from typing import Any

from pcaphunt.config import Config
from pcaphunt.core import build_context, extract_printable_strings, get_packet_metadata
from pcaphunt.pcap_reader import get_packet_payload
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
from pcaphunt.pcap_reader import read_pcap
from pcaphunt.stream_reassembly import get_reassembled_bytes, get_stream_payloads
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
    """Create detector instances based on config.

    Args:
        config: PcapHunt configuration.

    Returns:
        List of detector instances.
    """
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


def analyze_packets(
    pcap_path: str,
    config: Config,
    deep: bool = False,
    progress_callback=None,
) -> list[dict[str, Any]]:
    """Analyze a PCAP file and return findings.

    Args:
        pcap_path: Path to PCAP file.
        config: PcapHunt configuration.
        deep: Enable deep mode (TCP stream reassembly).
        progress_callback: Optional callback(current, total) for progress updates.

    Returns:
        List of finding dictionaries.
    """
    detectors = create_detectors(config)
    all_findings: list[dict[str, Any]] = []
    dedup_map: dict[str, dict[str, Any]] = {}

    packets = list(read_pcap(pcap_path))
    total = len(packets)

    for i, (pkt_num, pkt) in enumerate(packets):
        if progress_callback:
            progress_callback(i + 1, total)

        try:
            meta = get_packet_metadata(pkt, pkt_num)
            context = build_context(meta)
            payload = get_packet_payload(pkt)

            if not payload:
                continue

            for detector in detectors:
                try:
                    findings = detector.detect(payload, context)
                    for finding in findings:
                        _add_finding(finding, all_findings, dedup_map, config.deduplication)
                except Exception as exc:
                    logger.debug("Detector %s failed on packet %d: %s", detector.name, pkt_num, exc)

        except Exception as exc:
            logger.debug("Error processing packet %d: %s", pkt_num, exc)
            continue

    # Deep mode: TCP stream reassembly
    if deep:
        if progress_callback:
            progress_callback(0, 0)  # Reset for stream phase

        streams = get_stream_payloads(packets)
        stream_total = len(streams)
        for idx, (stream_key, stream_data) in enumerate(streams.items()):
            if progress_callback:
                progress_callback(idx + 1, stream_total)

            try:
                reassembled, pkt_nums = get_reassembled_bytes(stream_data)
                if not reassembled:
                    continue

                stream_context = {
                    "packet_numbers": pkt_nums,
                    "protocol": "TCP",
                    "source": f"{stream_key[0]}:{stream_key[1]}",
                    "destination": f"{stream_key[2]}:{stream_key[3]}",
                }

                for detector in detectors:
                    try:
                        findings = detector.detect(reassembled, stream_context)
                        for finding in findings:
                            _add_finding(finding, all_findings, dedup_map, config.deduplication)
                    except Exception as exc:
                        logger.debug("Detector %s failed on stream: %s", detector.name, exc)

            except Exception as exc:
                logger.debug("Error processing stream: %s", exc)
                continue

    # Merge deduplicated findings
    if config.deduplication:
        for fp, finding in dedup_map.items():
            all_findings.append(finding)

    return all_findings


def _add_finding(
    finding: dict[str, Any],
    all_findings: list[dict[str, Any]],
    dedup_map: dict[str, dict[str, Any]],
    deduplicate: bool,
) -> None:
    """Add a finding, handling deduplication.

    Args:
        finding: New finding.
        all_findings: List of all findings (used when dedup disabled).
        dedup_map: Deduplication map.
        deduplicate: Whether deduplication is enabled.
    """
    if not deduplicate:
        all_findings.append(finding)
        return

    fp = finding.get("fingerprint")
    if not fp:
        all_findings.append(finding)
        return

    if fp in dedup_map:
        existing = dedup_map[fp]
        # Merge packet numbers
        for pn in finding.get("packet_numbers", []):
            if pn not in existing["packet_numbers"]:
                existing["packet_numbers"].append(pn)
                existing["packet_numbers"].sort()
    else:
        dedup_map[fp] = finding
