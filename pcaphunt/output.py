"""Output generation for PcapHunt findings."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pcaphunt.models import FileArtifact

logger = logging.getLogger(__name__)

OUTPUT_DIRS = [
    "plaintext",
    "base64",
    "hex",
    "url_encoded",
    "urls",
    "ip_addresses",
    "domains",
    "emails",
    "credentials",
    "flags",
    "hashes",
    "jwt",
    "files",
    "suspicious",
    "streams",
    "protocol_http",
    "protocol_dns",
    "protocol_ftp",
    "protocol_smtp",
    "protocol_irc",
    "protocol_dhcp",
    "extracted_files",
    "yara",
    "rules",
]


def create_output_structure(base_dir: str) -> Path:
    """Create the output directory structure."""
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    for subdir in OUTPUT_DIRS:
        (base / subdir).mkdir(parents=True, exist_ok=True)
    return base


def format_finding_text(finding: dict[str, Any]) -> str:
    """Format a finding as human-readable text."""
    lines = [
        "PcapHunt Finding",
        "================",
        "",
        f"Type: {finding.get('type', 'Unknown')}",
    ]

    pkt_nums = finding.get("packet_numbers", [])
    if len(pkt_nums) == 1:
        lines.append(f"Packet: {pkt_nums[0]}")
    else:
        lines.append(f"Packets: {', '.join(str(n) for n in pkt_nums)}")

    if finding.get("first_seen_packet") is not None:
        lines.append(f"First Seen: Packet {finding['first_seen_packet']}")

    if finding.get("protocol"):
        lines.append(f"Protocol: {finding['protocol']}")
    if finding.get("source"):
        lines.append(f"Source: {finding['source']}")
    if finding.get("destination"):
        lines.append(f"Destination: {finding['destination']}")
    if finding.get("stream_id"):
        lines.append(f"Stream: {finding['stream_id']}")
    if finding.get("timestamp"):
        try:
            from datetime import datetime
            ts = datetime.fromtimestamp(finding["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"Timestamp: {ts}")
        except Exception:
            pass
    if finding.get("offset") is not None:
        lines.append(f"Offset: {finding['offset']}")
    if finding.get("confidence") is not None:
        lines.append(f"Confidence: {finding['confidence']:.2f}")
    if finding.get("severity"):
        lines.append(f"Severity: {finding['severity'].upper()}")
    if finding.get("score") is not None:
        lines.append(f"Score: {finding['score']}")
        if finding.get("score_reasons"):
            lines.append("Score Reasons:")
            for reason in finding["score_reasons"]:
                lines.append(f"  - {reason}")
    if finding.get("file_type"):
        lines.append(f"File Type: {finding['file_type']}")
    if finding.get("entropy") is not None:
        lines.append(f"Entropy: {finding['entropy']:.2f}")

    lines.append("")
    if finding.get("original"):
        lines.append("Original:")
        lines.append(str(finding["original"]))
        lines.append("")

    if finding.get("decoded") and finding["decoded"] != finding.get("original"):
        lines.append("Decoded:")
        lines.append(str(finding["decoded"]))
        lines.append("")

    if finding.get("decoding_steps"):
        lines.append("Decoding Steps:")
        for step in finding["decoding_steps"]:
            lines.append(f"  {step['method']}: {step['result']}")
        lines.append("")

    if finding.get("notes"):
        lines.append(f"Notes: {finding['notes']}")
        lines.append("")

    if finding.get("metadata"):
        lines.append("Metadata:")
        for k, v in finding["metadata"].items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    return "\n".join(lines)


class FileCounter:
    """Track file counts per directory to avoid overwrites."""

    def __init__(self):
        self._counts: dict[str, int] = {}

    def next(self, directory: str, prefix: str) -> str:
        """Get the next available filename."""
        key = f"{directory}/{prefix}"
        self._counts[key] = self._counts.get(key, 0) + 1
        count = self._counts[key]
        if count == 1:
            return f"{prefix}.txt"
        return f"{prefix}_{count:02d}.txt"


def write_findings(
    findings: list[dict[str, Any]],
    base_dir: str,
) -> None:
    """Write all findings to output files."""
    base = create_output_structure(base_dir)
    counter = FileCounter()

    for finding in findings:
        ftype = finding.get("type", "unknown")
        dir_name = ftype if ftype in OUTPUT_DIRS else "suspicious"
        dir_path = base / dir_name

        pkt_nums = finding.get("packet_numbers", [])
        first_seen = finding.get("first_seen_packet")
        prefix_pkt = first_seen if first_seen is not None else (pkt_nums[0] if pkt_nums else "finding")
        prefix = f"packet_{prefix_pkt}"

        filename = counter.next(str(dir_path), prefix)
        filepath = dir_path / filename

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(format_finding_text(finding))
        except Exception as exc:
            logger.warning("Failed to write finding to %s: %s", filepath, exc)

    # Write summary
    summary_path = base / "summary.txt"
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(format_summary(findings))
    except Exception as exc:
        logger.warning("Failed to write summary: %s", exc)

    # Write JSON
    json_path = base / "findings.json"
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, ensure_ascii=False, default=str)
    except Exception as exc:
        logger.warning("Failed to write JSON: %s", exc)


def write_full_output(result, base_dir: str) -> None:
    """Write complete Phase 2 output including findings, artifacts, profile, timeline, topology."""
    base = create_output_structure(base_dir)

    # Write findings (standard)
    write_findings(result.findings, base_dir)

    # Write artifacts (extracted files)
    if result.artifacts:
        extracted_dir = base / "extracted_files"
        extracted_dir.mkdir(parents=True, exist_ok=True)
        for artifact in result.artifacts:
            try:
                # Write artifact metadata
                meta_path = extracted_dir / f"{artifact.filename}.meta.json"
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(artifact.to_dict(), f, indent=2, ensure_ascii=False, default=str)
                # Write raw file data if available
                raw_hex = artifact.metadata.get("_raw_bytes", "")
                if raw_hex:
                    raw_bytes = bytes.fromhex(raw_hex)
                    file_path = extracted_dir / artifact.filename
                    # Prevent overwriting
                    counter = 1
                    orig_path = file_path
                    while file_path.exists():
                        stem = orig_path.stem
                        suffix = orig_path.suffix
                        file_path = extracted_dir / f"{stem}_{counter:02d}{suffix}"
                        counter += 1
                    with open(file_path, "wb") as f:
                        f.write(raw_bytes)
            except Exception as exc:
                logger.warning("Failed to write artifact %s: %s", artifact.filename, exc)

    # Write profile
    if result.profile is not None:
        profile_path = base / "profile.json"
        try:
            with open(profile_path, "w", encoding="utf-8") as f:
                json.dump(result.profile.to_dict(), f, indent=2, ensure_ascii=False, default=str)
        except Exception as exc:
            logger.warning("Failed to write profile: %s", exc)

    # Write timeline
    if result.timeline:
        timeline_path = base / "timeline.json"
        try:
            with open(timeline_path, "w", encoding="utf-8") as f:
                json.dump(
                    [e.to_dict() for e in result.timeline],
                    f,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
        except Exception as exc:
            logger.warning("Failed to write timeline: %s", exc)

    # Write topology
    if result.nodes or result.edges:
        topology_path = base / "topology.json"
        try:
            topo = {
                "nodes": [n.to_dict() for n in result.nodes],
                "edges": [e.to_dict() for e in result.edges],
            }
            with open(topology_path, "w", encoding="utf-8") as f:
                json.dump(topo, f, indent=2, ensure_ascii=False, default=str)
        except Exception as exc:
            logger.warning("Failed to write topology: %s", exc)

    # Write YARA matches
    if result.yara_matches:
        yara_path = base / "yara_matches.json"
        try:
            with open(yara_path, "w", encoding="utf-8") as f:
                json.dump(
                    [m.to_dict() for m in result.yara_matches],
                    f,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
        except Exception as exc:
            logger.warning("Failed to write YARA matches: %s", exc)

    # Write combined full result
    full_path = base / "full_result.json"
    try:
        with open(full_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False, default=str)
    except Exception as exc:
        logger.warning("Failed to write full result: %s", exc)


def format_summary(findings: list[dict[str, Any]]) -> str:
    """Format a text summary of findings."""
    counts: dict[str, int] = {}
    flags: list[str] = []

    for f in findings:
        ftype = f.get("type", "unknown")
        counts[ftype] = counts.get(ftype, 0) + 1
        if ftype == "flags" and f.get("decoded"):
            flags.append(str(f["decoded"]))

    lines = [
        "PcapHunt Summary",
        "================",
        "",
        "Findings by Type:",
    ]

    order = [
        "plaintext",
        "base64",
        "hex",
        "url_encoded",
        "urls",
        "ip_addresses",
        "domains",
        "emails",
        "credentials",
        "flags",
        "hashes",
        "jwt",
        "files",
        "suspicious",
        "protocol_http",
        "protocol_dns",
        "protocol_ftp",
        "protocol_smtp",
        "protocol_irc",
        "protocol_dhcp",
    ]

    for ftype in order:
        count = counts.get(ftype, 0)
        if count > 0:
            label = ftype.replace("protocol_", "").replace("_", " ").title()
            lines.append(f"  {label:20s} {count}")

    other = sum(v for k, v in counts.items() if k not in order)
    if other:
        lines.append(f"  {'Other':20s} {other}")

    lines.append("")
    if flags:
        lines.append("Flags Found:")
        for flag in flags:
            lines.append(f"  {flag}")
        lines.append("")

    # Protocol findings summary
    proto_types = [k for k in counts if k.startswith("protocol_")]
    if proto_types:
        lines.append("Protocol Findings:")
        for ptype in sorted(proto_types):
            label = ptype.replace("protocol_", "").upper()
            lines.append(f"  {label:20s} {counts[ptype]}")
        lines.append("")

    lines.append(f"Total Findings: {len(findings)}")
    return "\n".join(lines) + "\n"


def get_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Get counts of findings by type."""
    counts: dict[str, int] = {}
    for f in findings:
        ftype = f.get("type", "unknown")
        counts[ftype] = counts.get(ftype, 0) + 1
    return counts
