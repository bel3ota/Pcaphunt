"""Output generation for PcapHunt findings."""

import json
import logging
import os
from pathlib import Path
from typing import Any

from pcaphunt.utils import safe_filename

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
]


def create_output_structure(base_dir: str) -> Path:
    """Create the output directory structure.

    Args:
        base_dir: Base output directory path.

    Returns:
        Path to base output directory.
    """
    base = Path(base_dir)
    base.mkdir(parents=True, exist_ok=True)
    for subdir in OUTPUT_DIRS:
        (base / subdir).mkdir(parents=True, exist_ok=True)
    return base


def format_finding_text(finding: dict[str, Any]) -> str:
    """Format a finding as human-readable text.

    Args:
        finding: Finding dictionary.

    Returns:
        Formatted text string.
    """
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
    if finding.get("offset") is not None:
        lines.append(f"Offset: {finding['offset']}")
    if finding.get("confidence") is not None:
        lines.append(f"Confidence: {finding['confidence']:.2f}")
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

    return "\n".join(lines)


class FileCounter:
    """Track file counts per directory to avoid overwrites."""

    def __init__(self):
        self._counts: dict[str, int] = {}

    def next(self, directory: str, prefix: str) -> str:
        """Get the next available filename.

        Args:
            directory: Directory name.
            prefix: Filename prefix.

        Returns:
            Next available filename.
        """
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
    """Write all findings to output files.

    Args:
        findings: List of finding dictionaries.
        base_dir: Base output directory.
    """
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


def format_summary(findings: list[dict[str, Any]]) -> str:
    """Format a text summary of findings.

    Args:
        findings: List of finding dictionaries.

    Returns:
        Summary text.
    """
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
    ]

    for ftype in order:
        count = counts.get(ftype, 0)
        lines.append(f"  {ftype.replace('_', ' ').title():20s} {count}")

    other = sum(v for k, v in counts.items() if k not in order)
    if other:
        lines.append(f"  {'Other':20s} {other}")

    lines.append("")
    if flags:
        lines.append("Flags Found:")
        for flag in flags:
            lines.append(f"  {flag}")
        lines.append("")

    lines.append(f"Total Findings: {len(findings)}")
    return "\n".join(lines) + "\n"


def get_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Get counts of findings by type.

    Args:
        findings: List of finding dictionaries.

    Returns:
        Dictionary mapping type to count.
    """
    counts: dict[str, int] = {}
    for f in findings:
        ftype = f.get("type", "unknown")
        counts[ftype] = counts.get(ftype, 0) + 1
    return counts
