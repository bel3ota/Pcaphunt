"""DHCP protocol extractor for PcapHunt."""

import re
from typing import Any


def extract_dhcp(data: bytes) -> list[dict[str, Any]]:
    """Extract DHCP-related findings from raw bytes.

    Uses simple heuristics on DHCP payload bytes since Scapy DHCP
    dissection varies by version.

    Args:
        data: Raw payload bytes.

    Returns:
        List of finding-like dictionaries.
    """
    results: list[dict[str, Any]] = []
    if not data or len(data) < 20:
        return results

    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return results

    # Common DHCP option strings that appear in some captures
    # Hostname
    for match in re.finditer(r"hostname[=:]\s*([^\x00\s]+)", text, re.IGNORECASE):
        hostname = match.group(1).strip()
        results.append({
            "type": "protocol_dhcp",
            "original": f"DHCP hostname: {hostname}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.80,
            "severity": "info",
            "metadata": {"dhcp_hostname": hostname},
        })

    # Client MAC hint (if readable)
    for match in re.finditer(r"client[_\-]?mac[=:]\s*([0-9a-fA-F:]{12,17})", text, re.IGNORECASE):
        mac = match.group(1).strip()
        results.append({
            "type": "protocol_dhcp",
            "original": f"DHCP client MAC: {mac}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.85,
            "severity": "info",
            "metadata": {"dhcp_client_mac": mac},
        })

    # Requested IP
    for match in re.finditer(r"requested[_\-]?ip[=:]\s*(\d+\.\d+\.\d+\.\d+)", text, re.IGNORECASE):
        ip = match.group(1).strip()
        results.append({
            "type": "protocol_dhcp",
            "original": f"DHCP requested IP: {ip}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.85,
            "severity": "info",
            "metadata": {"dhcp_requested_ip": ip},
        })

    return results
