"""Protocol extraction dispatcher for PcapHunt."""

from typing import Any

from scapy.packet import Packet

from pcaphunt.protocols.dhcp import extract_dhcp
from pcaphunt.protocols.dns import extract_dns
from pcaphunt.protocols.ftp import extract_ftp
from pcaphunt.protocols.http import extract_http
from pcaphunt.protocols.irc import extract_irc
from pcaphunt.protocols.smtp import extract_smtp


def extract_protocols(pkt: Packet, payload: bytes) -> list[dict[str, Any]]:
    """Run all protocol extractors on a packet and its payload.

    Args:
        pkt: Scapy packet.
        payload: Raw payload bytes.

    Returns:
        List of finding-like dictionaries.
    """
    results: list[dict[str, Any]] = []

    # DNS (works on the packet itself)
    results.extend(extract_dns(pkt))

    # HTTP — check if payload looks like HTTP
    if payload:
        http_results = extract_http(payload)
        if http_results:
            results.extend(http_results)
        else:
            # FTP/SMTP/IRC only if not HTTP (avoid false positives)
            ftp_results = extract_ftp(payload)
            if ftp_results:
                results.extend(ftp_results)
            else:
                smtp_results = extract_smtp(payload)
                if smtp_results:
                    results.extend(smtp_results)
                else:
                    irc_results = extract_irc(payload)
                    if irc_results:
                        results.extend(irc_results)
                    else:
                        dhcp_results = extract_dhcp(payload)
                        results.extend(dhcp_results)

    return results
