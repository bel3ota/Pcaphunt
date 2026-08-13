"""DNS protocol extractor for PcapHunt."""

import re
from typing import Any

from scapy.all import DNS, DNSQR, DNSRR
from scapy.packet import Packet


def extract_dns(pkt: Packet) -> list[dict[str, Any]]:
    """Extract DNS-related findings from a Scapy packet.

    Args:
        pkt: Scapy packet that may contain a DNS layer.

    Returns:
        List of finding-like dictionaries.
    """
    results: list[dict[str, Any]] = []
    if not pkt.haslayer(DNS):
        return results

    dns = pkt[DNS]

    # DNS query
    if dns.qdcount and int(dns.qdcount) > 0 and dns.qd:
        qname = str(dns.qd.qname.decode() if isinstance(dns.qd.qname, bytes) else dns.qd.qname).rstrip(".")
        qtype = dns.qd.qtype if hasattr(dns.qd, "qtype") else "?"
        results.append({
            "type": "protocol_dns",
            "original": f"DNS query: {qname} (type {qtype})",
            "decoded": None,
            "offset": 0,
            "confidence": 0.98,
            "severity": "info",
            "metadata": {
                "dns_query": qname,
                "dns_qtype": qtype,
            },
        })

        # Heuristic: suspicious-looking DNS (high-entropy subdomains, encoding)
        labels = qname.split(".")
        for label in labels:
            if len(label) > 40:
                # Very long subdomain — possibly DNS tunneling or encoded data
                results.append({
                    "type": "protocol_dns",
                    "original": f"Suspicious DNS label: {label[:60]}...",
                    "decoded": None,
                    "offset": 0,
                    "confidence": 0.75,
                    "severity": "medium",
                    "metadata": {
                        "dns_suspicious_label": label,
                        "dns_query": qname,
                        "heuristic": "long_subdomain",
                    },
                })
                break
            # Check if label looks like Base64 or hex
            if re.match(r"^[A-Za-z0-9+/=]{20,}$", label) or re.match(r"^[0-9a-fA-F]{20,}$", label):
                results.append({
                    "type": "protocol_dns",
                    "original": f"Encoded-looking DNS label: {label[:60]}",
                    "decoded": None,
                    "offset": 0,
                    "confidence": 0.70,
                    "severity": "low",
                    "metadata": {
                        "dns_suspicious_label": label,
                        "dns_query": qname,
                        "heuristic": "encoded_label",
                    },
                })
                break

    # DNS response records
    if dns.ancount and int(dns.ancount) > 0:
        for i in range(int(dns.ancount)):
            rr = dns.an[i] if hasattr(dns.an, "__getitem__") else None
            if rr is None:
                continue
            try:
                rname = str(rr.rrname.decode() if isinstance(rr.rrname, bytes) else rr.rrname).rstrip(".")
                rdata = str(rr.rdata) if hasattr(rr, "rdata") else ""
                rtype = rr.type if hasattr(rr, "type") else "?"
                if rdata:
                    results.append({
                        "type": "protocol_dns",
                        "original": f"DNS answer: {rname} -> {rdata} (type {rtype})",
                        "decoded": None,
                        "offset": 0,
                        "confidence": 0.95,
                        "severity": "info",
                        "metadata": {
                            "dns_answer_name": rname,
                            "dns_answer_data": rdata,
                            "dns_answer_type": rtype,
                        },
                    })
            except Exception:
                continue

    return results
