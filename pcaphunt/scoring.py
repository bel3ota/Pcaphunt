"""Risk scoring system for PcapHunt.

Heuristic scoring to prioritize interesting findings.
Scores range 0-100 with severity mapping.
"""

from __future__ import annotations

import logging
from typing import Any

from pcaphunt.models import RiskScore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Score factors
# ---------------------------------------------------------------------------

CRITICAL_FACTORS: dict[str, int] = {
    "flag_detected": 80,
    "high_confidence_credential": 75,
    "password_plaintext": 70,
    "api_key_detected": 70,
    "private_key_detected": 70,
    "bearer_token": 65,
    "basic_auth": 60,
    "executable_transfer": 60,
    "suspicious_encoded_payload": 55,
}

HIGH_FACTORS: dict[str, int] = {
    "authorization_header": 45,
    "cookie_session": 40,
    "suspicious_dns_label": 35,
    "high_entropy_payload": 35,
    "unusual_port": 30,
    "ftp_credentials": 30,
    "smtp_auth": 30,
}

MEDIUM_FACTORS: dict[str, int] = {
    "encoded_content": 25,
    "jwt_detected": 25,
    "hash_detected": 20,
    "suspicious_file": 20,
    "potential_sensitive_data": 20,
    "irc_command": 15,
}

LOW_FACTORS: dict[str, int] = {
    "plain_url": 10,
    "email_detected": 10,
    "domain_detected": 10,
    "ip_detected": 5,
    "plaintext_strings": 5,
    "metadata": 3,
}

ALL_FACTORS = {**CRITICAL_FACTORS, **HIGH_FACTORS, **MEDIUM_FACTORS, **LOW_FACTORS}


def score_finding(finding: dict[str, Any]) -> RiskScore:
    """Calculate a risk score for a finding.

    Args:
        finding: A finding dictionary.

    Returns:
        RiskScore with score, severity, reasons, and factors.
    """
    ftype = finding.get("type", "")
    severity = finding.get("severity", "info")
    confidence = finding.get("confidence", 1.0)
    original = finding.get("original", "")
    decoded = finding.get("decoded", "")
    content = str(decoded or original or "")
    metadata = finding.get("metadata", {})
    file_type = finding.get("file_type", "")
    entropy = finding.get("entropy")

    factors: dict[str, int] = {}
    reasons: list[str] = []

    # --- Type-based scoring ---

    if ftype == "flags":
        factors["flag_detected"] = CRITICAL_FACTORS["flag_detected"]
        reasons.append("CTF flag pattern matched")

    elif ftype == "credentials":
        if "password" in content.lower() or "passwd" in content.lower():
            factors["password_plaintext"] = CRITICAL_FACTORS["password_plaintext"]
            reasons.append("Password/credential detected")
        elif "api_key" in content.lower() or "apikey" in content.lower():
            factors["api_key_detected"] = CRITICAL_FACTORS["api_key_detected"]
            reasons.append("API key detected")
        elif "private_key" in content.lower() or "BEGIN RSA" in content or "BEGIN OPENSSH" in content:
            factors["private_key_detected"] = CRITICAL_FACTORS["private_key_detected"]
            reasons.append("Private key detected")
        elif "Authorization: Bearer" in content or "bearer" in content.lower():
            factors["bearer_token"] = CRITICAL_FACTORS["bearer_token"]
            reasons.append("Bearer token detected")
        elif "Authorization: Basic" in content:
            factors["basic_auth"] = CRITICAL_FACTORS["basic_auth"]
            reasons.append("Basic authentication detected")
        else:
            factors["high_confidence_credential"] = CRITICAL_FACTORS["high_confidence_credential"]
            reasons.append("Credential/secret detected")

    elif ftype == "files":
        if file_type in ("PE", "ELF", "application/x-elf", "application/x-dosexec"):
            factors["executable_transfer"] = CRITICAL_FACTORS["executable_transfer"]
            reasons.append("Executable file detected")
        else:
            factors["suspicious_file"] = MEDIUM_FACTORS["suspicious_file"]
            reasons.append("File signature detected")

    elif ftype == "suspicious":
        factors["high_entropy_payload"] = HIGH_FACTORS["high_entropy_payload"]
        reasons.append("High-entropy payload (possibly encrypted/compressed)")

    elif ftype == "jwt":
        factors["jwt_detected"] = MEDIUM_FACTORS["jwt_detected"]
        reasons.append("JWT token detected")

    elif ftype == "hashes":
        factors["hash_detected"] = MEDIUM_FACTORS["hash_detected"]
        reasons.append("Cryptographic hash detected")

    elif ftype == "protocol_ftp":
        cmd = str(metadata.get("command", "")).upper()
        if cmd in ("USER", "PASS"):
            factors["ftp_credentials"] = HIGH_FACTORS["ftp_credentials"]
            reasons.append("FTP credential command detected")
        else:
            factors["irc_command"] = MEDIUM_FACTORS["irc_command"]
            reasons.append("FTP activity detected")

    elif ftype == "protocol_smtp":
        if metadata.get("auth") or "AUTH" in content.upper():
            factors["smtp_auth"] = HIGH_FACTORS["smtp_auth"]
            reasons.append("SMTP authentication detected")
        else:
            factors["metadata"] = LOW_FACTORS["metadata"]

    elif ftype == "protocol_dns":
        if metadata.get("suspicious_label") or any(
            label in str(metadata.get("domain", "")).lower()
            for label in ("malware", "c2", "botnet", "phishing")
        ):
            factors["suspicious_dns_label"] = HIGH_FACTORS["suspicious_dns_label"]
            reasons.append("Suspicious DNS label detected")
        else:
            factors["domain_detected"] = LOW_FACTORS["domain_detected"]

    elif ftype == "protocol_http":
        if metadata.get("authorization") or "Authorization" in content:
            factors["authorization_header"] = HIGH_FACTORS["authorization_header"]
            reasons.append("HTTP authorization header detected")
        elif metadata.get("cookie"):
            factors["cookie_session"] = HIGH_FACTORS["cookie_session"]
            reasons.append("HTTP session cookie detected")
        else:
            factors["plain_url"] = LOW_FACTORS["plain_url"]
            reasons.append("HTTP request/response detected")

    elif ftype in ("base64", "hex", "url_encoded"):
        factors["encoded_content"] = MEDIUM_FACTORS["encoded_content"]
        reasons.append(f"Encoded content ({ftype}) detected")

    elif ftype == "urls":
        factors["plain_url"] = LOW_FACTORS["plain_url"]
        reasons.append("URL detected")

    elif ftype == "emails":
        factors["email_detected"] = LOW_FACTORS["email_detected"]
        reasons.append("Email address detected")

    elif ftype == "domains":
        factors["domain_detected"] = LOW_FACTORS["domain_detected"]
        reasons.append("Domain detected")

    elif ftype == "ip_addresses":
        factors["ip_detected"] = LOW_FACTORS["ip_detected"]
        reasons.append("IP address detected")

    elif ftype == "plaintext":
        factors["plaintext_strings"] = LOW_FACTORS["plaintext_strings"]

    # --- Context-based boosts ---

    # Severity boost
    if severity == "critical":
        factors["severity_critical"] = 15
        reasons.append("Severity marked as critical")
    elif severity == "high":
        factors["severity_high"] = 10
        reasons.append("Severity marked as high")
    elif severity == "medium":
        factors["severity_medium"] = 5
    elif severity == "low":
        factors["severity_low"] = 2

    # Confidence boost (0.0-1.0)
    if confidence >= 0.95:
        factors["high_confidence"] = 8
        reasons.append("High confidence match")
    elif confidence >= 0.8:
        factors["high_confidence"] = 5
    elif confidence >= 0.5:
        factors["medium_confidence"] = 2

    # Unusual port check
    sport = _get_port_from_addr(finding.get("source", ""))
    dport = _get_port_from_addr(finding.get("destination", ""))
    unusual_ports = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321}
    if (sport in unusual_ports) or (dport in unusual_ports):
        factors["unusual_port"] = HIGH_FACTORS["unusual_port"]
        reasons.append("Unusual port detected")

    # Stream context boost — finding in a reconstructed stream is often more significant
    if finding.get("stream_id"):
        factors["stream_context"] = 3

    # Entropy boost
    if entropy is not None and entropy >= 7.5:
        factors["high_entropy"] = 5
        if "high_entropy_payload" not in factors:
            reasons.append("Very high entropy payload")

    # Calculate total score, capping at 100
    total = sum(factors.values())
    score = min(total, 100)

    # If no factors matched, give a small baseline score based on type
    if score == 0:
        score = 1

    risk = RiskScore.from_score(score)
    risk.factors = factors
    risk.reasons = reasons if reasons else ["Baseline finding"]

    return risk


def apply_scores(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply risk scoring to all findings in-place.

    Returns the modified findings list.
    """
    for finding in findings:
        try:
            risk = score_finding(finding)
            finding["score"] = risk.score
            finding["score_reasons"] = risk.reasons
            finding["score_factors"] = risk.factors
            # Upgrade severity if score suggests higher severity
            if risk.severity != finding.get("severity", "info"):
                # Only upgrade, never downgrade
                severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
                current = severity_order.get(finding.get("severity", "info"), 0)
                new = severity_order.get(risk.severity, 0)
                if new > current:
                    finding["severity"] = risk.severity
        except Exception as exc:
            logger.debug("Scoring error for finding: %s", exc)
    return findings


def _get_port_from_addr(addr: str) -> int | None:
    if not addr or ":" not in addr:
        return None
    parts = addr.rsplit(":", 1)
    if parts[1].isdigit():
        return int(parts[1])
    return None
