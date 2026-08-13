"""SMTP protocol extractor for PcapHunt."""

import re
from typing import Any


_SMTP_COMMANDS = [
    (r"\bMAIL FROM:\s*<([^>]+)>", "smtp_from", "info"),
    (r"\bRCPT TO:\s*<([^>]+)>", "smtp_to", "info"),
    (r"\bAUTH\s+([A-Za-z0-9_\-\+\=\/\s]+)", "smtp_auth", "high"),
]


def extract_smtp(data: bytes) -> list[dict[str, Any]]:
    """Extract SMTP-related findings from raw bytes.

    Args:
        data: Raw payload bytes.

    Returns:
        List of finding-like dictionaries.
    """
    results: list[dict[str, Any]] = []
    if not data or len(data) < 4:
        return results

    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return results

    for pattern, meta_key, severity in _SMTP_COMMANDS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(1).strip()
            if not value:
                continue
            results.append({
                "type": "protocol_smtp",
                "original": f"SMTP {meta_key}: {value}",
                "decoded": None,
                "offset": match.start(),
                "confidence": 0.90,
                "severity": severity,
                "metadata": {meta_key: value},
            })

    # Subject, Date, Message-ID headers
    for match in re.finditer(r"^Subject:\s*(.+)", text, re.MULTILINE | re.IGNORECASE):
        results.append({
            "type": "protocol_smtp",
            "original": f"Subject: {match.group(1).strip()}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.88,
            "severity": "info",
            "metadata": {"smtp_subject": match.group(1).strip()},
        })

    for match in re.finditer(r"^Date:\s*(.+)", text, re.MULTILINE | re.IGNORECASE):
        results.append({
            "type": "protocol_smtp",
            "original": f"Date: {match.group(1).strip()}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.85,
            "severity": "info",
            "metadata": {"smtp_date": match.group(1).strip()},
        })

    return results
