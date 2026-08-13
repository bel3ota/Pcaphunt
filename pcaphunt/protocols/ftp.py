"""FTP protocol extractor for PcapHunt."""

import re
from typing import Any


# Common FTP commands that carry useful data
_FTP_COMMANDS = [
    (r"\bUSER\s+(.+)\b", "ftp_user", "info"),
    (r"\bPASS\s+(.+)\b", "ftp_pass", "high"),
    (r"\bRETR\s+(.+)\b", "ftp_retr", "info"),
    (r"\bSTOR\s+(.+)\b", "ftp_stor", "info"),
    (r"\bCWD\s+(.+)\b", "ftp_cwd", "info"),
    (r"\bMKD\s+(.+)\b", "ftp_mkd", "info"),
]


def extract_ftp(data: bytes) -> list[dict[str, Any]]:
    """Extract FTP-related findings from raw bytes.

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

    for pattern, meta_key, severity in _FTP_COMMANDS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(1).strip()
            if not value:
                continue
            results.append({
                "type": "protocol_ftp",
                "original": f"FTP {meta_key}: {value}",
                "decoded": None,
                "offset": match.start(),
                "confidence": 0.90,
                "severity": severity,
                "metadata": {meta_key: value},
            })

    # FTP responses with codes
    for match in re.finditer(r"^(\d{3})\s+(.+)", text, re.MULTILINE):
        code = match.group(1)
        msg = match.group(2).strip()
        results.append({
            "type": "protocol_ftp",
            "original": f"FTP {code} {msg}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.85,
            "severity": "info",
            "metadata": {"ftp_response_code": code, "ftp_response_msg": msg},
        })

    return results
