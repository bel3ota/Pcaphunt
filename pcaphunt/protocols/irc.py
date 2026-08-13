"""IRC protocol extractor for PcapHunt."""

import re
from typing import Any


def extract_irc(data: bytes) -> list[dict[str, Any]]:
    """Extract IRC-related findings from raw bytes.

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

    # NICK
    for match in re.finditer(r"^NICK\s+(.+)", text, re.MULTILINE | re.IGNORECASE):
        nick = match.group(1).strip()
        results.append({
            "type": "protocol_irc",
            "original": f"NICK {nick}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.95,
            "severity": "info",
            "metadata": {"irc_nick": nick},
        })

    # JOIN
    for match in re.finditer(r"^JOIN\s+(.+)", text, re.MULTILINE | re.IGNORECASE):
        chan = match.group(1).strip()
        results.append({
            "type": "protocol_irc",
            "original": f"JOIN {chan}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.95,
            "severity": "info",
            "metadata": {"irc_channel": chan},
        })

    # PRIVMSG
    for match in re.finditer(
        r"^PRIVMSG\s+(\S+)\s+:(.+)", text, re.MULTILINE | re.IGNORECASE
    ):
        target = match.group(1).strip()
        msg = match.group(2).strip()
        results.append({
            "type": "protocol_irc",
            "original": f"PRIVMSG {target} :{msg}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.92,
            "severity": "info",
            "metadata": {"irc_target": target, "irc_message": msg},
        })

    # PART
    for match in re.finditer(r"^PART\s+(.+)", text, re.MULTILINE | re.IGNORECASE):
        chan = match.group(1).strip()
        results.append({
            "type": "protocol_irc",
            "original": f"PART {chan}",
            "decoded": None,
            "offset": match.start(),
            "confidence": 0.90,
            "severity": "info",
            "metadata": {"irc_channel": chan},
        })

    return results
