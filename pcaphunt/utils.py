"""Utility functions for PcapHunt."""

import math
import re
from typing import Any


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string.

    Args:
        data: Byte string to analyze.

    Returns:
        Shannon entropy value between 0 and 8.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = float(data.count(x)) / length
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy


def is_high_entropy(data: bytes, threshold: float = 7.2) -> bool:
    """Check if data has high entropy (likely compressed/encrypted).

    Args:
        data: Byte string to analyze.
        threshold: Entropy threshold above which data is considered high-entropy.

    Returns:
        True if entropy is above threshold.
    """
    return calculate_entropy(data) >= threshold


def stable_fingerprint(finding: dict[str, Any]) -> str:
    """Generate a stable fingerprint for deduplication.

    Args:
        finding: A finding dictionary.

    Returns:
        A hash-like string for deduplication.
    """
    import hashlib

    content = finding.get("decoded") or finding.get("original") or ""
    ftype = finding.get("type", "unknown")
    source = finding.get("source", "")
    dest = finding.get("destination", "")
    key = f"{ftype}:{content}:{source}:{dest}"
    return hashlib.md5(key.encode("utf-8", errors="ignore")).hexdigest()


def recursive_decode(data: str, max_depth: int = 3) -> list[dict[str, Any]]:
    """Recursively attempt to decode encoded data.

    Supports Base64, hex, and URL encoding layers.

    Args:
        data: The string to decode.
        max_depth: Maximum recursion depth.

    Returns:
        List of decoding steps, each with method and result.
    """
    steps: list[dict[str, Any]] = []
    current = data
    depth = 0
    seen = {data}

    while depth < max_depth:
        depth += 1
        decoded = None
        method = None

        # Try URL decode first
        if "%" in current:
            try:
                import urllib.parse

                candidate = urllib.parse.unquote(current)
                if candidate != current and len(candidate) > 0:
                    decoded = candidate
                    method = "URL Decode"
            except Exception:
                pass

        # Try Base64
        if decoded is None:
            b64_pattern = re.compile(r"^[A-Za-z0-9+/=]+$")
            if b64_pattern.match(current) and len(current) >= 4:
                try:
                    import base64

                    # Check padding
                    padding = 4 - len(current) % 4
                    if padding != 4:
                        candidate = current + "=" * padding
                    else:
                        candidate = current
                    result = base64.b64decode(candidate, validate=True)
                    # Must be printable-ish or binary
                    if all(b < 127 or b in (9, 10, 13) for b in result):
                        text = result.decode("utf-8", errors="replace")
                        if text != current and len(text) > 0:
                            decoded = text
                            method = "Base64"
                except Exception:
                    pass

        # Try hex
        if decoded is None:
            hex_pattern = re.compile(r"^[0-9a-fA-F]+$")
            if hex_pattern.match(current) and len(current) % 2 == 0 and len(current) >= 4:
                try:
                    result = bytes.fromhex(current)
                    # Must be printable-ish
                    if all(b < 127 or b in (9, 10, 13) for b in result):
                        text = result.decode("utf-8", errors="replace")
                        if text != current and len(text) > 0:
                            decoded = text
                            method = "Hex"
                except Exception:
                    pass

        if decoded is None or decoded in seen:
            break

        seen.add(decoded)
        steps.append({"method": method, "result": decoded})
        current = decoded

    return steps


def safe_filename(value: str) -> str:
    """Create a safe filename from a string.

    Args:
        value: Input string.

    Returns:
        A safe filename string.
    """
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", value)[:64]
