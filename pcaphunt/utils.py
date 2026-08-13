"""Utility functions for PcapHunt."""

import base64
import hashlib
import html
import math
import re
import zlib
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
    """Generate a stable content-based fingerprint for deduplication.

    The fingerprint is based solely on the detector type and the actual
    extracted/decoded content, NOT on packet numbers or source/destination.
    This ensures that the same content discovered in different packets
    or streams is deduplicated correctly.

    Args:
        finding: A finding dictionary.

    Returns:
        A hex hash string for deduplication.
    """
    content = finding.get("decoded") or finding.get("original") or ""
    ftype = finding.get("type", "unknown")
    key = f"{ftype}:{content}"
    return hashlib.sha256(key.encode("utf-8", errors="ignore")).hexdigest()


def _try_base32(text: str) -> str | None:
    """Attempt to decode Base32 string."""
    import base64
    try:
        if not re.match(r"^[A-Z2-7=]+$", text):
            return None
        if len(text) % 8 != 0 and not text.endswith("="):
            return None
        decoded = base64.b32decode(text, casefold=True)
        if all(b < 127 or b in (9, 10, 13) for b in decoded):
            return decoded.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _try_rot13(text: str) -> str | None:
    """Attempt ROT13 decode.

    Only applied to strings that look like they might be encoded,
    not to plain English text or strings with un-rotated special chars.
    """
    if len(text) < 4:
        return None
    # Skip if it looks like normal English (has spaces and many lowercase letters)
    if " " in text and sum(1 for c in text if c.islower()) / len(text) > 0.3:
        return None
    # Skip if contains special chars that ROT13 wouldn't transform
    if any(c in text for c in "{}[]()<>@#$%^&*!?|=+~`"):
        return None
    try:
        import codecs
        decoded = codecs.decode(text, "rot_13")
        printable = sum(1 for c in decoded if c.isprintable() or c.isspace())
        if len(decoded) > 0 and printable / len(decoded) > 0.8:
            if decoded != text:
                return decoded
    except Exception:
        pass
    return None


def _try_html_entities(text: str) -> str | None:
    """Attempt to decode HTML entities."""
    import html
    try:
        if "&" not in text or ";" not in text:
            return None
        decoded = html.unescape(text)
        if decoded != text and len(decoded) > 0:
            return decoded
    except Exception:
        pass
    return None


def _try_gzip(data: bytes) -> bytes | None:
    """Attempt to decompress gzip data."""
    try:
        import gzip
        decompressed = gzip.decompress(data)
        return decompressed
    except Exception:
        pass
    return None


def _try_zlib(data: bytes) -> bytes | None:
    """Attempt to decompress zlib data."""
    try:
        return zlib.decompress(data)
    except Exception:
        pass
    return None


def recursive_decode(data: str, max_depth: int = 3) -> list[dict[str, Any]]:
    """Recursively attempt to decode encoded data.

    Supports Base64, Base32, hex, URL encoding, HTML entities, and ROT13.

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

        # Try HTML entities
        if decoded is None:
            candidate = _try_html_entities(current)
            if candidate:
                decoded = candidate
                method = "HTML Entities"

        # Try Base64
        if decoded is None:
            b64_pattern = re.compile(r"^[A-Za-z0-9+/=]+$")
            if b64_pattern.match(current) and len(current) >= 4:
                try:
                    padding = 4 - len(current) % 4
                    if padding != 4:
                        candidate = current + "=" * padding
                    else:
                        candidate = current
                    result = base64.b64decode(candidate, validate=True)
                    if all(b < 127 or b in (9, 10, 13) for b in result):
                        text = result.decode("utf-8", errors="replace")
                        if text != current and len(text) > 0:
                            decoded = text
                            method = "Base64"
                except Exception:
                    pass

        # Try Base32
        if decoded is None:
            candidate = _try_base32(current)
            if candidate:
                decoded = candidate
                method = "Base32"

        # Try hex
        if decoded is None:
            hex_pattern = re.compile(r"^[0-9a-fA-F]+$")
            if hex_pattern.match(current) and len(current) % 2 == 0 and len(current) >= 4:
                try:
                    result = bytes.fromhex(current)
                    if all(b < 127 or b in (9, 10, 13) for b in result):
                        text = result.decode("utf-8", errors="replace")
                        if text != current and len(text) > 0:
                            decoded = text
                            method = "Hex"
                except Exception:
                    pass

        # Try ROT13
        if decoded is None:
            candidate = _try_rot13(current)
            if candidate:
                decoded = candidate
                method = "ROT13"

        if decoded is None or decoded in seen:
            break

        seen.add(decoded)
        steps.append({"method": method, "result": decoded})
        current = decoded

    return steps


def decompress_payload(data: bytes) -> tuple[bytes | None, str]:
    """Attempt to decompress gzip or zlib data.

    Args:
        data: Raw bytes.

    Returns:
        Tuple of (decompressed_bytes_or_None, method_name).
    """
    if not data or len(data) < 10:
        return None, ""

    # Try gzip first (magic: 0x1f 0x8b)
    if data[:2] == b"\x1f\x8b":
        result = _try_gzip(data)
        if result:
            return result, "gzip"

    # Try zlib (check for zlib header patterns)
    if data[:1] in (b"\x78", b"\x08", b"\x18", b"\x28", b"\x38", b"\x48", b"\x58", b"\x68"):
        result = _try_zlib(data)
        if result:
            return result, "zlib"

    return None, ""


def safe_filename(value: str) -> str:
    """Create a safe filename from a string."""
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", value)[:64]


def html_escape(value: str) -> str:
    """Safely escape a string for insertion into HTML."""
    return html.escape(str(value), quote=True)
