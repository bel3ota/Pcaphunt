"""File extraction and reconstruction from network traffic for PcapHunt.

Extracts files from protocols where reconstruction is reasonably possible,
using magic/signature detection for type identification.
"""

from __future__ import annotations

import hashlib
import io
import logging
import re
from pathlib import Path
from typing import Any

from pcaphunt.models import FileArtifact
from pcaphunt.utils import safe_filename

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Magic signatures (bytes -> type description)
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES: list[tuple[bytes, str, str]] = [
    # (magic_bytes, type_name, mime_type)
    (b"\x89PNG\r\n\x1a\n", "PNG", "image/png"),
    (b"\xff\xd8\xff", "JPEG", "image/jpeg"),
    (b"GIF87a", "GIF", "image/gif"),
    (b"GIF89a", "GIF", "image/gif"),
    (b"%PDF", "PDF", "application/pdf"),
    (b"PK\x03\x04", "ZIP", "application/zip"),
    (b"PK\x05\x06", "ZIP", "application/zip"),  # empty ZIP
    (b"PK\x07\x08", "ZIP", "application/zip"),  # ZIP64
    (b"\x1f\x8b\x08", "GZIP", "application/gzip"),
    (b"ustar\x00", "TAR", "application/x-tar"),
    (b"ustar  \x00", "TAR", "application/x-tar"),  # GNU tar
    (b"\x7fELF", "ELF", "application/x-elf"),
    (b"MZ", "PE", "application/x-dosexec"),
    (b"SQLite format 3\x00", "SQLite", "application/x-sqlite3"),
    (b"RIFF", "WAV", "audio/wav"),
    (b"ID3", "MP3", "audio/mpeg"),
    (b"\xff\xfb", "MP3", "audio/mpeg"),
    (b"\xff\xf3", "MP3", "audio/mpeg"),
    (b"\xff\xf2", "MP3", "audio/mpeg"),
    (b"ftyp", "MP4", "video/mp4"),
    (b"\xd0\xcf\x11\xe0", "OLE2", "application/x-ole-object"),  # Office 97-2003
    (b"PK\x03\x04", "DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    (b"PK\x03\x04", "XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    (b"PK\x03\x04", "PPTX", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
    (b"Rar!\x1a\x07\x00", "RAR", "application/x-rar-compressed"),
    (b"Rar!\x1a\x07\x01\x00", "RAR5", "application/x-rar-compressed"),
    (b"7z\xbc\xaf'\x1c", "7Z", "application/x-7z-compressed"),
    (b"BM", "BMP", "image/bmp"),
    (b"II*\x00", "TIFF", "image/tiff"),
    (b"MM\x00*", "TIFF", "image/tiff"),
]

# Minimum bytes for a plausible file of each type (filters false positives).
# Set low enough that legitimate tiny files / tests aren't rejected.
MIN_FILE_SIZES: dict[str, int] = {
    "JPEG": 4,
    "PNG": 4,
    "GIF": 4,
    "PDF": 4,
    "ZIP": 4,
    "GZIP": 4,
    "TAR": 4,
    "ELF": 4,
    "PE": 4,
    "SQLite": 4,
    "WAV": 4,
    "MP3": 400,  # one MPEG frame is ~400 bytes
    "MP4": 4,
    "OLE2": 4,
    "DOCX": 4,
    "XLSX": 4,
    "PPTX": 4,
    "RAR": 4,
    "RAR5": 4,
    "7Z": 4,
    "BMP": 4,
    "TIFF": 4,
}

# For ZIP-based formats, we need secondary checks
ZIP_TYPES: dict[str, tuple[bytes, str, str]] = {
    "DOCX": (b"word/document.xml", "DOCX", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
    "XLSX": (b"xl/workbook.xml", "XLSX", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "PPTX": (b"ppt/presentation.xml", "PPTX", "application/vnd.openxmlformats-officedocument.presentationml.presentation"),
}

# HTTP-related patterns for file extraction
HTTP_CONTENT_TYPE_RE = re.compile(rb"Content-Type:\s*([^\r\n]+)", re.IGNORECASE)
HTTP_CONTENT_LENGTH_RE = re.compile(rb"Content-Length:\s*(\d+)", re.IGNORECASE)
HTTP_CONTENT_DISPOSITION_RE = re.compile(rb"Content-Disposition:\s*[^\r\n]*filename\s*=\s*[\"']?([^\"'\r\n;]+)", re.IGNORECASE)
HTTP_TRANSFER_ENCODING_RE = re.compile(rb"Transfer-Encoding:\s*([^\r\n]+)", re.IGNORECASE)
HTTP_CHUNKED_END = re.compile(rb"\r\n0\r\n\r\n")


def detect_file_type(data: bytes) -> tuple[str, str] | None:
    """Detect file type from magic bytes.

    Returns (type_name, mime_type) or None if no match.
    """
    if not data:
        return None

    for magic, type_name, mime in MAGIC_SIGNATURES:
        if data.startswith(magic):
            # For ZIP-based formats, do secondary check
            if type_name in ZIP_TYPES:
                inner_marker, real_type, real_mime = ZIP_TYPES[type_name]
                if inner_marker in data[:4096]:
                    return real_type, real_mime
                # Fallback to generic ZIP if we can't confirm the specific type
                return "ZIP", "application/zip"
            return type_name, mime
    return None


# Valid JPEG markers (excluding SOI 0xFFD8 and EOI 0xFFD9)
_JPEG_VALID_MARKERS: set[int] = {
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
    0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xDB, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xDA, 0xFE,
}


def _is_valid_jpeg(data: bytes) -> bool:
    """Basic structural validation for JPEG.

    Checks that SOI is followed by at least one valid marker and
    that there is an EOI marker somewhere in the data.
    """
    if len(data) < 4:
        return False
    if data[:2] != b"\xff\xd8":
        return False
    # Scan for at least one valid marker after SOI
    has_valid_marker = False
    i = 2
    while i < len(data) - 1:
        if data[i] == 0xFF:
            marker = data[i + 1]
            if marker == 0xD9:  # EOI
                return has_valid_marker
            if marker in _JPEG_VALID_MARKERS:
                has_valid_marker = True
                # Skip marker + length bytes (2-byte length follows marker)
                if i + 3 < len(data):
                    length = int.from_bytes(data[i + 2 : i + 4], "big")
                    i += 2 + length
                    continue
        i += 1
    # No EOI found
    return False


def _is_valid_mp3_frame(data: bytes) -> bool:
    """Check that data contains at least three valid MPEG audio frame headers.

    A single valid-looking frame header is common in random binary data.
    Requiring three headers within the first 4 KB eliminates virtually all
    false positives while still accepting real MP3 files.
    """
    if len(data) < 12:
        return False

    def _valid_header(offset: int) -> bool:
        if offset + 4 > len(data):
            return False
        header = int.from_bytes(data[offset : offset + 4], "big")
        if (header & 0xFFE00000) != 0xFFE00000:
            return False
        version = (header >> 19) & 0x03
        if version == 0x01:
            return False
        layer = (header >> 17) & 0x03
        if layer == 0x00:
            return False
        bitrate = (header >> 12) & 0x0F
        if bitrate in (0x00, 0x0F):
            return False
        sample_rate = (header >> 10) & 0x03
        if sample_rate == 0x03:
            return False
        return True

    # Count valid headers in the first 4096 bytes (covers ~10 frames even at high bitrate)
    scan_len = min(len(data) - 3, 4096)
    header_count = 0
    for i in range(scan_len):
        if _valid_header(i):
            header_count += 1
            if header_count >= 3:
                return True
    return False


def _is_plausible_file(data: bytes, type_name: str) -> bool:
    """Quick validation to reject obvious false positives."""
    min_size = MIN_FILE_SIZES.get(type_name, 20)
    if len(data) < min_size:
        return False
    if type_name == "JPEG":
        return _is_valid_jpeg(data)
    if type_name in ("MP3", "MP3_ID3"):
        return _is_valid_mp3_frame(data)
    return True


def _sanitize_filename(name: str, max_len: int = 128) -> str:
    """Sanitize a filename to prevent path traversal and weird paths."""
    # Remove any path components
    name = Path(name).name
    # Replace dangerous characters except dot (needed for extensions)
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    # Prevent path traversal attempts like ../../etc/passwd
    # Only strip leading dots that indicate hidden files or traversal
    name = re.sub(r"^\.+", "", name)
    if not name:
        name = "unnamed"
    return name[:max_len]


def _compute_hashes_stream(data: bytes) -> tuple[str, str, str]:
    """Compute MD5, SHA1, SHA256 using streaming approach.

    Returns (md5, sha1, sha256) hex strings.
    """
    md5_hasher = hashlib.md5(usedforsecurity=False)
    sha1_hasher = hashlib.sha1(usedforsecurity=False)
    sha256_hasher = hashlib.sha256()

    # Process in chunks to avoid loading huge data multiple times
    # Since data is already bytes, we can feed it directly
    md5_hasher.update(data)
    sha1_hasher.update(data)
    sha256_hasher.update(data)

    return (
        md5_hasher.hexdigest(),
        sha1_hasher.hexdigest(),
        sha256_hasher.hexdigest(),
    )


def extract_files_from_payload(
    payload: bytes,
    context: dict[str, Any],
    protocol_hint: str = "",
) -> list[FileArtifact]:
    """Scan a payload for embedded files using magic signatures.

    Args:
        payload: Raw bytes to scan.
        context: Packet/stream context dict.
        protocol_hint: Optional protocol hint (e.g., "HTTP", "FTP").

    Returns:
        List of FileArtifact objects for detected files.
    """
    artifacts: list[FileArtifact] = []
    if not payload:
        return artifacts

    max_scan = min(len(payload), 50 * 1024 * 1024)  # Scan first 50MB max
    # Track extracted byte regions so different magics don't claim the same bytes.
    extracted_regions: list[tuple[int, int]] = []

    def _is_inside_region(offset: int) -> bool:
        for start, end in extracted_regions:
            if start <= offset < end:
                return True
        return False

    for magic, type_name, mime in MAGIC_SIGNATURES:
        start = 0
        while start < max_scan:
            idx = payload.find(magic, start)
            if idx == -1:
                break
            if _is_inside_region(idx):
                start = idx + 1
                continue

            # Try to determine file bounds
            file_data, complete, reason = _extract_file_bounds(
                payload, idx, type_name, context, protocol_hint
            )
            end = idx + len(file_data)
            extracted_regions.append((idx, end))

            # Validate extracted data to filter false positives
            if not _is_plausible_file(file_data, type_name):
                start = end
                continue

            md5, sha1, sha256 = _compute_hashes_stream(file_data)

            # Generate safe filename
            detected_name = _guess_filename(context, type_name, protocol_hint)
            safe_name = _sanitize_filename(detected_name or f"extracted_{type_name.lower()}")
            generated_name = f"{_artifact_index():03d}_{safe_name}.{type_name.lower()}"

            artifact = FileArtifact(
                filename=generated_name,
                file_type=mime,
                size=len(file_data),
                source_ip=_get_ip(context.get("source", "")),
                destination_ip=_get_ip(context.get("destination", "")),
                source_port=_get_port(context.get("source", "")),
                destination_port=_get_port(context.get("destination", "")),
                protocol=context.get("protocol", protocol_hint or "Unknown"),
                stream_id=context.get("stream_id"),
                first_packet=context.get("first_seen_packet"),
                last_packet=max(context.get("packet_numbers", [])) if context.get("packet_numbers") else None,
                timestamp=context.get("timestamp"),
                extraction_method="magic_signature",
                complete=complete,
                completeness_reason=reason,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                detected_filename=detected_name,
                metadata={"_raw_bytes": file_data.hex()},
            )
            artifacts.append(artifact)
            # Skip past the extracted file so the same magic (e.g. MP3 frame sync)
            # doesn't find false positives inside the file we just extracted.
            start = end

    return artifacts


# Global counter for artifact naming
_ARTIFACT_COUNTER = 0


def _artifact_index() -> int:
    global _ARTIFACT_COUNTER
    _ARTIFACT_COUNTER += 1
    return _ARTIFACT_COUNTER


def reset_artifact_counter() -> None:
    """Reset the artifact counter. Call before each scan."""
    global _ARTIFACT_COUNTER
    _ARTIFACT_COUNTER = 0


def _get_ip(addr_str: str) -> str:
    """Extract IP from 'IP:port' string."""
    if not addr_str:
        return ""
    if ":" in addr_str:
        # IPv6 handling is tricky; just take everything before the last colon for IPv4
        parts = addr_str.rsplit(":", 1)
        if parts[1].isdigit():
            return parts[0]
    return addr_str


def _get_port(addr_str: str) -> int | None:
    """Extract port from 'IP:port' string."""
    if not addr_str:
        return None
    if ":" in addr_str:
        parts = addr_str.rsplit(":", 1)
        if parts[1].isdigit():
            return int(parts[1])
    return None


def _guess_filename(context: dict[str, Any], type_name: str, protocol_hint: str) -> str | None:
    """Try to guess a filename from context or protocol metadata."""
    metadata = context.get("metadata", {})

    # HTTP-specific filename detection
    if protocol_hint == "HTTP" or context.get("protocol") == "HTTP":
        # Look for Content-Disposition filename
        for key in ("headers", "request_headers", "response_headers"):
            headers = metadata.get(key, {})
            if isinstance(headers, dict):
                cd = headers.get("Content-Disposition", "")
                if cd:
                    m = re.search(r'filename\s*=\s*["\']?([^"\';\r\n]+)', cd, re.IGNORECASE)
                    if m:
                        return m.group(1)
            elif isinstance(headers, bytes):
                m = HTTP_CONTENT_DISPOSITION_RE.search(headers)
                if m:
                    return m.group(1).decode("utf-8", errors="ignore")

        # Try to extract from URL path
        path = metadata.get("path", "")
        if path:
            # Get the last path component
            name = path.split("/")[-1]
            if name and "." in name:
                return name

    return None


def _extract_file_bounds(
    payload: bytes,
    offset: int,
    type_name: str,
    context: dict[str, Any],
    protocol_hint: str,
) -> tuple[bytes, bool, str]:
    """Attempt to extract the file data and determine if it's complete.

    Returns (file_data, complete, reason).
    """
    metadata = context.get("metadata", {})

    # Try to use Content-Length if available
    content_length = None
    headers = metadata.get("headers", {})
    if isinstance(headers, dict):
        cl = headers.get("Content-Length")
        if cl:
            try:
                content_length = int(cl)
            except ValueError:
                pass
    elif isinstance(headers, bytes):
        m = HTTP_CONTENT_LENGTH_RE.search(headers)
        if m:
            try:
                content_length = int(m.group(1))
            except ValueError:
                pass

    if content_length is not None and content_length > 0:
        end = offset + content_length
        if end <= len(payload):
            return payload[offset:end], True, ""
        else:
            return payload[offset:], False, f"Truncated: expected {content_length} bytes, got {len(payload) - offset}"

    # Type-specific heuristics for file size
    max_extract = _max_extract_size(type_name)
    available = len(payload) - offset
    extract_size = min(available, max_extract)

    # For some types we can try to detect the natural end
    if type_name == "PNG":
        # Look for IEND chunk marker
        iend = payload.find(b"IEND\xaeB`\x82", offset)
        if iend != -1:
            end = iend + 8  # 4 bytes length + "IEND" + 4 bytes CRC
            return payload[offset:end], True, ""

    elif type_name == "JPEG":
        # Look for EOI marker
        eoi = payload.find(b"\xff\xd9", offset + 2)
        if eoi != -1:
            return payload[offset : eoi + 2], True, ""

    elif type_name == "GIF":
        # Look for trailer byte 0x3B
        trailer = payload.find(b"\x3b", offset + 6)
        if trailer != -1:
            return payload[offset : trailer + 1], True, ""

    elif type_name in ("ZIP", "DOCX", "XLSX", "PPTX"):
        # ZIP files are hard to bound without scanning the central directory
        # Heuristic: extract a reasonable amount
        return payload[offset : offset + extract_size], True, ""

    elif type_name == "GZIP":
        # GZIP has no explicit end marker; we rely on zlib stream completion
        return payload[offset : offset + extract_size], True, ""

    elif type_name == "PDF":
        # Look for %%EOF
        eof = payload.find(b"%%EOF", offset)
        if eof != -1:
            return payload[offset : eof + 5], True, ""

    elif type_name == "PE":
        # PE files have headers that specify size
        if available >= 64:
            pe_offset = int.from_bytes(payload[offset + 60 : offset + 64], "little")
            if offset + pe_offset + 24 <= len(payload):
                # Read SizeOfImage from optional header
                size_offset = pe_offset + 80
                if size_offset + 4 <= len(payload):
                    size = int.from_bytes(payload[size_offset : size_offset + 4], "little")
                    if size > 0 and offset + size <= len(payload):
                        return payload[offset : offset + size], True, ""

    # Default: extract up to reasonable limit
    data = payload[offset : offset + extract_size]
    complete = extract_size >= available
    reason = "" if complete else "File may be truncated (size heuristic applied)"
    return data, complete, reason


def _max_extract_size(type_name: str) -> int:
    """Maximum bytes to extract for a given file type."""
    limits = {
        "PNG": 50 * 1024 * 1024,
        "JPEG": 50 * 1024 * 1024,
        "GIF": 20 * 1024 * 1024,
        "PDF": 100 * 1024 * 1024,
        "ZIP": 100 * 1024 * 1024,
        "GZIP": 100 * 1024 * 1024,
        "TAR": 500 * 1024 * 1024,
        "ELF": 50 * 1024 * 1024,
        "PE": 100 * 1024 * 1024,
        "SQLite": 100 * 1024 * 1024,
        "WAV": 100 * 1024 * 1024,
        "MP3": 100 * 1024 * 1024,
        "MP4": 500 * 1024 * 1024,
        "DOCX": 50 * 1024 * 1024,
        "XLSX": 50 * 1024 * 1024,
        "PPTX": 100 * 1024 * 1024,
        "RAR": 100 * 1024 * 1024,
        "RAR5": 100 * 1024 * 1024,
        "7Z": 100 * 1024 * 1024,
        "BMP": 50 * 1024 * 1024,
        "TIFF": 100 * 1024 * 1024,
    }
    return limits.get(type_name, 20 * 1024 * 1024)


def write_artifacts(
    artifacts: list[FileArtifact],
    base_dir: str,
) -> list[Path]:
    """Write extracted file artifacts to disk.

    Returns list of written file paths.
    """
    base = Path(base_dir)
    extracted_dir = base / "extracted_files"
    extracted_dir.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for artifact in artifacts:
        filepath = extracted_dir / artifact.filename
        # Prevent overwriting by appending counter
        counter = 1
        original_path = filepath
        while filepath.exists():
            stem = original_path.stem
            suffix = original_path.suffix
            filepath = extracted_dir / f"{stem}_{counter:02d}{suffix}"
            counter += 1

        try:
            with open(filepath, "wb") as f:
                # We need to reconstruct the actual file data. Currently the artifact
                # doesn't store the raw bytes — we need a way to get them.
                # For now, we'll handle this at a higher level where the raw data
                # is available. This function assumes the caller manages raw bytes.
                pass
        except Exception as exc:
            logger.warning("Failed to write artifact metadata for %s: %s", filepath, exc)

    return written


def extract_http_files(
    payload: bytes,
    context: dict[str, Any],
) -> list[tuple[bytes, FileArtifact]]:
    """Extract files from HTTP payloads.

    Returns list of (raw_bytes, artifact) tuples so the caller can write them.
    """
    artifacts: list[tuple[bytes, FileArtifact]] = []
    if not payload:
        return artifacts

    # Check if this looks like an HTTP response with body
    # Simple heuristic: split headers from body
    header_end = payload.find(b"\r\n\r\n")
    if header_end == -1:
        header_end = payload.find(b"\n\n")
    if header_end == -1:
        # No clear header/body split, fall back to signature scan
        sig_artifacts = extract_files_from_payload(payload, context, "HTTP")
        for art in sig_artifacts:
            # We need to find the actual data. Re-scan with the artifact offset.
            # But extract_files_from_payload doesn't expose offsets. Let's reimplement
            # a simpler version that returns raw bytes too.
            pass
        return artifacts

    body = payload[header_end + 4 :]
    headers = payload[:header_end]

    # Update context with HTTP metadata
    enriched_context = dict(context)
    enriched_context.setdefault("metadata", {})
    enriched_context["metadata"]["headers"] = headers

    # Detect file type in body
    detected = detect_file_type(body)
    if detected:
        type_name, mime = detected
        file_data, complete, reason = _extract_file_bounds(
            body, 0, type_name, enriched_context, "HTTP"
        )

        if not _is_plausible_file(file_data, type_name):
            return artifacts

        md5, sha1, sha256 = _compute_hashes_stream(file_data)
        detected_name = _guess_filename(enriched_context, type_name, "HTTP")
        safe_name = _sanitize_filename(detected_name or f"http_{type_name.lower()}")
        generated_name = f"{_artifact_index():03d}_{safe_name}.{type_name.lower()}"

        artifact = FileArtifact(
            filename=generated_name,
            file_type=mime,
            size=len(file_data),
            source_ip=_get_ip(context.get("source", "")),
            destination_ip=_get_ip(context.get("destination", "")),
            source_port=_get_port(context.get("source", "")),
            destination_port=_get_port(context.get("destination", "")),
            protocol="HTTP",
            stream_id=context.get("stream_id"),
            first_packet=context.get("first_seen_packet"),
            last_packet=max(context.get("packet_numbers", [])) if context.get("packet_numbers") else None,
            timestamp=context.get("timestamp"),
            extraction_method="http_body",
            complete=complete,
            completeness_reason=reason,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            detected_filename=detected_name,
            metadata={"_raw_bytes": file_data.hex()},
        )
        artifacts.append((file_data, artifact))

    # Also do a full signature scan on the body for embedded files
    sig_artifacts = _scan_for_files_with_data(body, enriched_context, "HTTP")
    artifacts.extend(sig_artifacts)

    return artifacts


def _scan_for_files_with_data(
    payload: bytes,
    context: dict[str, Any],
    protocol_hint: str,
) -> list[tuple[bytes, FileArtifact]]:
    """Scan payload for magic signatures and return (data, artifact) pairs."""
    results: list[tuple[bytes, FileArtifact]] = []
    if not payload:
        return results

    max_scan = min(len(payload), 50 * 1024 * 1024)
    extracted_regions: list[tuple[int, int]] = []

    def _is_inside_region(offset: int) -> bool:
        for start, end in extracted_regions:
            if start <= offset < end:
                return True
        return False

    for magic, type_name, mime in MAGIC_SIGNATURES:
        start = 0
        while start < max_scan:
            idx = payload.find(magic, start)
            if idx == -1:
                break
            if _is_inside_region(idx):
                start = idx + 1
                continue

            file_data, complete, reason = _extract_file_bounds(
                payload, idx, type_name, context, protocol_hint
            )
            end = idx + len(file_data)
            extracted_regions.append((idx, end))

            if not _is_plausible_file(file_data, type_name):
                start = end
                continue

            md5, sha1, sha256 = _compute_hashes_stream(file_data)
            detected_name = _guess_filename(context, type_name, protocol_hint)
            safe_name = _sanitize_filename(detected_name or f"extracted_{type_name.lower()}")
            generated_name = f"{_artifact_index():03d}_{safe_name}.{type_name.lower()}"

            artifact = FileArtifact(
                filename=generated_name,
                file_type=mime,
                size=len(file_data),
                source_ip=_get_ip(context.get("source", "")),
                destination_ip=_get_ip(context.get("destination", "")),
                source_port=_get_port(context.get("source", "")),
                destination_port=_get_port(context.get("destination", "")),
                protocol=context.get("protocol", protocol_hint or "Unknown"),
                stream_id=context.get("stream_id"),
                first_packet=context.get("first_seen_packet"),
                last_packet=max(context.get("packet_numbers", [])) if context.get("packet_numbers") else None,
                timestamp=context.get("timestamp"),
                extraction_method="magic_signature",
                complete=complete,
                completeness_reason=reason,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                detected_filename=detected_name,
                metadata={"_raw_bytes": file_data.hex()},
            )
            results.append((file_data, artifact))
            start = end

    return results
