"""Tests for PcapHunt file extraction and hashing subsystem."""

from __future__ import annotations

import hashlib

import pytest

from pcaphunt.extraction import (
    MAGIC_SIGNATURES,
    _compute_hashes_stream,
    _extract_file_bounds,
    _guess_filename,
    _max_extract_size,
    _sanitize_filename,
    detect_file_type,
    extract_files_from_payload,
    extract_http_files,
    reset_artifact_counter,
)
from pcaphunt.models import FileArtifact


class TestMagicDetection:
    def test_detect_png(self):
        data = b"\x89PNG\r\n\x1a\n" + b"fake_png_data"
        result = detect_file_type(data)
        assert result is not None
        assert result[0] == "PNG"

    def test_detect_jpeg(self):
        data = b"\xff\xd8\xff" + b"fake_jpeg"
        result = detect_file_type(data)
        assert result is not None
        assert result[0] == "JPEG"

    def test_detect_pdf(self):
        data = b"%PDF-1.4" + b"fake_pdf"
        result = detect_file_type(data)
        assert result is not None
        assert result[0] == "PDF"

    def test_detect_elf(self):
        data = b"\x7fELF" + b"fake_elf"
        result = detect_file_type(data)
        assert result is not None
        assert result[0] == "ELF"

    def test_detect_pe(self):
        data = b"MZ" + b"fake_pe"
        result = detect_file_type(data)
        assert result is not None
        assert result[0] == "PE"

    def test_detect_zip(self):
        data = b"PK\x03\x04" + b"fake_zip"
        result = detect_file_type(data)
        assert result is not None
        assert result[0] == "ZIP"

    def test_detect_none(self):
        data = b"random data that is not a file"
        result = detect_file_type(data)
        assert result is None

    def test_detect_empty(self):
        assert detect_file_type(b"") is None


class TestSanitizeFilename:
    def test_basic(self):
        assert _sanitize_filename("test.png") == "test.png"

    def test_path_traversal(self):
        # Path traversal is prevented by Path(name).name which strips all path components
        assert _sanitize_filename("../../etc/passwd") == "passwd"

    def test_special_chars(self):
        assert _sanitize_filename("test<file>.png") == "test_file_.png"

    def test_leading_dots(self):
        assert _sanitize_filename("..hidden") == "hidden"

    def test_empty(self):
        assert _sanitize_filename("") == "unnamed"

    def test_max_length(self):
        long_name = "a" * 200
        assert len(_sanitize_filename(long_name)) <= 128


class TestHashing:
    def test_known_data(self):
        data = b"hello world"
        md5, sha1, sha256 = _compute_hashes_stream(data)
        assert md5 == hashlib.md5(data, usedforsecurity=False).hexdigest()
        assert sha1 == hashlib.sha1(data, usedforsecurity=False).hexdigest()
        assert sha256 == hashlib.sha256(data).hexdigest()

    def test_empty_data(self):
        md5, sha1, sha256 = _compute_hashes_stream(b"")
        assert md5 == hashlib.md5(b"", usedforsecurity=False).hexdigest()


class TestExtractFileBounds:
    def test_png_with_iend(self):
        payload = b"\x89PNG\r\n\x1a\n" + b"data" + b"IEND\xaeB`\x82" + b"trailing"
        data, complete, reason = _extract_file_bounds(payload, 0, "PNG", {}, "")
        assert complete is True
        assert b"IEND" in data

    def test_jpeg_with_eoi(self):
        payload = b"\xff\xd8\xff" + b"data" + b"\xff\xd9" + b"trailing"
        data, complete, reason = _extract_file_bounds(payload, 0, "JPEG", {}, "")
        assert complete is True

    def test_pdf_with_eof(self):
        payload = b"%PDF" + b"data" + b"%%EOF" + b"trailing"
        data, complete, reason = _extract_file_bounds(payload, 0, "PDF", {}, "")
        assert complete is True

    def test_generic_truncated(self):
        payload = b"\x7fELF" + b"data"
        data, complete, reason = _extract_file_bounds(payload, 0, "ELF", {}, "")
        # ELF has no simple end marker, so it uses heuristic
        assert len(data) > 0


class TestMaxExtractSize:
    def test_known_types(self):
        assert _max_extract_size("PNG") > 0
        assert _max_extract_size("JPEG") > 0
        assert _max_extract_size("PDF") > 0

    def test_unknown_type(self):
        assert _max_extract_size("UNKNOWN") == 20 * 1024 * 1024


class TestGuessFilename:
    def test_http_content_disposition(self):
        ctx = {"metadata": {"headers": b"Content-Disposition: attachment; filename=secret.pdf\r\n"}}
        name = _guess_filename(ctx, "PDF", "HTTP")
        assert name == "secret.pdf"

    def test_http_path(self):
        ctx = {"metadata": {"path": "/files/document.pdf"}}
        name = _guess_filename(ctx, "PDF", "HTTP")
        assert name == "document.pdf"

    def test_no_hint(self):
        ctx = {}
        assert _guess_filename(ctx, "PNG", "TCP") is None


class TestExtractFilesFromPayload:
    def test_extract_png(self):
        reset_artifact_counter()
        payload = b"\x89PNG\r\n\x1a\n" + b"fake" + b"IEND\xaeB`\x82"
        ctx = {
            "source": "10.0.0.1:12345",
            "destination": "10.0.0.2:80",
            "protocol": "TCP",
            "packet_numbers": [1],
            "first_seen_packet": 1,
        }
        arts = extract_files_from_payload(payload, ctx)
        assert len(arts) >= 1
        art = arts[0]
        assert art.file_type == "image/png"
        assert art.source_ip == "10.0.0.1"
        assert art.destination_ip == "10.0.0.2"
        assert art.md5 != ""
        assert art.sha256 != ""

    def test_extract_jpeg(self):
        reset_artifact_counter()
        # Minimal valid JPEG structure: SOI + APP0 marker + JFIF + EOI
        payload = (
            b"\xff\xd8\xff"  # SOI
            b"\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # APP0
            b"\xff\xd9"  # EOI
        )
        ctx = {
            "source": "10.0.0.1:12345",
            "destination": "10.0.0.2:80",
            "protocol": "TCP",
            "packet_numbers": [1],
            "first_seen_packet": 1,
        }
        arts = extract_files_from_payload(payload, ctx)
        assert len(arts) >= 1
        art = arts[0]
        assert art.file_type == "image/jpeg"
        assert art.complete is True
        # Critical: raw bytes must be stored so the file can be written
        assert "_raw_bytes" in art.metadata
        raw = bytes.fromhex(art.metadata["_raw_bytes"])
        assert raw.startswith(b"\xff\xd8\xff")
        assert raw.endswith(b"\xff\xd9")

    def test_no_magic(self):
        reset_artifact_counter()
        payload = b"this is just plain text with no file magic"
        ctx = {"source": "", "destination": "", "protocol": "TCP"}
        arts = extract_files_from_payload(payload, ctx)
        assert len(arts) == 0


class TestExtractHttpFiles:
    def test_http_response_with_png(self):
        reset_artifact_counter()
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: image/png\r\n"
            b"Content-Length: 12\r\n"
            b"\r\n"
            b"\x89PNG\r\n\x1a\nfake"
        )
        ctx = {
            "source": "10.0.0.2:80",
            "destination": "10.0.0.1:12345",
            "protocol": "HTTP",
            "packet_numbers": [1],
            "first_seen_packet": 1,
        }
        results = extract_http_files(payload, ctx)
        assert len(results) >= 1
        data, art = results[0]
        assert art.file_type == "image/png"
        assert len(data) > 0
