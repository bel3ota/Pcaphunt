"""File signature detector for PcapHunt."""

from typing import Any

from pcaphunt.detectors.base import BaseDetector


class FileDetector(BaseDetector):
    """Detect embedded file signatures/magic bytes."""

    SIGNATURES: list[dict[str, Any]] = [
        {"type": "PNG", "magic": b"\x89PNG\r\n\x1a\n", "ext": ".png"},
        {"type": "JPEG", "magic": b"\xff\xd8\xff", "ext": ".jpg"},
        {"type": "GIF", "magic": b"GIF87a", "ext": ".gif"},
        {"type": "GIF", "magic": b"GIF89a", "ext": ".gif"},
        {"type": "PDF", "magic": b"%PDF-", "ext": ".pdf"},
        {"type": "ZIP", "magic": b"PK\x03\x04", "ext": ".zip"},
        {"type": "GZIP", "magic": b"\x1f\x8b\x08", "ext": ".gz"},
        {"type": "ELF", "magic": b"\x7fELF", "ext": ""},
        {"type": "RAR", "magic": b"Rar!\x1a\x07\x01\x00", "ext": ".rar"},
        {"type": "RAR", "magic": b"Rar!\x1a\x07\x00", "ext": ".rar"},
        {"type": "7z", "magic": b"7z\xbc\xaf\x27\x1c", "ext": ".7z"},
        {"type": "BMP", "magic": b"BM", "ext": ".bmp"},
        {"type": "TIFF", "magic": b"II*\x00", "ext": ".tiff"},
        {"type": "TIFF", "magic": b"MM\x00*", "ext": ".tiff"},
        {"type": "TAR", "magic": b"ustar\x00", "ext": ".tar"},
        {"type": "TAR", "magic": b"ustar  ", "ext": ".tar"},
        {"type": "MP3", "magic": b"ID3", "ext": ".mp3"},
        {"type": "WAV", "magic": b"RIFF", "ext": ".wav", "offset": 8, "check": b"WAVE"},
    ]

    @property
    def name(self) -> str:
        return "files"

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect file signatures in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data:
            return results

        seen_offsets: set[int] = set()

        for sig in self.SIGNATURES:
            magic = sig["magic"]
            offset = 0
            if "offset" in sig:
                offset = sig["offset"]

            start = 0
            while True:
                idx = data.find(magic, start)
                if idx == -1:
                    break

                # Check additional bytes if specified
                if "check" in sig:
                    check_offset = idx + offset
                    check_data = sig["check"]
                    end = check_offset + len(check_data)
                    if end > len(data) or data[check_offset:end] != check_data:
                        start = idx + 1
                        continue

                # Avoid duplicates at same offset
                if idx in seen_offsets:
                    start = idx + 1
                    continue
                seen_offsets.add(idx)

                # Try to extract data from this offset to end or reasonable limit
                # For some file types we can estimate minimum size
                extracted = data[idx:]
                min_size = sig.get("min_size", 32)
                has_enough_data = len(extracted) >= min_size

                notes = f"File type: {sig['type']}"
                if not has_enough_data:
                    notes += " (incomplete data)"

                results.append(
                    self.create_finding(
                        context,
                        original=f"Magic bytes for {sig['type']}",
                        decoded=f"Signature detected at offset {idx}",
                        offset=idx,
                        confidence=0.99 if has_enough_data else 0.85,
                        file_type=sig["type"],
                        notes=notes,
                    )
                )

                start = idx + 1

        return results
