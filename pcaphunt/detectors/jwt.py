"""JWT detector for PcapHunt."""

import base64
import json
import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class JWTDetector(BaseDetector):
    """Detect JSON Web Tokens in packet data."""

    JWT_RE = re.compile(
        rb"[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
    )

    @property
    def name(self) -> str:
        return "jwt"

    def _pad_b64(self, s: str) -> str:
        """Add padding to Base64 string.

        Args:
            s: Base64 string.

        Returns:
            Padded string.
        """
        padding = 4 - len(s) % 4
        if padding != 4:
            return s + "=" * padding
        return s

    def _try_decode_part(self, part: str) -> str:
        """Try to decode a JWT part.

        Args:
            part: Base64-encoded part.

        Returns:
            Decoded string or empty.
        """
        try:
            padded = self._pad_b64(part)
            decoded = base64.b64decode(padded, validate=True)
            return decoded.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def _is_valid_jwt(self, token: str) -> bool:
        """Validate JWT structure and decode header/payload.

        Args:
            token: JWT string.

        Returns:
            True if valid JWT.
        """
        parts = token.split(".")
        if len(parts) != 3:
            return False

        header = self._try_decode_part(parts[0])
        payload = self._try_decode_part(parts[1])

        if not header or not payload:
            return False

        # Check if header is valid JSON
        try:
            header_json = json.loads(header)
            if not isinstance(header_json, dict):
                return False
            # Header should have typical JWT fields
            if "typ" not in header_json and "alg" not in header_json:
                return False
        except Exception:
            return False

        try:
            payload_json = json.loads(payload)
            if not isinstance(payload_json, dict):
                return False
        except Exception:
            return False

        return True

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect JWT strings in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data:
            return results

        seen: set[str] = set()

        for match in self.JWT_RE.finditer(data):
            raw = match.group()
            offset = match.start()
            token = raw.decode("ascii", errors="ignore")

            if token in seen:
                continue

            if not self._is_valid_jwt(token):
                continue

            seen.add(token)

            parts = token.split(".")
            header = self._try_decode_part(parts[0])
            payload = self._try_decode_part(parts[1])

            try:
                header_pretty = json.dumps(json.loads(header), indent=2)
            except Exception:
                header_pretty = header

            try:
                payload_pretty = json.dumps(json.loads(payload), indent=2)
            except Exception:
                payload_pretty = payload

            decoded = f"Header:\n{header_pretty}\n\nPayload:\n{payload_pretty}"

            results.append(
                self.create_finding(
                    context,
                    original=token,
                    decoded=decoded,
                    offset=offset,
                    confidence=0.98,
                )
            )

        return results
