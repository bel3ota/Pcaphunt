"""Credentials detector for PcapHunt."""

import re
from typing import Any

from pcaphunt.detectors.base import BaseDetector


class CredentialsDetector(BaseDetector):
    """Detect credential patterns in packet data."""

    PATTERNS = [
        (r"(?i)(username|user|login)\s*[:=]\s*([^\s&;]{3,50})", "username", "medium"),
        (r"(?i)(password|pass|passwd)\s*[:=]\s*([^\s&;]{3,50})", "password", "high"),
        (r"(?i)(token|api_key|apikey|secret)\s*[:=]\s*([^\s&;]{8,100})", "token", "high"),
        (r"(?i)(authorization|bearer)\s+([A-Za-z0-9_\-\.]{8,200})", "auth", "high"),
        (r"(?i)(cookie|session)\s*[:=]\s*([^\s&;]{8,200})", "session", "medium"),
    ]

    SENSITIVE_KEYS = [
        "password", "passwd", "pass", "secret", "token",
        "api_key", "apikey", "private_key", "client_secret",
    ]

    @property
    def name(self) -> str:
        return "credentials"

    def detect(self, data: bytes, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect credential patterns in data.

        Args:
            data: Byte string to analyze.
            context: Metadata context.

        Returns:
            List of finding dictionaries.
        """
        results: list[dict[str, Any]] = []
        if not data:
            return results

        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return results

        seen: set[str] = set()

        for pattern, cred_type, severity in self.PATTERNS:
            for match in re.finditer(pattern, text):
                key = match.group(1)
                value = match.group(2)
                offset = match.start()

                if value.lower() in ("true", "false", "null", "none", "undefined", ""):
                    continue
                if len(value) < 3:
                    continue

                fingerprint = f"{cred_type}:{value}"
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)

                results.append(
                    self.create_finding(
                        context,
                        original=f"{key}={value}",
                        decoded=f"{key}={value}",
                        offset=offset,
                        confidence=0.85,
                        severity=severity,
                        notes=f"Type: {cred_type}",
                    )
                )

        # JSON-formatted credentials
        json_pattern = re.compile(
            r'"(password|passwd|pass|token|api_key|apikey|secret)"\s*:\s*"([^"]{3,100})"',
            re.IGNORECASE,
        )
        for match in json_pattern.finditer(text):
            key = match.group(1)
            value = match.group(2)
            offset = match.start()

            if value.lower() in ("true", "false", "null", "none", "", "string"):
                continue

            fingerprint = f"json:{key}:{value}"
            if fingerprint in seen:
                continue
            seen.add(fingerprint)

            severity = "high" if key.lower() in ("password", "passwd", "pass", "secret") else "medium"

            results.append(
                self.create_finding(
                    context,
                    original=f'{key}: "{value}"',
                    decoded=f'{key}: "{value}"',
                    offset=offset,
                    confidence=0.88,
                    severity=severity,
                    notes="Type: json_credential",
                )
            )

        return results
