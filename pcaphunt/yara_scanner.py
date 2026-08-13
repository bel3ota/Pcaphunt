"""Optional YARA integration for PcapHunt.

Scans extracted files and payloads against YARA rules.
YARA is an optional dependency — PcapHunt works without it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from pcaphunt.models import YaraMatch

logger = logging.getLogger(__name__)

# Lazy import flag
_yara_available: bool | None = None


def _yara_installed() -> bool:
    """Check if YARA Python bindings are installed."""
    global _yara_available
    if _yara_available is not None:
        return _yara_available
    try:
        import yara  # noqa: F401
        _yara_available = True
        return True
    except ImportError:
        _yara_available = False
        return False


def scan_data(
    data: bytes,
    rules_path: str,
) -> list[YaraMatch]:
    """Scan byte data against YARA rules.

    Args:
        data: Raw bytes to scan.
        rules_path: Path to YARA rule file or directory.

    Returns:
        List of YaraMatch objects. Empty if YARA not installed.
    """
    if not _yara_installed():
        logger.debug("YARA not installed, skipping scan")
        return []

    if not data:
        return []

    try:
        import yara
    except ImportError:
        return []

    rules = _load_yara_rules(rules_path)
    if rules is None:
        return []

    matches: list[YaraMatch] = []
    try:
        yara_matches = rules.match(data=data)
        for ym in yara_matches:
            strings_data: list[dict[str, Any]] = []
            if ym.strings:
                for s in ym.strings:
                    # YARA 4.x vs 3.x compatibility
                    try:
                        identifier = s.identifier if hasattr(s, "identifier") else s[1]
                        instances = s.instances if hasattr(s, "instances") else s[2]
                        for inst in instances:
                            offset = inst.offset if hasattr(inst, "offset") else inst[0]
                            match_data = inst.matched_data if hasattr(inst, "matched_data") else inst[2]
                            strings_data.append({
                                "identifier": identifier,
                                "offset": offset,
                                "data": match_data.hex() if isinstance(match_data, bytes) else str(match_data),
                            })
                    except Exception:
                        pass

            meta: dict[str, Any] = dict(ym.meta) if ym.meta else {}
            tags = list(ym.tags) if ym.tags else []

            # Determine severity from meta if present
            severity = meta.get("severity", "info")
            if isinstance(severity, bytes):
                severity = severity.decode("utf-8", errors="ignore")

            matches.append(
                YaraMatch(
                    rule_name=ym.rule,
                    target="payload",
                    tags=tags,
                    meta=meta,
                    strings=strings_data,
                    severity=str(severity).lower(),
                )
            )
    except Exception as exc:
        logger.warning("YARA scan error: %s", exc)

    return matches


def scan_file(
    filepath: str,
    rules_path: str,
) -> list[YaraMatch]:
    """Scan a file against YARA rules.

    Args:
        filepath: Path to file to scan.
        rules_path: Path to YARA rule file or directory.

    Returns:
        List of YaraMatch objects.
    """
    if not _yara_installed():
        return []

    try:
        with open(filepath, "rb") as f:
            data = f.read()
        matches = scan_data(data, rules_path)
        # Update target to filename
        for m in matches:
            m.target = os.path.basename(filepath)
        return matches
    except Exception as exc:
        logger.warning("YARA file scan error for %s: %s", filepath, exc)
        return []


def _load_yara_rules(rules_path: str) -> Any:
    """Load YARA rules from a file or directory.

    Returns compiled rules object or None.
    """
    if not _yara_installed():
        return None

    try:
        import yara
    except ImportError:
        return None

    path = Path(rules_path)
    if not path.exists():
        logger.warning("YARA rules path not found: %s", rules_path)
        return None

    try:
        if path.is_file():
            return yara.compile(filepath=str(path))
        elif path.is_dir():
            # Compile all .yar and .yara files in directory
            rule_files: dict[str, str] = {}
            for f in path.iterdir():
                if f.suffix.lower() in (".yar", ".yara"):
                    rule_files[f.name] = str(f)
            if not rule_files:
                logger.warning("No YARA rule files found in %s", rules_path)
                return None
            return yara.compile(filepaths=rule_files)
        else:
            return None
    except yara.Error as exc:
        logger.warning("YARA compilation error: %s", exc)
        return None
    except Exception as exc:
        logger.warning("YARA load error: %s", exc)
        return None


def yara_to_findings(matches: list[YaraMatch]) -> list[dict[str, Any]]:
    """Convert YaraMatch objects to finding dictionaries.

    Args:
        matches: List of YaraMatch objects.

    Returns:
        List of finding dicts.
    """
    from pcaphunt.utils import stable_fingerprint

    findings: list[dict[str, Any]] = []
    for match in matches:
        finding = {
            "type": "yara_match",
            "original": f"YARA: {match.rule_name}",
            "decoded": None,
            "packet_numbers": [],
            "first_seen_packet": None,
            "protocol": "",
            "source": "",
            "destination": "",
            "offset": 0,
            "confidence": 1.0,
            "severity": match.severity,
            "notes": f"YARA rule matched: {match.rule_name}",
            "metadata": {
                "yara_rule": match.rule_name,
                "yara_tags": match.tags,
                "yara_meta": match.meta,
                "yara_target": match.target,
            },
        }
        finding["fingerprint"] = stable_fingerprint(finding)
        findings.append(finding)
    return findings
