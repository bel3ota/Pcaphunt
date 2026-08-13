"""Custom detection rules for PcapHunt.

Supports YAML-based user-defined detection rules.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from pcaphunt.models import RuleMatch

logger = logging.getLogger(__name__)


class CustomRule:
    """A single custom detection rule."""

    def __init__(
        self,
        name: str,
        category: str,
        severity: str,
        regex: str,
        description: str = "",
        confidence: float = 1.0,
        enabled: bool = True,
    ):
        self.name = name
        self.category = category
        self.severity = severity
        self.regex = regex
        self.description = description
        self.confidence = confidence
        self.enabled = enabled
        self._compiled: re.Pattern | None = None

    def compile(self) -> bool:
        """Compile the regex pattern. Return True on success."""
        if not self.enabled:
            return True
        try:
            self._compiled = re.compile(self.regex)
            return True
        except re.error as exc:
            logger.warning("Invalid regex in rule '%s': %s", self.name, exc)
            return False

    def match(self, data: str) -> list[re.Match]:
        """Find all matches in the given data string."""
        if not self.enabled or self._compiled is None:
            return []
        return list(self._compiled.finditer(data))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "regex": self.regex,
            "description": self.description,
            "confidence": self.confidence,
            "enabled": self.enabled,
        }


class RuleEngine:
    """Engine for loading and applying custom detection rules."""

    def __init__(self, rules: list[CustomRule] | None = None):
        self.rules: list[CustomRule] = rules or []
        self._invalid_rules: list[str] = []

    @classmethod
    def from_yaml(cls, path: str) -> "RuleEngine":
        """Load rules from a YAML file.

        Args:
            path: Path to YAML rules file.

        Returns:
            RuleEngine with loaded rules.
        """
        rules: list[CustomRule] = []
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("Rules file not found: %s", path)
            return cls(rules)

        try:
            import yaml
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except ImportError:
            logger.error("PyYAML is required for custom rules. Install with: pip install pyyaml")
            return cls(rules)
        except Exception as exc:
            logger.error("Failed to load rules file %s: %s", path, exc)
            return cls(rules)

        raw_rules = data.get("rules", []) if isinstance(data, dict) else []
        for raw in raw_rules:
            if not isinstance(raw, dict):
                continue
            name = raw.get("name", "unnamed")
            category = raw.get("category", "finding")
            severity = raw.get("severity", "info")
            regex = raw.get("regex", "")
            description = raw.get("description", "")
            confidence = float(raw.get("confidence", 1.0))
            enabled = bool(raw.get("enabled", True))

            if not regex:
                logger.warning("Rule '%s' has no regex pattern, skipping", name)
                continue

            rule = CustomRule(
                name=name,
                category=category,
                severity=severity,
                regex=regex,
                description=description,
                confidence=confidence,
                enabled=enabled,
            )
            if not rule.compile():
                logger.warning("Rule '%s' has invalid regex and will be skipped", name)
            else:
                rules.append(rule)

        return cls(rules)

    @classmethod
    def from_dict_list(cls, rules_list: list[dict[str, Any]]) -> "RuleEngine":
        """Load rules from a list of dictionaries."""
        rules: list[CustomRule] = []
        for raw in rules_list:
            rule = CustomRule(
                name=raw.get("name", "unnamed"),
                category=raw.get("category", "finding"),
                severity=raw.get("severity", "info"),
                regex=raw.get("regex", ""),
                description=raw.get("description", ""),
                confidence=float(raw.get("confidence", 1.0)),
                enabled=bool(raw.get("enabled", True)),
            )
            if rule.compile():
                rules.append(rule)
        return cls(rules)

    def scan(
        self,
        data: bytes,
        context: dict[str, Any],
    ) -> list[RuleMatch]:
        """Scan data against all enabled rules.

        Args:
            data: Raw bytes to scan.
            context: Packet/stream context.

        Returns:
            List of RuleMatch objects.
        """
        matches: list[RuleMatch] = []
        if not data:
            return matches

        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            return matches

        for rule in self.rules:
            if not rule.enabled or rule._compiled is None:
                continue

            try:
                for m in rule.match(text):
                    matched_text = m.group(0)
                    offset = m.start()
                    match_obj = RuleMatch(
                        rule_name=rule.name,
                        category=rule.category,
                        matched_text=matched_text,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        description=rule.description,
                        packet_number=context.get("first_seen_packet"),
                        source=context.get("source", ""),
                        destination=context.get("destination", ""),
                        protocol=context.get("protocol", ""),
                        stream_id=context.get("stream_id"),
                        offset=offset,
                        timestamp=context.get("timestamp"),
                    )
                    matches.append(match_obj)
            except Exception as exc:
                logger.debug("Rule '%s' match error: %s", rule.name, exc)

        return matches

    def get_rule_dicts(self) -> list[dict[str, Any]]:
        """Return all rules as dictionaries."""
        return [r.to_dict() for r in self.rules]


def rules_to_findings(matches: list[RuleMatch]) -> list[dict[str, Any]]:
    """Convert RuleMatch objects to finding dictionaries.

    Args:
        matches: List of RuleMatch objects.

    Returns:
        List of finding dicts compatible with the engine.
    """
    from pcaphunt.utils import stable_fingerprint

    findings: list[dict[str, Any]] = []
    for match in matches:
        finding = {
            "type": f"rule_{match.category}",
            "original": match.matched_text,
            "packet_numbers": [match.packet_number] if match.packet_number is not None else [],
            "first_seen_packet": match.packet_number,
            "protocol": match.protocol,
            "source": match.source,
            "destination": match.destination,
            "offset": match.offset,
            "confidence": match.confidence,
            "severity": match.severity,
            "stream_id": match.stream_id,
            "timestamp": match.timestamp,
            "notes": match.description,
            "metadata": {
                "rule_name": match.rule_name,
                "rule_category": match.category,
            },
        }
        finding["fingerprint"] = stable_fingerprint(finding)
        findings.append(finding)
    return findings
