"""Tests for PcapHunt custom rules and plugin system."""

from __future__ import annotations

import tempfile

import pytest

from pcaphunt.plugins import PcapHuntPlugin, discover_plugins, load_plugins, run_plugins_on_packet
from pcaphunt.rules import CustomRule, RuleEngine, rules_to_findings


class TestCustomRule:
    def test_compile_valid(self):
        rule = CustomRule(name="test", category="flag", severity="high", regex=r"FLAG\{[^}]+\}")
        assert rule.compile() is True

    def test_compile_invalid(self):
        rule = CustomRule(name="bad", category="flag", severity="high", regex=r"[invalid")
        assert rule.compile() is False

    def test_match(self):
        rule = CustomRule(name="flag", category="flag", severity="high", regex=r"flag\{[^}]+\}")
        rule.compile()
        matches = rule.match("here is a flag{test} in text")
        assert len(matches) == 1
        assert matches[0].group(0) == "flag{test}"

    def test_no_match(self):
        rule = CustomRule(name="flag", category="flag", severity="high", regex=r"flag\{[^}]+\}")
        rule.compile()
        matches = rule.match("no flag here")
        assert len(matches) == 0

    def test_disabled(self):
        rule = CustomRule(name="off", category="flag", severity="high", regex=r"test", enabled=False)
        rule.compile()
        matches = rule.match("test")
        assert len(matches) == 0


class TestRuleEngine:
    def test_from_dict_list(self):
        rules_data = [
            {"name": "flag", "category": "flag", "severity": "high", "regex": r"flag\{[^}]+\}"},
            {"name": "api", "category": "credential", "severity": "medium", "regex": r"API_[A-Z0-9]{32}"},
        ]
        engine = RuleEngine.from_dict_list(rules_data)
        assert len(engine.rules) == 2

    def test_scan(self):
        engine = RuleEngine.from_dict_list([
            {"name": "flag", "category": "flag", "severity": "high", "regex": r"flag\{[^}]+\}"},
        ])
        context = {"first_seen_packet": 1, "source": "10.0.0.1", "protocol": "TCP"}
        matches = engine.scan(b"hello flag{test} world", context)
        assert len(matches) == 1
        assert matches[0].rule_name == "flag"
        assert matches[0].matched_text == "flag{test}"

    def test_scan_empty(self):
        engine = RuleEngine.from_dict_list([])
        matches = engine.scan(b"data", {})
        assert len(matches) == 0

    def test_scan_no_match(self):
        engine = RuleEngine.from_dict_list([
            {"name": "flag", "category": "flag", "severity": "high", "regex": r"flag\{[^}]+\}"},
        ])
        matches = engine.scan(b"no flag here", {})
        assert len(matches) == 0

    def test_rules_to_findings(self):
        from pcaphunt.models import RuleMatch
        matches = [
            RuleMatch(rule_name="r1", category="flag", matched_text="FLAG{a}", severity="high", confidence=1.0),
        ]
        findings = rules_to_findings(matches)
        assert len(findings) == 1
        assert findings[0]["type"] == "rule_flag"
        assert findings[0]["original"] == "FLAG{a}"
        assert "fingerprint" in findings[0]


class TestPluginSystem:
    def test_discover_plugins_empty(self):
        classes = discover_plugins()
        assert isinstance(classes, list)

    def test_load_plugins(self):
        class DummyPlugin(PcapHuntPlugin):
            name = "dummy"
            version = "1.0.0"

            def process_packet(self, pkt_num, pkt, payload, context):
                return []

        classes = [DummyPlugin]
        instances = load_plugins(classes)
        assert len(instances) == 1
        assert instances[0].name == "dummy"

    def test_run_plugins_on_packet(self):
        class FindingPlugin(PcapHuntPlugin):
            name = "finder"
            version = "1.0.0"

            def process_packet(self, pkt_num, pkt, payload, context):
                return [
                    {
                        "type": "plugin_finding",
                        "original": "found",
                        "packet_numbers": [pkt_num],
                        "first_seen_packet": pkt_num,
                        "protocol": "TCP",
                        "source": "",
                        "destination": "",
                        "confidence": 1.0,
                        "severity": "info",
                        "fingerprint": "abc",
                    }
                ]

        instances = load_plugins([FindingPlugin])
        findings = run_plugins_on_packet(instances, 1, None, b"data", {})
        assert len(findings) == 1
        assert findings[0]["type"] == "plugin_finding"

    def test_plugin_finalize(self):
        class FinalizePlugin(PcapHuntPlugin):
            name = "final"
            version = "1.0.0"

            def process_packet(self, pkt_num, pkt, payload, context):
                return []

            def finalize(self):
                return [
                    {
                        "type": "plugin_summary",
                        "original": "done",
                        "packet_numbers": [],
                        "first_seen_packet": None,
                        "protocol": "",
                        "source": "",
                        "destination": "",
                        "confidence": 1.0,
                        "severity": "info",
                        "fingerprint": "xyz",
                    }
                ]

        instances = load_plugins([FinalizePlugin])
        from pcaphunt.plugins import finalize_plugins
        findings = finalize_plugins(instances)
        assert len(findings) == 1
        assert findings[0]["type"] == "plugin_summary"
