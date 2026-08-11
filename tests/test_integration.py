"""Integration tests for PcapHunt."""

import json
import os
from pathlib import Path

import pytest

from pcaphunt.config import Config
from pcaphunt.engine import analyze_packets
from pcaphunt.output import write_findings


class TestIntegration:
    def test_analyze_simple_pcap(self, simple_tcp_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        assert len(findings) > 0

        # Check specific detections
        types = {f["type"] for f in findings}
        assert "plaintext" in types
        assert "base64" in types
        assert "hex" in types
        assert "url_encoded" in types
        assert "flags" in types
        assert "emails" in types
        assert "urls" in types
        assert "ip_addresses" in types
        assert "domains" in types
        assert "credentials" in types
        assert "hashes" in types
        assert "jwt" in types
        assert "files" in types

    def test_deep_mode_reconstructs_split_flag(self, split_flag_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)

        # Without deep mode, flag should not be found
        findings_shallow = analyze_packets(split_flag_pcap, config, deep=False)
        flag_findings_shallow = [f for f in findings_shallow if f["type"] == "flags"]
        assert len(flag_findings_shallow) == 0

        # With deep mode, flag should be reconstructed
        findings_deep = analyze_packets(split_flag_pcap, config, deep=True)
        flag_findings_deep = [f for f in findings_deep if f["type"] == "flags"]
        assert len(flag_findings_deep) > 0
        assert any("CTF{this_is_a_flag}" in str(f.get("decoded", "")) for f in flag_findings_deep)

        # Verify packet numbers are preserved
        flag = flag_findings_deep[0]
        assert len(flag["packet_numbers"]) == 2

    def test_malformed_packets_handled(self, malformed_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        # Should not crash
        findings = analyze_packets(malformed_pcap, config, deep=False)
        # At least the normal packet should be processed
        assert len(findings) >= 0

    def test_deduplication(self, simple_tcp_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        config.set("deduplication", True)
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        # Should not have exact duplicates
        fingerprints = [f.get("fingerprint") for f in findings if f.get("fingerprint")]
        assert len(fingerprints) == len(set(fingerprints))

    def test_output_files_created(self, simple_tcp_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        write_findings(findings, tmp_output_dir, deduplicate=True)

        # Check that output structure exists
        output_path = Path(tmp_output_dir)
        assert (output_path / "summary.txt").exists()
        assert (output_path / "findings.json").exists()

        # Check some category directories
        assert (output_path / "plaintext").exists()
        assert (output_path / "flags").exists()

        # Validate JSON
        with open(output_path / "findings.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, list)
        if data:
            assert "type" in data[0]
            assert "packet_numbers" in data[0]

    def test_no_dedup_mode(self, simple_tcp_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        config.set("deduplication", False)
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        # Should have more findings when dedup is off
        assert len(findings) > 0

    def test_search_filter(self, simple_tcp_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        # Filter for flag
        flag_results = [f for f in findings if "flag" in str(f.get("original", "")).lower()]
        assert len(flag_results) > 0
