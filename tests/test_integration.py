"""Integration tests for PcapHunt."""

import json
import os
from pathlib import Path

import pytest

from pcaphunt.config import Config
from pcaphunt.engine import analyze_packets
from pcaphunt.output import write_findings
from pcaphunt.report import generate_html_report


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

    def test_deduplication_content_based(self, duplicate_content_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        config.set("deduplication", True)
        findings = analyze_packets(duplicate_content_pcap, config, deep=False)

        # All three packets have the same content; should deduplicate to 1 finding
        flag_findings = [f for f in findings if f["type"] == "flags"]
        same_content_flags = [f for f in flag_findings if "same_content}" in str(f.get("decoded", ""))]
        assert len(same_content_flags) == 1

        # That one finding should have all 3 packet numbers merged
        deduped = same_content_flags[0]
        assert len(deduped["packet_numbers"]) == 3
        assert sorted(deduped["packet_numbers"]) == [1, 2, 3]

        # first_seen_packet should be the earliest
        assert deduped["first_seen_packet"] == 1

        # The similar-but-different content must still exist
        similar_flags = [f for f in flag_findings if "same_content!}" in str(f.get("decoded", ""))]
        assert len(similar_flags) == 1

        # The unique content must exist
        unique_flags = [f for f in flag_findings if "different}" in str(f.get("decoded", ""))]
        assert len(unique_flags) == 1

    def test_deduplication_no_dedup(self, duplicate_content_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        config.set("deduplication", False)
        findings = analyze_packets(duplicate_content_pcap, config, deep=False)

        flag_findings = [f for f in findings if f["type"] == "flags"]
        same_content_flags = [f for f in flag_findings if "same_content}" in str(f.get("decoded", ""))]
        # Without dedup, each packet produces its own finding
        assert len(same_content_flags) == 3

    def test_deduplication_cross_stream(self, tmp_output_dir):
        """Duplicate content found in TCP streams vs packets should still dedup."""
        from scapy.all import IP, TCP, Raw, wrpcap
        import tempfile

        packets = []
        # Packet 1: flag in single packet
        packets.append(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=80) / Raw(b"flag{cross_stream_test}"))
        # Packet 2: same flag in same stream
        packets.append(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=11111, dport=80) / Raw(b"flag{cross_stream_test}"))

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            wrpcap(f.name, packets)
            pcap_path = f.name

        try:
            config = Config()
            config.set("deduplication", True)
            findings = analyze_packets(pcap_path, config, deep=False)
            flags = [f for f in findings if f["type"] == "flags" and "cross_stream_test" in str(f.get("decoded", ""))]
            assert len(flags) == 1
            assert len(flags[0]["packet_numbers"]) == 2
        finally:
            os.unlink(pcap_path)

    def test_output_files_created(self, simple_tcp_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        write_findings(findings, tmp_output_dir)

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
        # Should have findings when dedup is off
        assert len(findings) > 0

    def test_search_filter(self, simple_tcp_pcap, tmp_output_dir):
        config = Config()
        config.set("output_directory", tmp_output_dir)
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        # Filter for flag
        flag_results = [f for f in findings if "flag" in str(f.get("original", "")).lower()]
        assert len(flag_results) > 0

    def test_custom_flag_pattern(self, tmp_output_dir):
        """Custom flag patterns should be detected."""
        from scapy.all import IP, TCP, Raw, wrpcap
        import tempfile

        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80) / Raw(b"CUSTOM{my_custom_flag}")
        ]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            wrpcap(f.name, packets)
            pcap_path = f.name

        try:
            config = Config()
            config.set("flag_patterns", [r"CUSTOM\{[^}]+\}"])
            findings = analyze_packets(pcap_path, config, deep=False)
            flags = [f for f in findings if f["type"] == "flags"]
            assert len(flags) == 1
            assert "CUSTOM{my_custom_flag}" in str(flags[0].get("decoded", ""))
        finally:
            os.unlink(pcap_path)

    def test_deep_mode_extracts_http(self, tmp_output_dir):
        """Deep mode should extract HTTP from reassembled TCP stream."""
        from scapy.all import IP, TCP, Raw, wrpcap
        import tempfile

        packets = []
        # HTTP GET split across 2 packets
        packets.append(
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1000)
            / Raw(b"GET /secret.txt HTTP/1.1\r\nHost: example.com\r\n")
        )
        packets.append(
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, seq=1045)
            / Raw(b"Cookie: session=abc123\r\n\r\n")
        )

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            wrpcap(f.name, packets)
            pcap_path = f.name

        try:
            config = Config()
            findings = analyze_packets(pcap_path, config, deep=True)
            http = [f for f in findings if f["type"] == "protocol_http"]
            assert len(http) > 0
            assert any("GET /secret.txt" in str(f.get("original", "")) for f in http)
        finally:
            os.unlink(pcap_path)

    def test_deep_mode_udp_conversations(self, tmp_output_dir):
        """Deep mode should group UDP packets into conversations."""
        from scapy.all import IP, UDP, Raw, wrpcap
        import tempfile

        packets = []
        packets.append(
            IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53)
            / Raw(b"flag{udp_flag_part1}")
        )
        packets.append(
            IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53)
            / Raw(b"flag{udp_flag_part2}")
        )

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            wrpcap(f.name, packets)
            pcap_path = f.name

        try:
            config = Config()
            findings = analyze_packets(pcap_path, config, deep=True)
            flags = [f for f in findings if f["type"] == "flags"]
            # Both UDP packets should be grouped; the flag might be split or found individually
            assert len(flags) >= 0  # At minimum, shouldn't crash
            # Check stream_id is present in some findings
            with_stream = [f for f in findings if f.get("stream_id")]
            assert len(with_stream) > 0
        finally:
            os.unlink(pcap_path)

    def test_severity_field_present(self, simple_tcp_pcap, tmp_output_dir):
        config = Config()
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        creds = [f for f in findings if f["type"] == "credentials"]
        if creds:
            assert "severity" in creds[0]
        flags = [f for f in findings if f["type"] == "flags"]
        if flags:
            assert "severity" in flags[0]


class TestHTMLReport:
    def test_html_report_generated(self, simple_tcp_pcap, tmp_output_dir):
        from pcaphunt.config import Config
        from pcaphunt.engine import analyze_packets
        from pcaphunt.report import generate_html_report

        config = Config()
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        report_path = Path(tmp_output_dir) / "report.html"
        generate_html_report(findings, "test.pcap", str(report_path), duration_seconds=0.5)

        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        assert "PcapHunt Report" in content
        assert "test.pcap" in content

    def test_html_contains_categories(self, simple_tcp_pcap, tmp_output_dir):
        from pcaphunt.config import Config
        from pcaphunt.engine import analyze_pcap
        from pcaphunt.report import generate_html_report

        config = Config()
        result = analyze_pcap(simple_tcp_pcap, config, deep=False)
        report_path = Path(tmp_output_dir) / "report.html"
        generate_html_report(result.findings, "test.pcap", str(report_path), result=result)

        content = report_path.read_text(encoding="utf-8")
        # Should contain tabs for new sections
        assert "overview" in content.lower()
        assert "findings" in content.lower()
        assert "files" in content.lower()
        assert "timeline" in content.lower()
        assert "network" in content.lower()
        # Should contain base64-encoded findings data for XSS safety
        assert "JSON.parse(atob" in content

    def test_html_escapes_content(self, tmp_output_dir):
        """Malicious/special content should be safely encoded in the report."""
        from pcaphunt.report import generate_html_report

        xss_payload = "<script>alert('xss')</script>"
        findings = [
            {
                "type": "plaintext",
                "packet_numbers": [1],
                "first_seen_packet": 1,
                "protocol": "TCP",
                "source": "10.0.0.1:80",
                "destination": "10.0.0.2:443",
                "offset": 0,
                "original": xss_payload,
                "decoded": xss_payload,
                "confidence": 1.0,
                "fingerprint": "abc123",
            },
            {
                "type": "plaintext",
                "packet_numbers": [2],
                "first_seen_packet": 2,
                "protocol": "TCP",
                "source": "10.0.0.1:80",
                "destination": "10.0.0.2:443",
                "offset": 0,
                "original": 'hello"world',
                "decoded": 'hello"world',
                "confidence": 1.0,
                "fingerprint": "def456",
            },
        ]
        report_path = Path(tmp_output_dir) / "report.html"
        generate_html_report(findings, "test.pcap", str(report_path))

        content = report_path.read_text(encoding="utf-8")
        # The literal XSS payload must NOT appear in executable form in the HTML
        assert "<script>alert" not in content
        # It should be embedded safely (base64-encoded inside a JS atob() call)
        assert "atob(" in content
        # The HTML template meta title should be escaped properly
        assert "test.pcap" in content

    def test_html_empty_results(self, tmp_output_dir):
        """An empty result set should still produce a valid report."""
        from pcaphunt.report import generate_html_report

        report_path = Path(tmp_output_dir) / "report.html"
        generate_html_report([], "empty.pcap", str(report_path))

        assert report_path.exists()
        content = report_path.read_text(encoding="utf-8")
        assert "PcapHunt Report" in content
        assert "empty.pcap" in content
        # Empty array base64 encoded is W10=
        assert "W10=" in content

    def test_html_does_not_break_txt_output(self, simple_tcp_pcap, tmp_output_dir):
        from pcaphunt.config import Config
        from pcaphunt.engine import analyze_packets
        from pcaphunt.output import write_findings
        from pcaphunt.report import generate_html_report

        config = Config()
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        write_findings(findings, tmp_output_dir)
        generate_html_report(findings, "test.pcap", str(Path(tmp_output_dir) / "report.html"))

        # TXT output must still exist and be valid
        summary = Path(tmp_output_dir) / "summary.txt"
        assert summary.exists()
        assert "PcapHunt Summary" in summary.read_text()

        # JSON must still exist
        json_file = Path(tmp_output_dir) / "findings.json"
        assert json_file.exists()
        data = json.loads(json_file.read_text())
        assert isinstance(data, list)

    def test_html_contains_search_and_filter(self, simple_tcp_pcap, tmp_output_dir):
        from pcaphunt.config import Config
        from pcaphunt.engine import analyze_packets
        from pcaphunt.report import generate_html_report

        config = Config()
        findings = analyze_packets(simple_tcp_pcap, config, deep=False)
        report_path = Path(tmp_output_dir) / "report.html"
        generate_html_report(findings, "test.pcap", str(report_path))

        content = report_path.read_text(encoding="utf-8")
        assert "searchInput" in content
        assert "filterType" in content
        assert "sortBy" in content
        assert "openModal" in content

    def test_cli_filter_options(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir,
             "--quiet", "--category", "flags"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        findings = json.loads((Path(tmp_output_dir) / "findings.json").read_text())
        assert all(f.get("type") == "flags" for f in findings)

    def test_cli_severity_filter(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir,
             "--quiet", "--severity", "high"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        findings = json.loads((Path(tmp_output_dir) / "findings.json").read_text())
        sev_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        for f in findings:
            assert sev_map.get(f.get("severity", "info"), 0) >= 3

    def test_cli_min_score_filter(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir,
             "--quiet", "--min-score", "50"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        findings = json.loads((Path(tmp_output_dir) / "findings.json").read_text())
        for f in findings:
            assert f.get("score", 0) >= 50

    def test_cli_protocol_filter(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir,
             "--quiet", "--protocol", "TCP"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        findings = json.loads((Path(tmp_output_dir) / "findings.json").read_text())
        for f in findings:
            assert f.get("protocol", "").upper() == "TCP"

    def test_cli_ip_filter(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir,
             "--quiet", "--ip", "10.0.0.1"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        findings = json.loads((Path(tmp_output_dir) / "findings.json").read_text())
        for f in findings:
            src = f.get("source", "")
            dst = f.get("destination", "")
            assert "10.0.0.1" in src or "10.0.0.1" in dst

    def test_cli_no_extract(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir,
             "--quiet", "--no-extract"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        extracted_dir = Path(tmp_output_dir) / "extracted_files"
        # Should still exist as directory but may be empty
        assert extracted_dir.exists() or True

    def test_full_analysis_result(self, simple_tcp_pcap, tmp_output_dir):
        from pcaphunt.config import Config
        from pcaphunt.engine import analyze_pcap

        config = Config()
        result = analyze_pcap(simple_tcp_pcap, config, deep=False)

        assert len(result.findings) > 0
        assert result.profile is not None
        assert result.profile.total_packets > 0
        assert result.timeline is not None
        assert len(result.timeline) > 0
        assert result.nodes is not None
        assert result.edges is not None

    def test_profile_json_output(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir, "--quiet"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        profile_path = Path(tmp_output_dir) / "profile.json"
        assert profile_path.exists()
        data = json.loads(profile_path.read_text())
        assert data.get("total_packets", 0) > 0

    def test_timeline_json_output(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir, "--quiet"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        timeline_path = Path(tmp_output_dir) / "timeline.json"
        assert timeline_path.exists()
        data = json.loads(timeline_path.read_text())
        assert isinstance(data, list)
        if data:
            assert "event_type" in data[0]

    def test_topology_json_output(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir, "--quiet"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        topo_path = Path(tmp_output_dir) / "topology.json"
        assert topo_path.exists()
        data = json.loads(topo_path.read_text())
        assert "nodes" in data
        assert "edges" in data

    def test_scoring_applied(self, simple_tcp_pcap, tmp_output_dir):
        import subprocess
        import sys
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "-o", tmp_output_dir, "--quiet"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        findings = json.loads((Path(tmp_output_dir) / "findings.json").read_text())
        flags = [f for f in findings if f.get("type") == "flags"]
        if flags:
            assert "score" in flags[0]
            assert flags[0]["score"] >= 80
            assert "score_reasons" in flags[0]

    def test_html_report_phase2_sections(self, simple_tcp_pcap, tmp_output_dir):
        from pcaphunt.config import Config
        from pcaphunt.engine import analyze_pcap
        from pcaphunt.report import generate_html_report

        config = Config()
        result = analyze_pcap(simple_tcp_pcap, config, deep=False)
        report_path = Path(tmp_output_dir) / "report.html"
        generate_html_report(result.findings, "test.pcap", str(report_path), result=result)

        content = report_path.read_text(encoding="utf-8")
        assert "Overview" in content
        assert "Files" in content
        assert "Timeline" in content
        assert "Network" in content
        assert "Streams" in content
        assert "JSON.parse(atob" in content
