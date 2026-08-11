"""Tests for PcapHunt CLI."""

import subprocess
import sys
from pathlib import Path

import pytest

from pcaphunt.cli import get_parser, run_cli


class TestCLI:
    def test_parser_help(self):
        parser = get_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--help"])

    def test_parser_version(self):
        parser = get_parser()
        args = parser.parse_args(["--version"])
        assert args.version is True

    def test_parser_min_length(self):
        parser = get_parser()
        args = parser.parse_args(["file.pcap", "--min-length", "10"])
        assert args.min_length == 10

    def test_parser_deep(self):
        parser = get_parser()
        args = parser.parse_args(["file.pcap", "--deep"])
        assert args.deep is True

    def test_parser_no_dedup(self):
        parser = get_parser()
        args = parser.parse_args(["file.pcap", "--no-dedup"])
        assert args.no_dedup is True

    def test_parser_json(self):
        parser = get_parser()
        args = parser.parse_args(["file.pcap", "--json"])
        assert args.json is True

    def test_parser_search(self):
        parser = get_parser()
        args = parser.parse_args(["file.pcap", "--search", "flag"])
        assert args.search == "flag"

    def test_run_cli_no_args(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["pcaphunt"])
        result = run_cli()
        assert result == 1

    def test_run_cli_nonexistent_file(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["pcaphunt", "/nonexistent/file.pcap"])
        result = run_cli()
        assert result == 1

    def test_module_entry_point(self, simple_tcp_pcap):
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "--quiet"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

    def test_json_output(self, simple_tcp_pcap):
        result = subprocess.run(
            [sys.executable, "-m", "pcaphunt", simple_tcp_pcap, "--json", "--quiet"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        import json
        data = json.loads(result.stdout)
        assert isinstance(data, list)
