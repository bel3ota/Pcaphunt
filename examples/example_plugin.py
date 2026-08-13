"""Example PcapHunt plugin.

This plugin demonstrates how to create a custom PcapHunt plugin
that produces normalized findings.

To use this plugin, install it as a Python package with an entry point
under the "pcaphunt.plugins" group:

    [project.entry-points."pcaphunt.plugins"]
    my_plugin = my_plugin:MyPlugin

Or place this file in a package and ensure the package is installed
in the same Python environment as PcapHunt.
"""

from __future__ import annotations

from typing import Any

from pcaphunt.plugins import PcapHuntPlugin


class ExamplePlugin(PcapHuntPlugin):
    """Example plugin that detects the word 'SECRET' in payloads."""

    name = "example"
    version = "1.0.0"

    def initialize(self, global_config: dict[str, Any]) -> None:
        """Called once before processing begins."""
        super().initialize(global_config)
        self.matches = 0

    def process_packet(
        self,
        pkt_num: int,
        pkt: Any,
        payload: bytes,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Process a single packet and return findings."""
        findings: list[dict[str, Any]] = []
        if not payload:
            return findings

        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return findings

        if "SECRET" in text.upper():
            self.matches += 1
            findings.append(
                {
                    "type": "plugin_secret",
                    "original": "SECRET keyword detected",
                    "packet_numbers": [pkt_num],
                    "first_seen_packet": pkt_num,
                    "protocol": context.get("protocol", "Unknown"),
                    "source": context.get("source", ""),
                    "destination": context.get("destination", ""),
                    "confidence": 0.8,
                    "severity": "medium",
                    "notes": "Example plugin detected SECRET keyword",
                    "fingerprint": "example_secret_" + str(pkt_num),
                }
            )
        return findings

    def finalize(self) -> list[dict[str, Any]]:
        """Return a summary finding after all processing."""
        if self.matches > 0:
            return [
                {
                    "type": "plugin_summary",
                    "original": f"Example plugin found {self.matches} SECRET mentions",
                    "packet_numbers": [],
                    "first_seen_packet": None,
                    "protocol": "",
                    "source": "",
                    "destination": "",
                    "confidence": 1.0,
                    "severity": "info",
                    "notes": "Summary from example plugin",
                    "fingerprint": "example_summary",
                }
            ]
        return []
