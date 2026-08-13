"""Plugin system for PcapHunt.

Extensible plugin architecture for custom detectors and processors.
Plugins are trusted local code installed by the user.
"""

from __future__ import annotations

import importlib
import inspect
import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


class PcapHuntPlugin(ABC):
    """Base class for PcapHunt plugins.

    Plugins receive packets, streams, and findings, and can produce
    their own normalized findings that integrate into the report.
    """

    name: str = "unnamed"
    version: str = "0.0.1"

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self._initialized = False

    def initialize(self, global_config: dict[str, Any]) -> None:
        """Called once before processing begins.

        Args:
            global_config: The full PcapHunt configuration dict.
        """
        self._initialized = True

    @abstractmethod
    def process_packet(
        self,
        pkt_num: int,
        pkt: Any,
        payload: bytes,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Process a single packet.

        Args:
            pkt_num: Packet number.
            pkt: Scapy packet object.
            payload: Packet payload bytes.
            context: Packet context dict.

        Returns:
            List of finding dicts (can be empty).
        """
        ...

    def process_stream(
        self,
        stream_id: str,
        reassembled: bytes,
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Process a reconstructed TCP/UDP stream.

        Args:
            stream_id: Stream identifier.
            reassembled: Reassembled stream bytes.
            context: Stream context dict.

        Returns:
            List of finding dicts (can be empty).
        """
        return []

    def finalize(self) -> list[dict[str, Any]]:
        """Called after all processing is complete.

        Returns:
            List of any final findings.
        """
        return []


def discover_plugins() -> list[type[PcapHuntPlugin]]:
    """Discover plugins via entry points.

    Looks for plugins registered under the "pcaphunt.plugins" entry point.

    Returns:
        List of plugin classes.
    """
    classes: list[type[PcapHuntPlugin]] = []

    try:
        from importlib.metadata import entry_points
        eps = entry_points()
        if hasattr(eps, "select"):
            group = eps.select(group="pcaphunt.plugins")
        else:
            group = eps.get("pcaphunt.plugins", [])
        for ep in group:
            try:
                cls = ep.load()
                if inspect.isclass(cls) and issubclass(cls, PcapHuntPlugin):
                    classes.append(cls)
            except Exception as exc:
                logger.warning("Failed to load plugin %s: %s", ep.name, exc)
    except Exception as exc:
        logger.debug("Plugin discovery error: %s", exc)

    return classes


def load_plugins(
    plugin_classes: list[type[PcapHuntPlugin]],
    config: dict[str, Any] | None = None,
) -> list[PcapHuntPlugin]:
    """Instantiate plugin classes.

    Args:
        plugin_classes: List of plugin classes to instantiate.
        config: Optional configuration dict.

    Returns:
        List of plugin instances.
    """
    instances: list[PcapHuntPlugin] = []
    for cls in plugin_classes:
        try:
            inst = cls(config)
            instances.append(inst)
        except Exception as exc:
            logger.warning("Failed to instantiate plugin %s: %s", cls.__name__, exc)
    return instances


def run_plugins_on_packet(
    plugins: list[PcapHuntPlugin],
    pkt_num: int,
    pkt: Any,
    payload: bytes,
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run all plugins on a packet and collect findings.

    Args:
        plugins: List of plugin instances.
        pkt_num: Packet number.
        pkt: Scapy packet.
        payload: Payload bytes.
        context: Context dict.

    Returns:
        Combined list of findings from all plugins.
    """
    all_findings: list[dict[str, Any]] = []
    for plugin in plugins:
        try:
            if not plugin._initialized:
                plugin.initialize({})
            findings = plugin.process_packet(pkt_num, pkt, payload, context)
            all_findings.extend(findings)
        except Exception as exc:
            logger.debug("Plugin %s error on packet %d: %s", plugin.name, pkt_num, exc)
    return all_findings


def run_plugins_on_stream(
    plugins: list[PcapHuntPlugin],
    stream_id: str,
    reassembled: bytes,
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run all plugins on a reconstructed stream.

    Args:
        plugins: List of plugin instances.
        stream_id: Stream identifier.
        reassembled: Reassembled bytes.
        context: Stream context dict.

    Returns:
        Combined list of findings.
    """
    all_findings: list[dict[str, Any]] = []
    for plugin in plugins:
        try:
            if not plugin._initialized:
                plugin.initialize({})
            findings = plugin.process_stream(stream_id, reassembled, context)
            all_findings.extend(findings)
        except Exception as exc:
            logger.debug("Plugin %s error on stream %s: %s", plugin.name, stream_id, exc)
    return all_findings


def finalize_plugins(plugins: list[PcapHuntPlugin]) -> list[dict[str, Any]]:
    """Finalize all plugins and collect final findings.

    Args:
        plugins: List of plugin instances.

    Returns:
        Combined list of final findings.
    """
    all_findings: list[dict[str, Any]] = []
    for plugin in plugins:
        try:
            findings = plugin.finalize()
            all_findings.extend(findings)
        except Exception as exc:
            logger.debug("Plugin %s finalize error: %s", plugin.name, exc)
    return all_findings
