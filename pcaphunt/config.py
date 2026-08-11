"""Configuration handling for PcapHunt."""

import os
from pathlib import Path
from typing import Any


DEFAULT_CONFIG: dict[str, Any] = {
    "min_length": 6,
    "enabled_detectors": [
        "plaintext",
        "base64",
        "hex",
        "url_encoded",
        "urls",
        "ip_addresses",
        "domains",
        "emails",
        "credentials",
        "flags",
        "hashes",
        "jwt",
        "files",
        "suspicious",
    ],
    "flag_patterns": [
        r"flag\{[^}]+\}",
        r"FLAG\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"ctf\{[^}]+\}",
        r"ICT\{[^}]+\}",
        r"HTB\{[^}]+\}",
        r"picoCTF\{[^}]+\}",
    ],
    "output_directory": "./PcapHunt_output",
    "max_decode_depth": 3,
    "deduplication": True,
    "deep_mode_default": False,
}


class Config:
    """PcapHunt configuration manager."""

    def __init__(self, overrides: dict[str, Any] | None = None):
        """Initialize configuration with optional overrides.

        Args:
            overrides: Dictionary of configuration overrides.
        """
        self._data: dict[str, Any] = dict(DEFAULT_CONFIG)
        self._load_config_file()
        if overrides:
            self._data.update(overrides)

    def _load_config_file(self) -> None:
        """Load configuration from file if it exists."""
        config_path = Path.home() / ".config" / "PcapHunt" / "config.toml"
        if not config_path.exists():
            return
        try:
            import tomllib

            with open(config_path, "rb") as f:
                data = tomllib.load(f)
            for key, value in data.items():
                if key in self._data:
                    self._data[key] = value
        except Exception:
            pass

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            key: Configuration key.
            default: Default value if key not found.

        Returns:
            Configuration value or default.
        """
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value.

        Args:
            key: Configuration key.
            value: Value to set.
        """
        self._data[key] = value

    @property
    def min_length(self) -> int:
        return int(self._data.get("min_length", 6))

    @property
    def enabled_detectors(self) -> list[str]:
        return list(self._data.get("enabled_detectors", []))

    @property
    def flag_patterns(self) -> list[str]:
        return list(self._data.get("flag_patterns", []))

    @property
    def output_directory(self) -> str:
        return str(self._data.get("output_directory", "./PcapHunt_output"))

    @property
    def max_decode_depth(self) -> int:
        return int(self._data.get("max_decode_depth", 3))

    @property
    def deduplication(self) -> bool:
        return bool(self._data.get("deduplication", True))

    @property
    def deep_mode_default(self) -> bool:
        return bool(self._data.get("deep_mode_default", False))


@staticmethod
def create_sample_config() -> str:
    """Return a sample configuration file content."""
    return """# PcapHunt Configuration File
# Place this file at ~/.config/PcapHunt/config.toml

# Minimum string length for plaintext extraction
min_length = 6

# List of enabled detectors
enabled_detectors = [
    "plaintext",
    "base64",
    "hex",
    "url_encoded",
    "urls",
    "ip_addresses",
    "domains",
    "emails",
    "credentials",
    "flags",
    "hashes",
    "jwt",
    "files",
    "suspicious",
]

# Custom flag regex patterns
flag_patterns = [
    'flag\\{[^}]+\\}',
    'FLAG\\{[^}]+\\}',
    'CTF\\{[^}]+\\}',
    'ctf\\{[^}]+\\}',
    'ICT\\{[^}]+\\}',
    'HTB\\{[^}]+\\}',
    'picoCTF\\{[^}]+\\}',
]

# Default output directory
output_directory = "./PcapHunt_output"

# Maximum recursive decode depth
max_decode_depth = 3

# Enable deduplication by default
deduplication = true

# Enable deep mode by default
deep_mode_default = false
"""
