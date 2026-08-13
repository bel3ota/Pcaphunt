# PcapHunt

[![PyPI version](https://img.shields.io/pypi/v/pcaphunt.svg)](https://pypi.org/project/pcaphunt/)
[![Python versions](https://img.shields.io/pypi/pyversions/pcaphunt.svg)](https://pypi.org/project/pcaphunt/)
[![CI](https://github.com/bel3ota/PcapHunt/actions/workflows/ci.yml/badge.svg)](https://github.com/bel3ota/PcapHunt/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**PcapHunt** is a Python CLI tool for automated PCAP/PCAPNG triage and investigation. It extracts useful content, reconstructs streams and files, detects secrets and encoded data, profiles network activity, prioritizes findings with risk scoring, and generates machine-readable and interactive reports.

```text
 ____                 _   _             _
|  _ \ ___ __ _ _ __ | | | |_   _ _ __ | |_
| |_) / __/ _` | '_ \| |_| | | | | '_ \| __|
|  __/ (_| (_| | |_) |  _  | |_| | | | | |_
|_|   \___\__,_| .__/|_| |_\__,_|_| |_\__|
               |_|
```

## Why PcapHunt?

During CTFs and incident-response investigations, PCAP files often contain thousands of packets. Manually scrolling through them in Wireshark is time-consuming and error-prone. **PcapHunt performs a structured first-pass investigation** and surfaces the data most likely to matter — flags, credentials, files, suspicious patterns, and protocol metadata.

PcapHunt is **complementary to Wireshark**, not a replacement. Wireshark excels at deep manual packet inspection. PcapHunt excels at rapid automated triage.

## Features

### Detection & Hunting
- **Plaintext string extraction** — ASCII and UTF-8 with configurable minimum length
- **Encoded data detection** — Base64, Base32, hex, URL encoding, HTML entities, ROT13
- **Compressed data detection** — gzip and zlib payload identification
- **Flag hunting** — configurable regex patterns for CTF formats (`flag{...}`, `CTF{...}`, `HTB{...}`, etc.)
- **Credential/secret hunting** — passwords, tokens, API keys, bearer tokens, private keys
- **URL, domain, IP, and email detection**
- **Hash and JWT detection**
- **File signature detection** — 20+ formats by magic bytes
- **Suspicious payload detection** — high-entropy data indicating compression or encryption
- **Recursive decoding chains** — automatically decode nested encodings

### Network Analysis
- **PCAP and PCAPNG support**
- **TCP stream reassembly** — sequence-number tracking, out-of-order handling, retransmission deduplication, overlap resolution
- **UDP conversation reconstruction** — groups related UDP packets into flows
- **Protocol-aware extraction** — HTTP, DNS, FTP, SMTP, IRC, DHCP metadata
- **PCAP profiling** — packet counts, bytes, duration, unique IPs/MACs, protocols, top talkers, top ports, top conversations
- **Investigation timeline** — chronological events: stream creation, DNS queries, HTTP requests, finding detections, file extractions
- **Network topology** — communication graph with nodes, edges, protocol metadata, and suspicious host marking

### File Analysis
- **File reconstruction** — extracts files from HTTP bodies, TCP streams, and UDP conversations
- **Magic/signature detection** — recognizes PNG, JPEG, GIF, PDF, ZIP, GZIP, TAR, ELF, PE, SQLite, WAV, MP3, MP4, DOCX, XLSX, PPTX, RAR, 7Z, BMP, TIFF
- **Completeness tracking** — marks incomplete reconstructions with reasons
- **Streaming hashes** — MD5, SHA1, SHA256 for every extracted file
- **Safe filename sanitization** — prevents path traversal attacks

### Investigation & Prioritization
- **Content-based deduplication** — identical findings across packets/streams are merged, not duplicated
- **Risk scoring** — heuristic 0-100 score per finding with severity mapping and explanations
- **Advanced filtering** — filter by category, protocol, IP, port, severity, score, stream ID
- **Stream investigation** — view findings associated with each reconstructed stream

### Extensibility
- **Custom YAML rules** — user-defined regex-based detection rules
- **Optional YARA integration** — scan payloads and extracted files against YARA rules
- **Plugin system** — Python entry-point based architecture for custom detectors

### Reporting
- **Rich terminal output** — progress bars, color-coded severity, summary statistics
- **Self-contained HTML report** — interactive tabs for Overview, Findings, Files, Timeline, Network, Streams; client-side search/filter/sort; XSS-safe via base64 encoding
- **JSON output** — findings list or complete `full_result.json` with profile, timeline, topology, artifacts
- **Structured text output** — one file per finding with full metadata

## Installation

### From PyPI

```bash
pip install pcaphunt
```

Or with [pipx](https://pypa.github.io/pipx/):

```bash
pipx install pcaphunt
```

### From source (development)

```bash
git clone https://github.com/bel3ota/PcapHunt.git
cd PcapHunt
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Optional dependencies

```bash
# For custom YAML rules support
pip install "pcaphunt[rules]"

# For YARA integration
pip install "pcaphunt[yara]"

# Development dependencies (tests, build)
pip install "pcaphunt[dev]"
```

### Verify installation

```bash
pcaphunt --version
pcaphunt --help
python -m pcaphunt --version
```

## Usage

### Basic scan

```bash
pcaphunt capture.pcap
```

### Deep mode (TCP/UDP stream reassembly + protocols + file extraction)

```bash
pcaphunt capture.pcap --deep
```

### JSON output

```bash
pcaphunt capture.pcap --json --quiet
```

### Search and filter

```bash
pcaphunt capture.pcap --search "flag"
pcaphunt capture.pcap --category flags
pcaphunt capture.pcap --protocol HTTP --ip 10.10.10.5
pcaphunt capture.pcap --severity high
pcaphunt capture.pcap --min-score 50
```

### Custom detection rules

```bash
pcaphunt capture.pcap --rules rules.yaml
```

### YARA scanning

```bash
pcaphunt capture.pcap --yara /path/to/yara/rules/
```

### Specify output directory

```bash
pcaphunt capture.pcap -o ./results
```

### Disable features

```bash
pcaphunt capture.pcap --no-html       # Skip HTML report
pcaphunt capture.pcap --no-dedup      # Disable deduplication
pcaphunt capture.pcap --no-extract     # Disable file extraction
pcaphunt capture.pcap --quiet          # Suppress terminal output
```

## Examples

### Example 1: Basic scan

```bash
$ pcaphunt challenge.pcap

 ____                 _   _             _
|  _ \ ___ __ _ _ __ | | | |_   _ _ __ | |_
| |_) / __/ _` | '_ \| |_| | | | | '_ \| __|
|  __/ (_| (_| | |_) |  _  | |_| | | | | |_
|_|   \___\__,_| .__/|_| |_\__,_|_| |_\__|
               |_|

[*] Input: challenge.pcap
[*] Packets: 18,421

[+] Analyzing packets... 100%

────────────────────────────────────────────
              PcapHunt RESULTS
────────────────────────────────────────────

Packets:        18,421
Duration:       00:14:32

Findings:       97
Critical:       3
High:          17
Medium:        24
Low:           53

Files:           12
Streams:        421
DNS Queries:    312
HTTP Requests:   84

🏁 FLAGS FOUND:
  flag{hidden_in_stream}
  CTF{reconstructed_flag}

🔒 Credentials detected: 4
  (saved to output/credentials/)

📁 Files extracted: 8/12 complete
  (saved to output/extracted_files/)

📡 Protocol Findings:
  HTTP: 5
  DNS: 3

[+] Results: ./pcaphunt_output/
[+] HTML report: ./pcaphunt_output/report.html
[+] Analysis completed in 4.82 seconds
```

### Example 2: Deep mode with rules and YARA

```bash
$ pcaphunt challenge.pcap --deep --rules my_rules.yaml --yara yara_rules/ -o ./deep_results
```

### Example 3: JSON output with filtering

```bash
$ pcaphunt challenge.pcap --json --quiet --category flags --severity high | jq '.[] | select(.type == "flags")'

{
  "type": "flags",
  "packet_numbers": [100, 101],
  "first_seen_packet": 100,
  "protocol": "TCP",
  "source": "10.0.0.5:43122",
  "destination": "10.0.0.10:80",
  "stream_id": "tcp_10.0.0.5:43122->10.0.0.10:80",
  "offset": 42,
  "original": "CTF{this_is_a_flag}",
  "decoded": "CTF{this_is_a_flag}",
  "confidence": 1.0,
  "severity": "critical",
  "score": 88,
  "score_reasons": ["CTF flag pattern matched", "Severity marked as critical"],
  "score_factors": {"flag_detected": 80, "severity_critical": 15, "high_confidence": 8}
}
```

## CLI Reference

```text
$ pcaphunt --help
usage: pcaphunt [-h] [-o OUTPUT] [--deep] [--min-length MIN_LENGTH]
                [--no-dedup] [--json] [--quiet] [--search SEARCH]
                [--version] [--html] [--no-html] [--pattern PATTERNS]
                [--category CATEGORY] [--protocol PROTOCOL] [--ip IP]
                [--src-ip SRC_IP] [--dst-ip DST_IP] [--port PORT]
                [--severity SEVERITY] [--min-score MIN_SCORE]
                [--stream STREAM] [--no-extract] [--rules RULES]
                [--yara YARA]
                [pcap]

PcapHunt - Hunt for useful data in PCAP/PCAPNG files

positional arguments:
  pcap                  Path to PCAP/PCAPNG file

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Output directory (default: ./pcaphunt_output)
  --deep                Enable deep mode (TCP/UDP stream reassembly,
                        protocol extraction, file extraction)
  --min-length MIN_LENGTH
                        Minimum plaintext string length (default: 6)
  --no-dedup            Disable deduplication
  --json                Output findings as JSON to stdout
  --quiet               Suppress terminal output
  --search SEARCH       Filter findings by search string
  --version             Show version and exit
  --html                Generate HTML report (default: enabled)
  --no-html             Disable HTML report generation
  --pattern PATTERNS    Add a custom flag regex pattern (can be used
                        multiple times)
  --category CATEGORY   Filter findings by category/type
  --protocol PROTOCOL   Filter findings by protocol
  --ip IP               Filter findings by IP (source or destination)
  --src-ip SRC_IP       Filter findings by source IP
  --dst-ip DST_IP       Filter findings by destination IP
  --port PORT           Filter findings by port
  --severity SEVERITY   Filter findings by minimum severity
  --min-score MIN_SCORE
                        Filter findings by minimum score
  --stream STREAM       Filter findings by stream ID
  --no-extract          Disable file extraction
  --rules RULES         Path to custom rules YAML file
  --yara YARA           Path to YARA rule file or directory
```

## Output Structure

Default output directory: `./pcaphunt_output/`

```text
pcaphunt_output/
├── plaintext/
├── base64/
├── hex/
├── url_encoded/
├── urls/
├── ip_addresses/
├── domains/
├── emails/
├── credentials/
├── flags/
├── hashes/
├── jwt/
├── files/
├── suspicious/
├── streams/
├── protocol_http/
├── protocol_dns/
├── protocol_ftp/
├── protocol_smtp/
├── protocol_irc/
├── protocol_dhcp/
├── extracted_files/
│   ├── 001_secret.png
│   ├── 001_secret.png.meta.json
│   ├── 003_document.pdf
│   └── ...
├── report.html
├── summary.txt
├── findings.json
├── full_result.json
├── profile.json
├── timeline.json
├── topology.json
├── yara_matches.json (when YARA enabled)
└── rules/
```

## JSON Output

When `--json` is used, the output is a **list of finding dictionaries** for backwards compatibility:

```json
[
  {
    "type": "flags",
    "packet_numbers": [100, 101],
    "first_seen_packet": 100,
    "protocol": "TCP",
    "source": "10.0.0.5:43122",
    "destination": "10.0.0.10:80",
    "stream_id": "tcp_10.0.0.5:43122->10.0.0.10:80",
    "offset": 42,
    "original": "CTF{this_is_a_flag}",
    "decoded": "CTF{this_is_a_flag}",
    "confidence": 1.0,
    "severity": "critical",
    "score": 88,
    "score_reasons": ["CTF flag pattern matched", "Severity marked as critical"],
    "score_factors": {"flag_detected": 80, "severity_critical": 15, "high_confidence": 8},
    "fingerprint": "..."
  }
]
```

The `full_result.json` file (always written to disk) contains the complete analysis result:

```json
{
  "findings": [...],
  "profile": {
    "pcap_name": "capture.pcap",
    "total_packets": 18421,
    "total_bytes": 2147483,
    "capture_duration_seconds": 872.5,
    "unique_ips_count": 12,
    "unique_macs_count": 4,
    "unique_ports_count": 47,
    "tcp_streams": 421,
    "udp_conversations": 38,
    "protocols": {"TCP": 15234, "UDP": 2100, "HTTP": 84, "DNS": 312},
    "http_requests": 84,
    "dns_queries": 312,
    "files_extracted": 12,
    "findings_count": 97,
    "flags_count": 3,
    "credentials_count": 4,
    "top_source_ips": [["10.0.0.1", 5234], ["192.168.1.10", 4121]],
    "top_ports": [[80, 84], [53, 312], [443, 45]],
    "top_protocols": [["TCP", 15234], ["UDP", 2100]]
  },
  "timeline": [
    {
      "event_type": "dns_query",
      "description": "DNS query: example.com",
      "timestamp": 1699123456.0,
      "packet_number": 5,
      "severity": "info"
    }
  ],
  "artifacts": [
    {
      "filename": "001_secret.png",
      "file_type": "image/png",
      "size": 12345,
      "source_ip": "10.0.0.1",
      "destination_ip": "10.0.0.2",
      "protocol": "HTTP",
      "complete": true,
      "md5": "abc...",
      "sha1": "def...",
      "sha256": "ghi..."
    }
  ],
  "network": {
    "nodes": [...],
    "edges": [...]
  },
  "yara": [...],
  "rules": [...]
}
```

Useful `jq` examples:

```bash
# All flags
jq '.[] | select(.type == "flags")' findings.json

# High-severity findings
jq '.[] | select(.severity == "high" or .severity == "critical")' findings.json

# Credentials
jq '.[] | select(.type == "credentials")' findings.json

# Profile statistics
jq '.profile' full_result.json

# Timeline events
jq '.timeline[] | select(.event_type == "http_request")' full_result.json

# Extracted file hashes
jq '.artifacts[] | {filename, sha256}' full_result.json
```

## HTML Report

PcapHunt generates a self-contained `report.html` by default. It requires no web server — simply open it in any modern browser.

The report is organized into tabs:

- **Overview** — PCAP profile summary, packet/duration stats, severity distribution, flag/credential/file counts
- **Findings** — Searchable, filterable, sortable table. Filter by category, severity, protocol. Sort by packet number, content, confidence, severity, or score. Click any row for a detail modal.
- **Files** — Extracted files with type, size, MD5, SHA256, source/destination, and completeness status
- **Timeline** — Chronological investigation events with timestamps, types, and descriptions
- **Network** — Communication topology: IP nodes (with packet/byte counts and suspicious markers) and edges (protocol, port, packet/byte counts)
- **Streams** — Reconstructed TCP/UDP streams with associated finding counts

### Security note

All untrusted PCAP-derived content is safely handled before insertion into HTML:

- Finding data is **base64-encoded JSON** embedded via `JSON.parse(atob(...))`
- Template variables are **HTML-escaped**
- No raw untrusted strings are inserted into the DOM
- Malicious payloads in a PCAP cannot execute JavaScript in the report

```bash
pcaphunt challenge.pcap
firefox ./pcaphunt_output/report.html
```

## Detection Categories

| Category | What it finds | Notes |
|----------|-------------|-------|
| `plaintext` | Printable ASCII/UTF-8 strings | Configurable minimum length |
| `base64` | Valid Base64 with meaningful decoded content | Supports recursive decode |
| `hex` | Hexadecimal strings with printable decoded output | Validates even length |
| `url_encoded` | Percent-encoded sequences | Supports recursive decoding |
| `urls` | `http://`, `https://`, `ftp://`, etc. | Extracts full URLs |
| `ip_addresses` | IPv4 and IPv6 addresses | Validates with `ipaddress` module |
| `domains` | Domain names | Filters fake TLDs and noise |
| `emails` | Email addresses | Simple structure validation |
| `credentials` | `password=`, `token=`, `api_key=`, etc. | Severity: high/medium |
| `flags` | `flag{...}`, `CTF{...}`, `HTB{...}`, etc. | Configurable regex patterns |
| `hashes` | MD5, SHA1, SHA256, SHA512 | Length and context heuristics |
| `jwt` | JSON Web Tokens | Decodes header and payload when valid |
| `files` | File magic bytes (PNG, PDF, ZIP, ELF, etc.) | Reports offset and type |
| `suspicious` | High-entropy data (compressed/encrypted) | Entropy threshold ≥ 7.5 |
| `protocol_http` | HTTP requests/responses | Method, path, headers, cookies, auth |
| `protocol_dns` | DNS queries/responses | Domains, answers, suspicious labels |
| `protocol_ftp` | FTP commands | USER, PASS, RETR, STOR |
| `protocol_smtp` | SMTP metadata | MAIL FROM, RCPT TO, AUTH, Subject |
| `protocol_irc` | IRC commands | NICK, JOIN, PRIVMSG |
| `protocol_dhcp` | DHCP metadata | Hostname, client MAC, requested IP |

## Deep Mode

Deep mode (`--deep`) enables:

- **TCP stream reassembly** — handles out-of-order segments, deduplicates retransmissions, respects sequence numbers, overlap resolution
- **UDP conversation reconstruction** — groups UDP packets into flows
- **Protocol-aware extraction** — HTTP, DNS, FTP, SMTP, IRC, DHCP metadata from reassembled streams
- **File extraction** — reconstructs files split across multiple packets
- **Additional decoding passes** — more aggressive recursive decoding
- **Deeper file signature analysis** — scans more aggressively for embedded files
- **Entropy analysis** — runs on all substantial payloads

Deep mode is slower but essential when flags or secrets are fragmented across multiple packets.

```bash
pcaphunt challenge.pcap --deep
```

## Deduplication

By default, PcapHunt deduplicates findings based on their **actual extracted content**, not the packet number. This means:

- If the same flag appears in packet 10, packet 25, and packet 100, only **one** result is saved
- The saved result records **all** packet numbers where it was found
- The **first seen packet** is preserved for reference
- `Hello World`, `Hello World!`, and `hello world` are still treated as different findings

Deduplication happens across the entire scan, including TCP stream reassembly and UDP conversation results. To disable it:

```bash
pcaphunt capture.pcap --no-dedup
```

## File Extraction

PcapHunt extracts files from network traffic using three complementary methods:

1. **Magic signature detection** — scans every payload for 20+ file format magic bytes
2. **HTTP body extraction** — parses HTTP responses, respects Content-Length and Content-Disposition
3. **Stream reassembly** — files split across TCP/UDP packets are reconstructed from reassembled streams

For each extracted file, PcapHunt records:
- Safe sanitized filename
- Detected MIME type
- Size in bytes
- Source and destination IP/port
- Protocol and stream ID
- First and last packet numbers
- Extraction method
- MD5, SHA1, SHA256 hashes
- Completeness status (with reason if incomplete)

Files are saved to `extracted_files/` with accompanying `.meta.json` metadata files.

```bash
pcaphunt capture.pcap --deep
# ./pcaphunt_output/extracted_files/
```

## Risk Scoring

PcapHunt assigns a heuristic risk score (0-100) to every finding with explanations:

| Score | Severity | Example triggers |
|-------|----------|-------------------|
| 80-100 | Critical | CTF flag, password, API key, private key, executable transfer |
| 60-79 | High | Bearer token, Basic auth, suspicious encoded payload |
| 40-59 | Medium | High-entropy payload, JWT, unusual port, suspicious DNS |
| 20-39 | Low | Encoded content, hash detected, suspicious file |
| 0-19 | Info | Plaintext, URL, domain, email, IP address |

Scores are **heuristic** and do not prove maliciousness. Each scored finding includes:
- Numeric score (0-100)
- Severity level (info, low, medium, high, critical)
- Human-readable reasons
- Contributing score factors

## Custom Rules

Create a YAML rules file:

```yaml
rules:
  - name: Internal API Key
    category: credential
    severity: high
    regex: "API_[A-Za-z0-9]{32}"
    description: "Detects an internal API key pattern"
    confidence: 0.95

  - name: Custom Flag
    category: flag
    severity: critical
    regex: "MYCTF\\{[^}]+\\}"
    description: "Detects custom CTF flags"

  - name: Interesting Domain
    category: suspicious-domain
    severity: medium
    regex: "secret\\.example\\.com"
    description: "Detects a known interesting domain"
    enabled: true
```

Run with:

```bash
pcaphunt challenge.pcap --rules rules.yaml
```

Rule fields:
- `name` (required) — human-readable rule name
- `category` (required) — output category (`rule_<category>`)
- `severity` (required) — info, low, medium, high, critical
- `regex` (required) — Python regex pattern
- `description` (optional) — human-readable description
- `confidence` (optional) — 0.0-1.0, default 1.0
- `enabled` (optional) — true/false, default true

Rules are validated before scanning. Invalid regexes produce clear error messages and the offending rule is skipped.

## YARA Integration

YARA support is **optional**. PcapHunt works without it.

```bash
# Install with YARA support
pip install "pcaphunt[yara]"

# Scan with YARA rules
pcaphunt challenge.pcap --yara /path/to/yara/rules/
```

YARA matches appear as `yara_match` findings with rule name, tags, and metadata. PcapHunt scans both extracted payloads and reconstructed files.

If YARA is requested but not installed, a clear installation message is shown.

## Plugin System

Create a plugin by subclassing `PcapHuntPlugin`:

```python
from pcaphunt.plugins import PcapHuntPlugin

class MyPlugin(PcapHuntPlugin):
    name = "my_plugin"
    version = "1.0.0"

    def process_packet(self, pkt_num, pkt, payload, context):
        # Return list of finding dicts
        findings = []
        if b"SECRET" in payload:
            findings.append({
                "type": "plugin_secret",
                "original": "SECRET keyword detected",
                "packet_numbers": [pkt_num],
                "first_seen_packet": pkt_num,
                "protocol": context.get("protocol", "Unknown"),
                "source": context.get("source", ""),
                "destination": context.get("destination", ""),
                "confidence": 0.8,
                "severity": "medium",
                "fingerprint": "secret_" + str(pkt_num),
            })
        return findings

    def process_stream(self, stream_id, reassembled, context):
        return []

    def finalize(self):
        return []
```

Register via `pyproject.toml` entry points:

```toml
[project.entry-points."pcaphunt.plugins"]
my_plugin = my_package.my_plugin:MyPlugin
```

Plugins are **trusted local code** installed by the user. See `examples/example_plugin.py` for a complete working example.

## Configuration

Create `~/.config/pcaphunt/config.toml`:

```toml
# PcapHunt Configuration File
# Place this file at ~/.config/pcaphunt/config.toml

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
output_directory = "./pcaphunt_output"

# Maximum recursive decode depth
max_decode_depth = 3

# Enable deduplication by default
deduplication = true

# Enable file extraction
extract_files = true

# Enable scoring, timeline, topology, profile
enable_scoring = true
enable_timeline = true
enable_topology = true
enable_profile = true
```

## Security

PcapHunt analyzes potentially malicious or untrusted network captures. The following precautions are taken:

- **Extracted files are never executed**
- **Decoded payloads are never executed**
- **No network connections are made based on extracted data**
- **No credentials are automatically used to authenticate anywhere**
- **Output paths are sanitized** to prevent path traversal (`../../etc/passwd` never becomes a write path)
- **HTML-escaping and base64 encoding** are used when embedding untrusted data into reports
- **Size and depth limits** are applied to prevent decompression bombs and excessive recursion
- **Plugins are treated as trusted local code** installed by the user

Users should still exercise caution:
- Run PcapHunt in an isolated environment when analyzing highly suspicious PCAPs
- Review extracted files manually before opening them in other applications
- Do not rely solely on risk scores to determine maliciousness — scores are heuristic, not proof

## Limitations

- **Encrypted traffic** — TLS/QUIC payloads remain opaque without decryption keys
- **Incomplete captures** — truncated PCAPs may prevent complete file reconstruction
- **Unsupported protocols** — proprietary or exotic protocols may only be analyzed as raw traffic
- **TCP reassembly** — works well for typical CTF traffic but is not a full TCP stack (no SACK, no complex window scaling)
- **UDP reconstruction** — simple concatenation; no sequence numbers mean request/response pairing is heuristic-based
- **Very large PCAPs** — multi-gigabyte captures require more processing time and resources; incremental reading keeps memory reasonable
- **File extraction** — uses heuristics for file bounds; some formats without explicit end markers may be truncated

## Development

```bash
git clone https://github.com/bel3ota/PcapHunt.git
cd PcapHunt
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run tests

```bash
python -m pytest tests/ -v
```

### Build and validate

```bash
rm -rf dist build *.egg-info
python -m build
python -m twine check dist/*
```

### Test the installed wheel

```bash
python -m venv /tmp/clean_venv
/tmp/clean_venv/bin/pip install dist/*.whl
/tmp/clean_venv/bin/pcaphunt --version
/tmp/clean_venv/bin/pcaphunt --help
```

## Release Process

Releases are automated via GitHub Actions using PyPI Trusted Publishing (OIDC). No PyPI API token is stored in the repository.

### One-time PyPI setup (repository owner)

1. Go to [PyPI](https://pypi.org/manage/account/publishing/)
2. Add a new Trusted Publisher:
   - **PyPI Project:** `pcaphunt`
   - **Owner:** `bel3ota`
   - **Repository:** `PcapHunt`
   - **Workflow name:** `release.yml`
   - **Environment:** `release`

### Creating a release

```bash
# Update version in pcaphunt/version.py and pyproject.toml
# Commit
# Create and push a tag
git tag v1.1.0
git push origin v1.1.0
```

GitHub Actions will:
1. Build the wheel and sdist
2. Validate with `twine check`
3. Verify the CLI entry point in a clean environment
4. Publish to PyPI via OIDC Trusted Publishing

**Normal pushes do NOT publish to PyPI.** Only version tags trigger releases.

### TestPyPI (manual)

For manual testing before an official release:

```bash
python -m build
python -m twine upload --repository testpypi dist/*
```

Note: package filenames/version numbers cannot be reused on PyPI or TestPyPI.

## Testing

PcapHunt includes a comprehensive pytest suite with synthetic PCAP fixtures. Tests cover:

- All detectors (plaintext, base64, hex, URL, IP, domain, email, credentials, flags, hashes, JWT, files, suspicious)
- Encoding chains (Base64, Base32, hex, URL, HTML entities, ROT13, gzip, zlib)
- TCP stream reconstruction (out-of-order, retransmissions, overlaps, FIN/RST)
- UDP conversation reconstruction
- Protocol extraction (HTTP, DNS, FTP, SMTP, IRC, DHCP)
- File extraction and magic signature detection
- File hashing (MD5, SHA1, SHA256)
- PCAP profiling
- Timeline generation
- Risk scoring
- Search and filtering
- Network topology
- Custom rules (valid, invalid, matching, non-matching)
- Plugin system (discovery, execution, findings)
- YARA integration (optional dependency behavior)
- HTML report generation with XSS safety
- CLI argument parsing and backwards compatibility
- Packaging and console script validation

All tests use small synthetic PCAPs created in-memory with Scapy — no external files required.

## License

MIT License — see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding guidelines, and the pull request process.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and vulnerability reporting process.
