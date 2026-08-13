# PcapHunt

**PcapHunt** is a complete, production-quality CLI tool for CTF players and network-forensics analysts. It hunts through `.pcap` / `.pcapng` files packet-by-packet and automatically extracts useful human-readable or encoded data — dramatically reducing the need to manually inspect thousands of packets in Wireshark.

## Why PcapHunt?

During CTFs and incident-response investigations, PCAP files often contain thousands of packets. Manually scrolling through them in Wireshark is time-consuming and error-prone. PcapHunt performs a **rapid first-pass triage**, extracting:

- plaintext strings
- Base64, hex, and URL-encoded data
- URLs, domains, IP addresses, emails
- credentials and tokens
- CTF flags
- hashes and JWTs
- embedded file signatures (PNG, PDF, ZIP, etc.)
- suspicious high-entropy blobs

It associates every finding with specific packet numbers, reconstructs TCP streams in deep mode, deduplicates repeated content so you get clean, actionable output, and generates a searchable HTML report for easy inspection.

## Features

- **14 modular detectors** covering the most common CTF/forensics data types
- **Content-based deduplication** — identical findings across different packets are merged, not duplicated
- **TCP stream reassembly** (`--deep`) to catch flags split across packets
- **Self-contained HTML report** with search, filter, sort, and detail view
- **Recursive decoding** (Base64 → hex → plaintext, etc.)
- **Deduplication** prevents hundreds of identical files
- **Rich terminal UI** with progress bars and color-coded results
- **JSON output** (`--json`) for programmatic consumption
- **Search filtering** (`--search`) to narrow results
- **Configurable** via `~/.config/pcaphunt/config.toml`
- **Graceful error handling** — malformed packets never crash the tool
- **Fast** — works incrementally without loading the entire PCAP into memory

## Installation

### From source (recommended for development)

```bash
git clone <repo-url>
cd pcaphunt
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### System install with pipx

```bash
pipx install pcaphunt
```

### Requirements

- Python 3.11+
- `scapy` (PCAP parsing)
- `rich` (terminal UI)

## Usage

### Basic scan

```bash
pcaphunt capture.pcap
```

### Deep mode (TCP stream reassembly)

```bash
pcaphunt capture.pcap --deep
```

### Specify output directory

```bash
pcaphunt capture.pcap -o ./results
```

### JSON output to stdout

```bash
pcaphunt capture.pcap --json
```

### Search for a specific string

```bash
pcaphunt capture.pcap --search "flag"
```

### Disable HTML report

```bash
pcaphunt capture.pcap --no-html
```

### Disable deduplication

```bash
pcaphunt capture.pcap --no-dedup
```

### Full CLI reference

```text
$ pcaphunt --help
usage: pcaphunt [-h] [-o OUTPUT] [--deep] [--min-length MIN_LENGTH]
                [--no-dedup] [--json] [--quiet] [--search SEARCH] [--version]
                [--html] [--no-html]
                [pcap]

PcapHunt - Hunt for useful data in PCAP/PCAPNG files

positional arguments:
  pcap                  Path to PCAP/PCAPNG file

options:
  -h, --help            show this help message and exit
  -o, --output OUTPUT   Output directory (default: ./pcaphunt_output)
  --deep                Enable deep mode (TCP stream reassembly, etc.)
  --min-length MIN_LENGTH
                        Minimum plaintext string length (default: 6)
  --no-dedup            Disable deduplication
  --json                Output findings as JSON to stdout
  --quiet               Suppress terminal output
  --search SEARCH       Filter findings by search string
  --version             Show version and exit
  --html                Generate HTML report (default: enabled)
  --no-html             Disable HTML report generation
```

Also runnable without installation:

```bash
python -m pcaphunt capture.pcap
```

## Examples

### Example 1: Basic scan

```bash
$ pcaphunt challenge.pcap

 ____   ____          _   _             _
|  _ \ / ___|__ _ ___| | | |  _   _ _ __ | |_
| |_) | |   / _` / __| |_| | | | | | '_ \| __|
|  __/| |__| (_| \__ \  _  | | |_| | | | | |_
|_|    \____\__,_|___/_| |_|  \__,_|_| |_|\__|

             PCAP Content Hunter

[*] Input: challenge.pcap
[*] Packets: 18,421

[+] Analyzing packets... 100%

────────────────────────────────────────────
              PCAPHUNT RESULTS
────────────────────────────────────────────

  Plaintext       1,284
  Base64             37
  Hex                19
  Url Encoded        11
  URLs               43
  IP Addresses      112
  Domains            28
  Emails              6
  Credentials         4
  Flags               2
  Hashes             13
  JWT                 1
  Files               7
  Suspicious          8

────────────────────────────────────────────

🏁 FLAGS FOUND:
  flag{hidden_in_stream}
  CTF{reconstructed_flag}

🔒 Credentials detected: 4
  (saved to output/credentials/)

[+] Results: ./pcaphunt_output/
[+] HTML report: ./pcaphunt_output/report.html
[+] Analysis completed in 4.82 seconds
```

### Example 2: Deep mode

```bash
$ pcaphunt challenge.pcap --deep -o ./deep_results
```

Deep mode enables TCP stream reassembly, allowing PcapHunt to detect strings split across multiple packets.

### Example 3: JSON output

```bash
$ pcaphunt challenge.pcap --json --quiet | jq '.[] | select(.type == "flags")'

{
  "type": "flags",
  "packet_numbers": [100, 101],
  "first_seen_packet": 100,
  "protocol": "TCP",
  "source": "10.0.0.5:43122",
  "destination": "10.0.0.10:80",
  "offset": 42,
  "original": "CTF{this_is_a_flag}",
  "decoded": "CTF{this_is_a_flag}",
  "confidence": 1.0,
  "fingerprint": "..."
}
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
├── summary.txt
├── findings.json
└── report.html
```

Each finding is saved as a human-readable `.txt` file:

```text
PcapHunt Finding
================

Type: Base64
Packet: 81
First Seen: Packet 81
Protocol: TCP
Source: 10.0.0.5:43122
Destination: 10.0.0.10:80
Offset: 42
Confidence: 0.98

Original:
SGVsbG8gQ1RG

Decoded:
Hello CTF
```

If multiple findings exist in one packet, files are numbered:

```text
packet_12_01.txt
packet_12_02.txt
```

## HTML Report

PcapHunt generates a self-contained `report.html` by default. It requires no web server — simply open it in any modern browser.

The report includes:

- **Header** with PCAP filename, scan date/time, duration, and total findings
- **Statistics dashboard** showing counts for each detector category
- **Searchable, filterable, and sortable findings table** with:
  - Category/type badges
  - Extracted content (with truncation for very long values)
  - Packet numbers and first-seen packet
  - Source/destination IPs and ports
  - Protocol
  - Confidence score
- **Clickable detail modal** for inspecting any finding without cluttering the main table
- **Client-side search** across all content
- **Category filtering** dropdown
- **Sorting** by packet number, category, content, or confidence

All extracted data is safely encoded before insertion. Malicious payloads in a PCAP cannot execute JavaScript in the report.

### Opening the report

```bash
pcaphunt challenge.pcap
# Then open in your browser:
firefox ./pcaphunt_output/report.html
# or
chrome ./pcaphunt_output/report.html
```

## Detector Explanations

| Detector | What it finds | Notes |
|----------|-------------|-------|
| `plaintext` | Printable ASCII/UTF-8 strings | Configurable minimum length |
| `base64` | Valid Base64 with meaningful decoded content | Uses padding, alphabet, and content heuristics |
| `hex` | Hexadecimal strings with printable decoded output | Validates even length and printable result |
| `url_encoded` | Percent-encoded sequences | Supports recursive decoding |
| `urls` | `http://`, `https://`, `ftp://`, etc. | Extracts full URLs |
| `ip_addresses` | IPv4 and IPv6 addresses | Validates with Python's `ipaddress` module |
| `domains` | Domain names | Filters fake TLDs and noise |
| `emails` | Email addresses | Simple structure validation |
| `credentials` | `password=`, `token=`, `api_key=`, etc. | Values saved to `credentials/` only |
| `flags` | `flag{...}`, `CTF{...}`, `HTB{...}`, etc. | Configurable regex patterns |
| `hashes` | MD5, SHA1, SHA256, SHA512 | Uses length and context heuristics |
| `jwt` | JSON Web Tokens | Decodes header and payload when valid |
| `files` | File magic bytes (PNG, PDF, ZIP, etc.) | Reports offset and type |
| `suspicious` | High-entropy data (compressed/encrypted) | Entropy threshold ≥ 7.5 |

## Deep Mode

Deep mode (`--deep`) enables:

- **TCP stream reassembly** — concatenates payloads from the same TCP stream to find strings split across packets
- **Additional decoding passes** — more aggressive recursive decoding
- **Deeper file signature analysis** — scans more aggressively for embedded files
- **Entropy analysis** — runs on all substantial payloads

Deep mode is slower but essential when flags or secrets are fragmented across multiple packets.

### Example: split flag

Packet 100: `CTF{this_is_`
Packet 101: `a_flag}`

Without `--deep`: no flag found.
With `--deep`: `CTF{this_is_a_flag}` detected and associated with packets 100–101.

## Deduplication

By default, PcapHunt deduplicates findings based on their **actual extracted content**, not the packet number. This means:

- If the same flag appears in packet 10, packet 25, and packet 100, only **one** result is saved
- The saved result records **all** packet numbers where it was found
- The **first seen packet** is preserved for reference
- `Hello World`, `Hello World!`, and `hello world` are still treated as different findings

Deduplication happens across the entire scan, including TCP stream reassembly results. To disable it and see every raw detection:

```bash
pcaphunt capture.pcap --no-dedup
```

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

# Enable deep mode by default
deep_mode_default = false
```

## Development

```bash
# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run specific test
pytest tests/test_integration.py -v
```

## Testing

PcapHunt includes a comprehensive pytest suite with synthetic PCAP fixtures. Tests cover:

- plaintext, Base64, hex, URL-encoded extraction
- URL, IP, domain, email detection
- flag, hash, JWT, file-signature detection
- entropy calculation
- deduplication logic (same content in multiple packets, cross-stream dedup, `--no-dedup`)
- recursive decoding
- malformed packet handling
- TCP stream reconstruction (including split-flag detection)
- output generation (TXT, JSON, HTML)
- HTML report generation, search/filter, XSS-safe escaping
- CLI argument parsing

All tests use small synthetic PCAPs created in-memory with Scapy — no external files required.

## Limitations

- **Protocol parsing**: Uses Scapy heuristics; exotic or heavily fragmented protocols may not be perfectly parsed
- **TCP reassembly**: Simple concatenation (no out-of-order or gap handling). Works well for typical CTF traffic but not a full TCP stack
- **File extraction**: Detects signatures and reports offsets but does not always extract complete files when data is truncated
- **Encrypted traffic**: TLS payloads are opaque unless decrypted with keys (not supported)
- **Performance**: Very large PCAPs (>1 GB) will take longer; incremental reading keeps memory usage reasonable

## License

MIT License — see [LICENSE](LICENSE).

## Contributing

Contributions welcome! Areas of interest:

- Additional detectors (e.g., QR codes, steganography hints)
- Better protocol parsers (SMB, HTTP/2, QUIC)
- GUI or web viewer for results
- Performance optimizations for massive PCAPs
