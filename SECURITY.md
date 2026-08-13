# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in PcapHunt, please report it responsibly.

**Do not** open a public GitHub issue for security vulnerabilities.

Instead, please email the maintainer directly:

- **Email:** a.talbi@esi-sba.dz
- **Subject:** `[PcapHunt Security] <brief description>`

Please include the following information:

1. A description of the vulnerability
2. Steps to reproduce (if applicable)
3. The version of PcapHunt affected
4. Any potential impact assessment

You can expect an initial response within **5 business days**.

If the vulnerability is confirmed, we will work to develop and release a fix as quickly as possible. We will coordinate disclosure with you to ensure the issue is properly patched before public disclosure.

## Security Considerations

PcapHunt is designed to analyze potentially malicious or untrusted network captures. The tool takes the following precautions:

- Extracted files are **never executed**
- Decoded payloads are **never executed**
- No network connections are made based on extracted data
- No credentials are automatically used to authenticate anywhere
- Output paths are sanitized to prevent path traversal
- HTML-escaping and base64 encoding are used when embedding untrusted data into reports
- Plugins are treated as **trusted local code** installed by the user

However, users should still exercise caution:

- Run PcapHunt in an isolated environment when analyzing highly suspicious PCAPs
- Review extracted files manually before opening them in other applications
- Be aware that decompression of crafted payloads could consume significant memory

## Known Limitations

- PcapHunt does not perform sandboxed analysis of extracted files
- High-entropy payloads may indicate encryption or compression but are not decrypted automatically
- TLS/encrypted traffic remains opaque without decryption keys
