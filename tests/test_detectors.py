"""Tests for PcapHunt detectors."""

import pytest

from pcaphunt.detectors.base64 import Base64Detector
from pcaphunt.detectors.credentials import CredentialsDetector
from pcaphunt.detectors.domains import DomainDetector
from pcaphunt.detectors.emails import EmailDetector
from pcaphunt.detectors.files import FileDetector
from pcaphunt.detectors.flags import FlagDetector
from pcaphunt.detectors.hashes import HashDetector
from pcaphunt.detectors.hex import HexDetector
from pcaphunt.detectors.ip_addresses import IPAddressDetector
from pcaphunt.detectors.jwt import JWTDetector
from pcaphunt.detectors.plaintext import PlaintextDetector
from pcaphunt.detectors.suspicious import SuspiciousDetector
from pcaphunt.detectors.url_encoded import URLEncodedDetector
from pcaphunt.detectors.urls import URLDetector
from pcaphunt.utils import recursive_decode


class TestPlaintextDetector:
    def test_detects_ascii(self):
        detector = PlaintextDetector({"min_length": 6})
        data = b"Hello world, this is a test message"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("Hello world" in str(f.get("original", "")) for f in findings)

    def test_respects_min_length(self):
        detector = PlaintextDetector({"min_length": 20})
        data = b"Short\nThis is a much longer string here"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        texts = [f["original"] for f in findings]
        assert "Short" not in texts
        assert any("much longer string" in t for t in texts)


class TestBase64Detector:
    def test_detects_valid_base64(self):
        import base64
        detector = Base64Detector({})
        original = b"Base64 test data"
        encoded = base64.b64encode(original)
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(encoded, ctx)
        assert len(findings) > 0
        assert any(f.get("decoded") == "Base64 test data" for f in findings)

    def test_rejects_invalid(self):
        detector = Base64Detector({})
        data = b"NotBase64!!!"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) == 0


class TestHexDetector:
    def test_detects_hex(self):
        detector = HexDetector({})
        data = b"48656c6c6f205446"  # "Hello TF"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("Hello TF" in str(f.get("decoded", "")) for f in findings)

    def test_rejects_odd_length(self):
        detector = HexDetector({})
        data = b"48656c6c6f20546"  # odd length
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        # Should not decode odd length hex
        assert not any("Hello" in str(f.get("decoded", "")) for f in findings)


class TestURLEncodedDetector:
    def test_detects_url_encoded(self):
        detector = URLEncodedDetector({})
        data = b"%66%6c%61%67%7B%74%65%73%74%7D"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("flag{test}" in str(f.get("decoded", "")) for f in findings)

    def test_detects_mixed(self):
        detector = URLEncodedDetector({})
        data = b"hello%20world%21"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("hello world!" in str(f.get("decoded", "")) for f in findings)


class TestURLDetector:
    def test_detects_http(self):
        detector = URLDetector({})
        data = b"Check out http://example.com/path"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("http://example.com/path" in str(f.get("original", "")) for f in findings)

    def test_detects_https(self):
        detector = URLDetector({})
        data = b"Visit https://secure.example.com/login"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0


class TestIPAddressDetector:
    def test_detects_ipv4(self):
        detector = IPAddressDetector({})
        data = b"Server at 192.168.1.1 is live"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("192.168.1.1" in str(f.get("original", "")) for f in findings)


class TestDomainDetector:
    def test_detects_domains(self):
        detector = DomainDetector({})
        data = b"Host: www.example.com"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("www.example.com" in str(f.get("original", "")) for f in findings)

    def test_rejects_fake_tlds(self):
        detector = DomainDetector({})
        data = b"file.exe or data.pdf"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert not any("file.exe" in str(f.get("original", "")) for f in findings)


class TestEmailDetector:
    def test_detects_emails(self):
        detector = EmailDetector({})
        data = b"Contact user@example.com please"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("user@example.com" in str(f.get("original", "")) for f in findings)


class TestCredentialsDetector:
    def test_detects_password(self):
        detector = CredentialsDetector({})
        data = b"password=secret123"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("secret123" in str(f.get("original", "")) for f in findings)

    def test_detects_json_creds(self):
        detector = CredentialsDetector({})
        data = b'{"username": "admin", "password": "p@ssw0rd"}'
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0


class TestFlagDetector:
    def test_detects_flags(self):
        detector = FlagDetector({})
        data = b"The flag is CTF{found_it} here"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("CTF{found_it}" in str(f.get("original", "")) for f in findings)

    def test_detects_custom_pattern(self):
        detector = FlagDetector({"flag_patterns": [r"CUSTOM\{[^}]+\}"]})
        data = b"Here is CUSTOM{my_flag}"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("CUSTOM{my_flag}" in str(f.get("original", "")) for f in findings)


class TestHashDetector:
    def test_detects_md5(self):
        detector = HashDetector({})
        data = b"hash: 5f4dcc3b5aa765d61d8327deb882cf99"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("MD5" in str(f.get("notes", "")) for f in findings)

    def test_detects_sha256(self):
        detector = HashDetector({})
        data = b"sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("SHA256" in str(f.get("notes", "")) for f in findings)


class TestJWTDetector:
    def test_detects_jwt(self):
        import base64
        import json
        detector = JWTDetector({})
        header = base64.b64encode(json.dumps({"alg":"HS256","typ":"JWT"}).encode()).decode().rstrip("=")
        payload = base64.b64encode(json.dumps({"sub":"123"}).encode()).decode().rstrip("=")
        token = f"{header}.{payload}.signature12345"
        data = token.encode()
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("HS256" in str(f.get("decoded", "")) for f in findings)


class TestFileDetector:
    def test_detects_png(self):
        detector = FileDetector({})
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("PNG" in str(f.get("file_type", "")) for f in findings)

    def test_detects_pdf(self):
        detector = FileDetector({})
        data = b"%PDF-1.4" + b"\x00" * 30
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert any("PDF" in str(f.get("file_type", "")) for f in findings)


class TestSuspiciousDetector:
    def test_detects_high_entropy(self):
        import random
        detector = SuspiciousDetector({})
        random.seed(42)
        data = bytes(random.randint(0, 255) for _ in range(500))
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) > 0
        assert all(f.get("entropy", 0) > 7.0 for f in findings)

    def test_skips_short_data(self):
        detector = SuspiciousDetector({})
        data = b"\x00" * 30
        ctx = {"packet_numbers": [1], "protocol": "TCP", "source": "", "destination": ""}
        findings = detector.detect(data, ctx)
        assert len(findings) == 0


class TestRecursiveDecode:
    def test_url_then_base64(self):
        import base64
        import urllib.parse
        # Use a string that produces + or = in base64 so URL encoding actually encodes something
        inner = base64.b64encode(b">>>>>>>>>>").decode()
        outer = urllib.parse.quote(inner, safe="")
        steps = recursive_decode(outer, max_depth=3)
        assert len(steps) >= 2
        assert steps[-1]["result"] == ">>>>>>>>>>"

    def test_base64_then_hex(self):
        import base64
        inner = "48656c6c6f20435446"  # "Hello CTF"
        outer = base64.b64encode(inner.encode()).decode()
        steps = recursive_decode(outer, max_depth=3)
        assert len(steps) >= 2
        assert steps[-1]["result"] == "Hello CTF"
