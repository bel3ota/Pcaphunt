"""Tests for enhanced encoding chains and utilities."""

import base64
import gzip
import zlib

from pcaphunt.utils import (
    decompress_payload,
    recursive_decode,
)


class TestRecursiveDecode:
    def test_url_then_base64(self):
        import urllib.parse
        inner = base64.b64encode(b">>>>>>>>>>>").decode()
        outer = urllib.parse.quote(inner, safe="")
        steps = recursive_decode(outer, max_depth=3)
        assert len(steps) >= 2
        assert steps[-1]["result"] == ">>>>>>>>>>>"

    def test_base64_then_hex(self):
        inner = "48656c6c6f20435446"  # "Hello CTF"
        outer = base64.b64encode(inner.encode()).decode()
        steps = recursive_decode(outer, max_depth=3)
        assert len(steps) >= 2
        assert steps[-1]["result"] == "Hello CTF"

    def test_html_entities(self):
        data = "flag&amp;#123;test&amp;#125;"  # HTML entity encoded flag{test}
        steps = recursive_decode(data, max_depth=3)
        assert len(steps) >= 1
        assert any("flag" in step["result"] for step in steps)

    def test_base32_decode(self):
        import base64
        inner = b"Hello CTF"
        outer = base64.b32encode(inner).decode()
        steps = recursive_decode(outer, max_depth=3)
        assert len(steps) >= 1
        assert steps[0]["method"] == "Base32"
        assert steps[0]["result"] == "Hello CTF"

    def test_rot13_decode(self):
        data = "uryybjbeyq"  # ROT13 of "helloworld"
        steps = recursive_decode(data, max_depth=3)
        assert len(steps) >= 1
        assert steps[0]["method"] == "ROT13"
        assert steps[0]["result"] == "helloworld"

    def test_does_not_rot13_plaintext(self):
        data = "Hello World"
        steps = recursive_decode(data, max_depth=3)
        # Should not apply ROT13 to normal English text
        assert len(steps) == 0

    def test_does_not_rot13_special_chars(self):
        data = "flag{test}"
        steps = recursive_decode(data, max_depth=3)
        assert len(steps) == 0


class TestDecompression:
    def test_gzip_decompression(self):
        original = b"CTF{gzip_compressed_flag}"
        compressed = gzip.compress(original)
        result, method = decompress_payload(compressed)
        assert result == original
        assert method == "gzip"

    def test_zlib_decompression(self):
        original = b"CTF{zlib_compressed_flag}"
        compressed = zlib.compress(original)
        result, method = decompress_payload(compressed)
        assert result == original
        assert method == "zlib"

    def test_no_compression(self):
        data = b"not compressed at all"
        result, method = decompress_payload(data)
        assert result is None
        assert method == ""
