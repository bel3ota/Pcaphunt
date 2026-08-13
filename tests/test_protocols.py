"""Tests for protocol-aware extraction."""

import pytest

from pcaphunt.protocols.dhcp import extract_dhcp
from pcaphunt.protocols.dns import extract_dns
from pcaphunt.protocols.ftp import extract_ftp
from pcaphunt.protocols.http import extract_http
from pcaphunt.protocols.irc import extract_irc
from pcaphunt.protocols.smtp import extract_smtp


class TestHTTPExtractor:
    def test_extracts_get_request(self):
        data = b"GET /secret.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"
        results = extract_http(data)
        assert any("GET /secret.txt" in r["original"] for r in results)

    def test_extracts_host_header(self):
        data = b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
        results = extract_http(data)
        assert any("api.example.com" in r["original"] for r in results)

    def test_extracts_cookie(self):
        data = b"GET / HTTP/1.1\r\nCookie: session=abc123\r\n\r\n"
        results = extract_http(data)
        assert any("session=abc123" in r["original"] for r in results)
        assert any(r.get("severity") == "medium" for r in results)

    def test_extracts_authorization(self):
        data = b"GET / HTTP/1.1\r\nAuthorization: Bearer eyJtoken\r\n\r\n"
        results = extract_http(data)
        assert any("Bearer eyJtoken" in r["original"] for r in results)
        assert any(r.get("severity") == "high" for r in results)

    def test_extracts_status_code(self):
        data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        results = extract_http(data)
        assert any("HTTP 200 OK" in r["original"] for r in results)

    def test_extracts_query_params_with_secrets(self):
        data = b"GET /api?password=secret123&token=abc HTTP/1.1\r\n\r\n"
        results = extract_http(data)
        assert any("password=secret123" in r["original"] for r in results)


class TestDNSExtractor:
    def test_no_dns_layer(self):
        from scapy.all import IP, UDP, Raw
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=53) / Raw(b"fake")
        results = extract_dns(pkt)
        assert len(results) == 0

    def test_extracts_dns_query(self):
        from scapy.all import IP, UDP, DNS, DNSQR
        pkt = (
            IP(src="10.0.0.1", dst="10.0.0.2")
            / UDP(sport=12345, dport=53)
            / DNS(qd=DNSQR(qname=b"example.com"), qdcount=1)
        )
        results = extract_dns(pkt)
        assert len(results) > 0
        assert any("example.com" in r["original"] for r in results)


class TestFTPExtractor:
    def test_extracts_user(self):
        data = b"USER alice\r\n"
        results = extract_ftp(data)
        assert any("alice" in r["original"] for r in results)

    def test_extracts_pass(self):
        data = b"PASS secret123\r\n"
        results = extract_ftp(data)
        assert any("secret123" in r["original"] for r in results)
        assert any(r.get("severity") == "high" for r in results)

    def test_extracts_retr(self):
        data = b"RETR flag.txt\r\n"
        results = extract_ftp(data)
        assert any("flag.txt" in r["original"] for r in results)


class TestSMTPExtractor:
    def test_extracts_mail_from(self):
        data = b"MAIL FROM:<alice@example.com>\r\n"
        results = extract_smtp(data)
        assert any("alice@example.com" in r["original"] for r in results)

    def test_extracts_auth(self):
        data = b"AUTH LOGIN dXNlcg==\r\n"
        results = extract_smtp(data)
        assert any("LOGIN dXNlcg==" in r["original"] for r in results)
        assert any(r.get("severity") == "high" for r in results)

    def test_extracts_subject(self):
        data = b"Subject: Secret Flag\r\n"
        results = extract_smtp(data)
        assert any("Secret Flag" in r["original"] for r in results)


class TestIRCExtractor:
    def test_extracts_nick(self):
        data = b"NICK CTFPlayer\r\n"
        results = extract_irc(data)
        assert any("CTFPlayer" in r["original"] for r in results)

    def test_extracts_join(self):
        data = b"JOIN #ctf\r\n"
        results = extract_irc(data)
        assert any("#ctf" in r["original"] for r in results)

    def test_extracts_privmsg(self):
        data = b"PRIVMSG #ctf :flag{irc_flag}\r\n"
        results = extract_irc(data)
        assert any("flag{irc_flag}" in r["original"] for r in results)


class TestDhcpExtractor:
    def test_extracts_hostname(self):
        data = b"\x00hostname=DESKTOP-CTF\x00"
        results = extract_dhcp(data)
        assert any("DESKTOP-CTF" in r["original"] for r in results)

    def test_extracts_client_mac(self):
        data = b"\x00client_mac=aa:bb:cc:dd:ee:ff\x00"
        results = extract_dhcp(data)
        assert any("aa:bb:cc:dd:ee:ff" in r["original"] for r in results)
