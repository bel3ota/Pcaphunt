"""HTTP protocol extractor for PcapHunt."""

import re
from typing import Any


def extract_http(data: bytes) -> list[dict[str, Any]]:
    """Extract HTTP-related findings from raw bytes.

    Args:
        data: Raw payload bytes.

    Returns:
        List of finding-like dictionaries.
    """
    results: list[dict[str, Any]] = []
    if not data or len(data) < 10:
        return results

    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        return results

    # HTTP request line
    req_match = re.search(
        r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP",
        text,
        re.MULTILINE | re.IGNORECASE,
    )
    if req_match:
        method = req_match.group(1)
        path = req_match.group(2)
        results.append({
            "type": "protocol_http",
            "original": f"{method} {path}",
            "decoded": None,
            "offset": req_match.start(),
            "confidence": 0.98,
            "severity": "info",
            "metadata": {
                "http_method": method,
                "http_path": path,
            },
        })

    # Host header
    host_match = re.search(r"[\r\n]Host:\s*([^\r\n]+)", text, re.IGNORECASE)
    if host_match:
        host = host_match.group(1).strip()
        results.append({
            "type": "protocol_http",
            "original": f"Host: {host}",
            "decoded": None,
            "offset": host_match.start(),
            "confidence": 0.95,
            "severity": "info",
            "metadata": {"http_host": host},
        })

    # Cookie header
    cookie_match = re.search(r"[\r\n]Cookie:\s*([^\r\n]+)", text, re.IGNORECASE)
    if cookie_match:
        cookie = cookie_match.group(1).strip()
        results.append({
            "type": "protocol_http",
            "original": f"Cookie: {cookie}",
            "decoded": None,
            "offset": cookie_match.start(),
            "confidence": 0.92,
            "severity": "medium",
            "metadata": {"http_cookie": cookie},
        })

    # Authorization header
    auth_match = re.search(
        r"[\r\n]Authorization:\s*([^\r\n]+)", text, re.IGNORECASE
    )
    if auth_match:
        auth = auth_match.group(1).strip()
        results.append({
            "type": "protocol_http",
            "original": f"Authorization: {auth}",
            "decoded": None,
            "offset": auth_match.start(),
            "confidence": 0.97,
            "severity": "high",
            "metadata": {"http_authorization": auth},
        })

    # User-Agent
    ua_match = re.search(r"[\r\n]User-Agent:\s*([^\r\n]+)", text, re.IGNORECASE)
    if ua_match:
        ua = ua_match.group(1).strip()
        results.append({
            "type": "protocol_http",
            "original": f"User-Agent: {ua}",
            "decoded": None,
            "offset": ua_match.start(),
            "confidence": 0.94,
            "severity": "info",
            "metadata": {"http_user_agent": ua},
        })

    # Status code
    status_match = re.search(
        r"HTTP/\d\.\d\s+(\d{3})\s+([^\r\n]*)", text, re.IGNORECASE
    )
    if status_match:
        code = status_match.group(1)
        msg = status_match.group(2).strip()
        results.append({
            "type": "protocol_http",
            "original": f"HTTP {code} {msg}",
            "decoded": None,
            "offset": status_match.start(),
            "confidence": 0.98,
            "severity": "info",
            "metadata": {
                "http_status_code": code,
                "http_status_message": msg,
            },
        })

    # Query parameters from URLs
    if req_match and "?" in path:
        query = path.split("?", 1)[1]
        for param in query.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                if k.lower() in (
                    "password", "pass", "token", "api_key", "apikey",
                    "secret", "key", "auth",
                ):
                    results.append({
                        "type": "protocol_http",
                        "original": f"Query: {k}={v}",
                        "decoded": None,
                        "offset": req_match.start(),
                        "confidence": 0.90,
                        "severity": "high",
                        "metadata": {"http_query_param": k, "http_query_value": v},
                    })

    return results
