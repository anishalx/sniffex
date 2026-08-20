#!/usr/bin/env python3
"""
SniffEx — real-time HTTP packet sniffer (Advanced).

Captures network traffic and extracts HTTP requests, URLs and potential
credentials (query strings, form bodies, JSON payloads, Basic Auth, Bearer
tokens and cookies). Output can be streamed to the console, appended to a
JSON Lines log file and written to a pcap capture file.

Quick start:
    sudo python3 sniffex.py -i eth0                 # sniff an interface
    python3 sniffex.py --list-interfaces            # show available interfaces
    sudo python3 sniffex.py -i eth0 --json log.jsonl --pcap cap.pcap \\
        --host example.com --keyword login

DISCLAIMER: Use SniffEx only on networks you own or have explicit written
permission to test. Unauthorized traffic interception is illegal in most
jurisdictions. The author is not responsible for any misuse.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import logging
import os
import re
import signal
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.tls.handshake import TLSClientHello
from scapy.utils import PcapWriter

try:
    from scapy.layers import http as _http

    HTTPRequest = _http.HTTPRequest
    HTTPResponse = _http.HTTPResponse
except (ImportError, AttributeError):  # pragma: no cover - old scapy without http layer
    HTTPRequest = None
    HTTPResponse = None

# TOML config support (Python 3.11+ has built-in tomllib)
try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

VERSION = "3.0.0"
PROG = "sniffex"
BANNER_TAGLINE = "---- Real-time HTTP Packet Sniffer (Advanced) ----"

# Columns for the findings CSV output (one row per credential finding).
CSV_FIELDNAMES = ["ts", "method", "url", "host", "src", "dst", "kind", "fields", "raw"]

DISCLAIMER = (
    "DISCLAIMER:\n"
    "Unauthorized use of this tool to sniff traffic or manipulate networks\n"
    "without explicit permission from the target is illegal. The developer\n"
    "is not responsible for any misuse or illegal activities."
)

# Logging setup
logger = logging.getLogger("sniffex")


# ---------------------------------------------------------------------------
# ANSI colors
# ---------------------------------------------------------------------------

class Colors:
    """ANSI color codes used for console output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _decode(value, errors: str = "replace") -> str:
    """Decode bytes (or pass through str) into text without crashing."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors=errors)
    if value is None:
        return ""
    return str(value)


def colorize(text: str, code: str, enabled: bool = True) -> str:
    return f"{code}{text}{Colors.RESET}" if enabled else text


def _endpoint(packet, dst: bool) -> str:
    """Return 'ip:port' of the source (dst=False) or destination of a packet."""
    try:
        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP].dst if dst else packet[scapy.IP].src
        elif packet.haslayer(scapy.IPv6):
            ip = packet[scapy.IPv6].dst if dst else packet[scapy.IPv6].src
        else:
            return ""
        if packet.haslayer(scapy.TCP):
            port = packet[scapy.TCP].dport if dst else packet[scapy.TCP].sport
            return f"{ip}:{port}"
        return ip
    except Exception:
        return ""


def _ip_only(packet, dst: bool) -> str:
    """Return just the IP address."""
    try:
        if packet.haslayer(scapy.IP):
            return packet[scapy.IP].dst if dst else packet[scapy.IP].src
        elif packet.haslayer(scapy.IPv6):
            return packet[scapy.IPv6].dst if dst else packet[scapy.IPv6].src
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# TOML config loading
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    """Load a TOML configuration file and return its contents."""
    if tomllib is None:
        logger.warning("toml support unavailable (install tomli for Python <3.11)")
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception as exc:
        logger.error("Failed to load config %s: %s", path, exc)
        return {}


def _apply_config(args: argparse.Namespace, config: dict) -> argparse.Namespace:
    """Apply TOML config values to argparse namespace (CLI args take precedence)."""
    sniffer_cfg = config.get("sniffer", {})
    output_cfg = config.get("output", {})
    filter_cfg = config.get("filters", {})
    alert_cfg = config.get("alerts", {})

    def _set_if_unset(dest, key, value):
        if getattr(args, key, None) in (None, [], False):
            setattr(args, key, value)

    # sniffer section
    _set_if_unset(args, "interface", sniffer_cfg.get("interface"))
    _set_if_unset(args, "bpf", sniffer_cfg.get("bpf"))
    _set_if_unset(args, "count", sniffer_cfg.get("count"))
    _set_if_unset(args, "timeout", sniffer_cfg.get("timeout"))
    _set_if_unset(args, "quiet", sniffer_cfg.get("quiet", False))
    _set_if_unset(args, "verbose", sniffer_cfg.get("verbose", False))
    _set_if_unset(args, "dns", sniffer_cfg.get("dns", False))

    # output section
    _set_if_unset(args, "json", output_cfg.get("json"))
    _set_if_unset(args, "csv", output_cfg.get("csv"))
    _set_if_unset(args, "pcap", output_cfg.get("pcap"))
    _set_if_unset(args, "output", output_cfg.get("output"))
    _set_if_unset(args, "format", output_cfg.get("format"))

    # filters section
    if not args.host and "host" in filter_cfg:
        args.host = filter_cfg["host"] if isinstance(filter_cfg["host"], list) else [filter_cfg["host"]]
    if not args.keyword and "keyword" in filter_cfg:
        args.keyword = filter_cfg["keyword"] if isinstance(filter_cfg["keyword"], list) else [filter_cfg["keyword"]]
    _set_if_unset(args, "regex", filter_cfg.get("regex", False))

    # alerts section - normalize single values to lists
    raw_status = alert_cfg.get("status")
    if raw_status is not None and not isinstance(raw_status, list):
        raw_status = [raw_status]
    _set_if_unset(args, "alert_status", raw_status)
    raw_pattern = alert_cfg.get("pattern")
    if raw_pattern is not None and not isinstance(raw_pattern, list):
        raw_pattern = [raw_pattern]
    _set_if_unset(args, "alert_pattern", raw_pattern)
    _set_if_unset(args, "stats", alert_cfg.get("stats", False))

    return args


# ---------------------------------------------------------------------------
# HTTP header helpers (works with scapy's built-in http layer, >= 2.4.5)
# ---------------------------------------------------------------------------

HTTP_PSEUDO_FIELDS = {"Method", "Path", "Http_Version"}
_HEADER_FIELD_INDEX: Optional[Dict[str, str]] = None


def _header_field_index() -> Dict[str, str]:
    """Map 'USER_AGENT' -> 'User_Agent' for every known HTTP header field."""
    global _HEADER_FIELD_INDEX
    if _HEADER_FIELD_INDEX is None and HTTPRequest is not None:
        _HEADER_FIELD_INDEX = {
            f.name.upper(): f.name
            for f in HTTPRequest.fields_desc
            if getattr(f, "name", "") not in HTTP_PSEUDO_FIELDS
        }
    return _HEADER_FIELD_INDEX or {}


def get_request_header(request, header_name: str) -> Optional[str]:
    """Fetch a header value (e.g. 'Host', 'Content-Type') from an HTTPRequest."""
    field_name = _header_field_index().get(header_name.upper().replace("-", "_"))
    if field_name is None or field_name == "Unknown_Headers":
        return None
    try:
        value = getattr(request, field_name)
    except AttributeError:
        return None
    if value is None:
        return None
    return _decode(value)


def iter_request_headers(request) -> Iterable[Tuple[str, str]]:
    """Yield (Name, value) for every header present on an HTTPRequest."""
    try:
        fields_desc = request.fields_desc
    except Exception:
        return
    for f in fields_desc:
        name = getattr(f, "name", "")
        if name in HTTP_PSEUDO_FIELDS or name == "Unknown_Headers":
            continue
        if type(f).__name__ != "_HTTPHeaderField":
            continue
        try:
            value = getattr(request, name)
        except AttributeError:
            continue
        if value is None:
            continue
        yield name.replace("_", "-"), _decode(value)

    # Custom / non-standard headers arrive in the raw Unknown_Headers blob.
    try:
        raw_unknown = getattr(request, "Unknown_Headers")
    except AttributeError:
        raw_unknown = None
    if raw_unknown:
        for line in _decode(raw_unknown).split("\r\n"):
            if ":" in line:
                hname, _, hval = line.partition(":")
                yield hname.strip(), hval.strip()


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

def extract_url(request, packet) -> str:
    """Build the full request URL (scheme://host[:port]/path?query)."""
    host = get_request_header(request, "Host")
    if not host:
        host = _endpoint(packet, dst=True).rsplit(":", 1)[0]

    path = _decode(getattr(request, "Path", None)) or "/"

    # Absolute-form request targets (used through proxies) already carry a URL.
    if path.lower().startswith(("http://", "https://")):
        return path

    scheme = "https"
    try:
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport != 443:
            scheme = "http"
    except Exception:
        pass

    port = ""
    try:
        if packet.haslayer(scapy.TCP):
            dport = packet[scapy.TCP].dport
            if scheme == "http" and dport not in (None, 80):
                port = f":{dport}"
            elif scheme == "https" and dport not in (None, 443):
                port = f":{dport}"
    except Exception:
        pass

    return f"{scheme}://{host}{port}{path}"


# ---------------------------------------------------------------------------
# Enhanced credential detection
# ---------------------------------------------------------------------------

SENSITIVE_KEYS = re.compile(
    r"(?i)^(user(name|id)?|login|email|pass(word|wd|phrase)?|pwd|"
    r"password_?hash|token|access_?token|refresh_?token|api[_-]?key|apikey|"
    r"secret|auth|session|sessionid|session_?id|jwt|csrf|csrf_?token|pin|otp|"
    r"twofa|2fa|cookie|accesskey|access_?secret|private_?key)$"
)

SENSITIVE_HEADER_RE = re.compile(
    r"(?i)(api[-_]?key|auth[-_]?token|csrf[-_]?token|bearer|secret|access[-_]?token)"
)

BASIC_AUTH_RE = re.compile(r"^Basic\s+(.+)$", re.IGNORECASE)
BEARER_RE = re.compile(r"^Bearer\s+(\S+)$", re.IGNORECASE)

# --- Enhanced credential patterns ---

# AWS Access Key ID (AKIA...) and Secret Access Key
AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
AWS_SECRET_KEY_RE = re.compile(
    r"(?i)(aws[_\-]?secret[_\-]?access[_\-]?key|aws[_\-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
)

# Stripe API keys
STRIPE_KEY_RE = re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,99}|pk_live_[0-9a-zA-Z]{24,99}|sk_test_[0-9a-zA-Z]{24,99}|pk_test_[0-9a-zA-Z]{24,99}|rk_live_[0-9a-zA-Z]{24,99}|rk_test_[0-9a-zA-Z]{24,99})\b")

# GitHub tokens
GITHUB_TOKEN_RE = re.compile(r"\b(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|ghr_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59})\b")

# Google API keys (AIza...)
GOOGLE_API_KEY_RE = re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")

# Generic API key patterns (long hex/base64 strings assigned to key-like names)
GENERIC_SECRET_RE = re.compile(
    r"(?i)(secret|api_?key|access_?key|auth_?token|private_?key|encryption_?key)\s*[=:]\s*['\"]([A-Za-z0-9+/=\-_]{20,})['\"]"
)

# JWT token (three base64url segments separated by dots)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# Credit card numbers (basic pattern, validated with Luhn)
CREDIT_CARD_RE = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b")

# PEM-encoded private key
PEM_KEY_RE = re.compile(
    r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
    re.IGNORECASE,
)

# GCP service account JSON key pattern
GCP_SA_KEY_RE = re.compile(r'"private_key"\s*:\s*"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"')

# Generic connection string / DSN with embedded password
CONNECTION_STRING_RE = re.compile(
    r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp|mssql)://[^:]+:[^@]+@[^\s]+"
)

# Headers handled by their own dedicated extractors.
_SKIPPED_HEADERS = {"authorization", "proxy-authorization", "cookie"}


@dataclass
class CredentialFinding:
    """A set of credential-like key/value pairs found in one location."""

    kind: str  # query | form | json | basic_auth | bearer | cookie | header | aws_key | stripe_key | github_token | google_key | jwt | credit_card | pem_key | gcp_sa | connection_string
    fields: Dict[str, str] = field(default_factory=dict)
    raw: str = ""

    def render(self) -> str:
        if self.fields:
            return "&".join(f"{k}={v}" for k, v in self.fields.items())
        return self.raw

    def to_dict(self) -> Dict[str, object]:
        return {"kind": self.kind, "fields": dict(self.fields), "raw": self.raw}


def _is_sensitive(key: str) -> bool:
    return bool(SENSITIVE_KEYS.match(key.strip().lower()))


def _is_sensitive_header(name: str) -> bool:
    n = name.lower().replace("_", "-")
    if n in ("authorization", "proxy-authorization", "cookie",
             "x-api-key", "x-auth-token", "x-csrf-token", "x-session-token"):
        return True
    return bool(SENSITIVE_HEADER_RE.search(n))


def _luhn_check(number: str) -> bool:
    """Validate a credit card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


def _decode_jwt_payload(token: str) -> Optional[Dict[str, str]]:
    """Decode the payload of a JWT token (second segment) without verifying."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        # Add padding
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        decoded = base64.urlsafe_b64decode(payload_b64)
        data = json.loads(decoded)
        if isinstance(data, dict):
            return {k: str(v) for k, v in data.items() if isinstance(v, (str, int, float, bool))}
        return None
    except Exception:
        return None


def find_credentials_in_pairs(pairs: Iterable[Tuple[str, str]], kind: str) -> Optional[CredentialFinding]:
    found: Dict[str, str] = {}
    for key, value in pairs:
        if _is_sensitive(key) and value:
            found[key] = value
    return CredentialFinding(kind=kind, fields=found) if found else None


def find_credentials_in_query(url: str) -> Optional[CredentialFinding]:
    query = urlsplit(url).query
    if not query:
        return None
    pairs = [(k, v) for k, values in parse_qs(query, keep_blank_values=True).items() for v in values]
    return find_credentials_in_pairs(pairs, "query")


def find_credentials_in_form(body: str) -> Optional[CredentialFinding]:
    if "=" not in body:
        return None
    try:
        pairs = [(k, v) for k, values in parse_qs(body, keep_blank_values=True).items() for v in values]
    except Exception:
        return None
    return find_credentials_in_pairs(pairs, "form")


def find_credentials_in_json(body: str) -> Optional[CredentialFinding]:
    try:
        data = json.loads(body)
    except Exception:
        return None

    found: Dict[str, str] = {}

    def walk(node, prefix: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{prefix}{k}.")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{prefix}{i}.")
        elif isinstance(node, (str, int, float, bool)):
            key = prefix.rstrip(".")
            if key and _is_sensitive(key.split(".")[-1]):
                found[key] = str(node)

    walk(data, "")
    return CredentialFinding(kind="json", fields=found) if found else None


def find_credentials_in_basic_auth(header_value: str) -> Optional[CredentialFinding]:
    m = BASIC_AUTH_RE.match(header_value.strip())
    if not m:
        return None
    try:
        decoded = base64.b64decode(m.group(1), validate=False).decode("utf-8", "replace")
    except Exception:
        return None
    user, sep, password = decoded.partition(":")
    if not sep:
        return None
    return CredentialFinding(kind="basic_auth", fields={"username": user, "password": password})


def find_bearer_token(header_value: str) -> Optional[CredentialFinding]:
    m = BEARER_RE.match(header_value.strip())
    if m:
        return CredentialFinding(kind="bearer", fields={"token": m.group(1)})
    return None


def find_credentials_in_cookies(cookie_header: str) -> Optional[CredentialFinding]:
    pairs: List[Tuple[str, str]] = []
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part:
            continue
        key, _, value = part.partition("=")
        pairs.append((key.strip(), unquote(value.strip())))
    return find_credentials_in_pairs(pairs, "cookie")


def find_credentials_in_headers(headers: Iterable[Tuple[str, str]]) -> Optional[CredentialFinding]:
    found: Dict[str, str] = {}
    for name, value in headers:
        if value and name.lower() not in _SKIPPED_HEADERS and _is_sensitive_header(name):
            found[name] = value
    return CredentialFinding(kind="header", fields=found) if found else None


def find_credentials_in_body(content_type: Optional[str], body: str) -> List[CredentialFinding]:
    ctype = (content_type or "").lower()
    findings: List[CredentialFinding] = []
    stripped = body.lstrip()
    if "application/json" in ctype or stripped.startswith("{"):
        finding = find_credentials_in_json(body)
        if finding:
            findings.append(finding)
    elif "x-www-form-urlencoded" in ctype or ("=" in stripped and "&" in stripped):
        finding = find_credentials_in_form(body)
        if finding:
            findings.append(finding)
    return findings


def find_enhanced_credentials(text: str) -> List[CredentialFinding]:
    """Scan arbitrary text for high-value credential patterns (AWS, Stripe, etc.)."""
    findings: List[CredentialFinding] = []

    # AWS Access Key IDs
    for m in AWS_ACCESS_KEY_RE.finditer(text):
        findings.append(CredentialFinding(
            kind="aws_key",
            fields={"access_key_id": m.group(1)},
            raw=m.group(0),
        ))

    # AWS Secret Access Keys
    for m in AWS_SECRET_KEY_RE.finditer(text):
        findings.append(CredentialFinding(
            kind="aws_key",
            fields={"secret_key_name": m.group(1), "secret_key": m.group(2)},
            raw=m.group(0),
        ))

    # Stripe API keys
    for m in STRIPE_KEY_RE.finditer(text):
        prefix = m.group(1).split("_")[0]
        kind_label = {"sk": "stripe_secret", "pk": "stripe_public", "rk": "stripe_restricted"}.get(prefix, "stripe_key")
        findings.append(CredentialFinding(
            kind=kind_label,
            fields={"api_key": m.group(1)},
            raw=m.group(0),
        ))

    # GitHub tokens
    for m in GITHUB_TOKEN_RE.finditer(text):
        findings.append(CredentialFinding(
            kind="github_token",
            fields={"token": m.group(1)},
            raw=m.group(0),
        ))

    # Google API keys
    for m in GOOGLE_API_KEY_RE.finditer(text):
        findings.append(CredentialFinding(
            kind="google_key",
            fields={"api_key": m.group(1)},
            raw=m.group(0),
        ))

    # Generic secret patterns
    for m in GENERIC_SECRET_RE.finditer(text):
        findings.append(CredentialFinding(
            kind="generic_secret",
            fields={"name": m.group(1), "value": m.group(2)},
            raw=m.group(0),
        ))

    # JWT tokens
    for m in JWT_RE.finditer(text):
        payload = _decode_jwt_payload(m.group(0))
        if payload:
            fields = {"token_preview": m.group(0)[:60] + "..."}
            # Extract interesting claims
            for claim in ("sub", "iss", "aud", "exp", "iat", "email", "username", "role"):
                if claim in payload:
                    fields[claim] = payload[claim]
            findings.append(CredentialFinding(kind="jwt", fields=fields, raw=m.group(0)))

    # Credit card numbers (only valid Luhn)
    for m in CREDIT_CARD_RE.finditer(text):
        number = m.group(0).replace(" ", "").replace("-", "")
        if _luhn_check(number):
            findings.append(CredentialFinding(
                kind="credit_card",
                fields={"number": number},
                raw=m.group(0),
            ))

    # PEM private keys
    if PEM_KEY_RE.search(text):
        findings.append(CredentialFinding(kind="pem_key", raw="[private key detected]"))

    # GCP Service Account
    if GCP_SA_KEY_RE.search(text):
        findings.append(CredentialFinding(kind="gcp_sa", raw="[GCP service account key detected]"))

    # Connection strings with embedded passwords
    for m in CONNECTION_STRING_RE.finditer(text):
        findings.append(CredentialFinding(
            kind="connection_string",
            fields={"dsn": m.group(0)[:120]},
            raw=m.group(0),
        ))

    return findings


def extract_credentials(url: str, headers: List[Tuple[str, str]], body: str) -> List[CredentialFinding]:
    """Run every credential extractor against one HTTP request."""
    findings: List[CredentialFinding] = []

    finding = find_credentials_in_query(url)
    if finding:
        findings.append(finding)

    header_map = {name.lower(): value for name, value in headers}

    auth = header_map.get("authorization")
    if auth:
        finding = find_credentials_in_basic_auth(auth) or find_bearer_token(auth)
        if finding:
            findings.append(finding)

    cookie = header_map.get("cookie")
    if cookie:
        finding = find_credentials_in_cookies(cookie)
        if finding:
            findings.append(finding)

    finding = find_credentials_in_headers(headers)
    if finding:
        findings.append(finding)

    findings.extend(find_credentials_in_body(header_map.get("content-type"), body))

    # Enhanced credential scanning on the full URL + body text
    text_to_scan = f"{url} {_decode(body)}"
    findings.extend(find_enhanced_credentials(text_to_scan))

    return findings


def extract_response_credentials(packet_or_response) -> List[CredentialFinding]:
    """Extract credential-like data from an HTTP response (Set-Cookie, auth headers, body).

    Accepts either a scapy packet (preferred) or an HTTPResponse layer.
    """
    findings: List[CredentialFinding] = []

    # Determine if we have a full packet or just the HTTP response layer
    if packet_or_response is None:
        return findings

    # If it's a packet with layers, extract the response layer and raw body
    response = packet_or_response
    raw_body = b""
    if hasattr(packet_or_response, "haslayer"):
        # It's a packet - extract the HTTPResponse layer and raw body
        if packet_or_response.haslayer(HTTPResponse):
            response = packet_or_response[HTTPResponse]
        else:
            return findings
        if packet_or_response.haslayer(scapy.Raw):
            raw_body = packet_or_response[scapy.Raw].load
    elif hasattr(packet_or_response, "fields_desc"):
        # It's an HTTPResponse layer directly
        response = packet_or_response
    else:
        return findings

    try:
        headers = []
        # Extract headers from the response
        try:
            for f in response.fields_desc:
                name = getattr(f, "name", "")
                if name in ("Status_Code", "Reason_Phrase", "Http_Version") or name == "Unknown_Headers":
                    continue
                if type(f).__name__ != "_HTTPHeaderField":
                    continue
                value = getattr(response, name, None)
                if value is not None:
                    headers.append((name.replace("_", "-"), _decode(value)))
        except Exception:
            pass

        # Custom headers from Unknown_Headers
        try:
            raw_unknown = getattr(response, "Unknown_Headers")
            if raw_unknown:
                for line in _decode(raw_unknown).split("\r\n"):
                    if ":" in line:
                        hname, _, hval = line.partition(":")
                        headers.append((hname.strip(), hval.strip()))
        except Exception:
            pass

        header_map = {name.lower(): value for name, value in headers}

        # Check Set-Cookie for sensitive cookie values
        set_cookie = header_map.get("set-cookie")
        if set_cookie:
            finding = find_credentials_in_cookies(set_cookie)
            if finding:
                finding.kind = "response_cookie"
                findings.append(finding)

        # Check Authorization header in responses (rare but possible in redirects)
        auth = header_map.get("authorization")
        if auth:
            finding = find_credentials_in_basic_auth(auth) or find_bearer_token(auth)
            if finding:
                finding.kind = f"response_{finding.kind}"
                findings.append(finding)

        # Check for sensitive response headers
        finding = find_credentials_in_headers(headers)
        if finding:
            finding.kind = "response_header"
            findings.append(finding)

        # Scan response body for high-value patterns
        if not raw_body and hasattr(response, "load"):
            try:
                raw_body = response.load if isinstance(response.load, bytes) else b""
            except Exception:
                pass
        if raw_body:
            body_text = _decode(raw_body)
            findings.extend(find_enhanced_credentials(body_text))

    except Exception:
        pass
    return findings


# ---------------------------------------------------------------------------
# DNS query logging
# ---------------------------------------------------------------------------

@dataclass
class DNSQueryInfo:
    """Parsed DNS query."""
    timestamp: str
    src: str
    dst: str
    query_name: str
    query_type: int
    query_type_str: str
    is_response: bool

    def to_dict(self) -> dict:
        return {
            "ts": self.timestamp,
            "src": self.src,
            "dst": self.dst,
            "query_name": self.query_name,
            "query_type": self.query_type_str,
            "is_response": self.is_response,
        }


DNS_TYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "SVCB",
    65: "HTTPS", 255: "ANY", 256: "URI",
}


def analyze_dns(packet) -> Optional[DNSQueryInfo]:
    """Extract DNS query information from a DNS packet."""
    if not packet.haslayer(DNS):
        return None
    try:
        dns = packet[DNS]
        qd = dns.qd
        if qd is None:
            return None
        qname = _decode(qd.qname).rstrip(".")
        qtype = int(qd.qtype) if hasattr(qd, "qtype") else 0
        is_response = bool(dns.qr)
        return DNSQueryInfo(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            src=_endpoint(packet, dst=False),
            dst=_endpoint(packet, dst=True),
            query_name=qname,
            query_type=qtype,
            query_type_str=DNS_TYPE_MAP.get(qtype, f"TYPE{qtype}"),
            is_response=is_response,
        )
    except Exception:
        return None


# ---------------------------------------------------------------------------
# TLS SNI extraction
# ---------------------------------------------------------------------------

@dataclass
class TLSInfo:
    """Parsed TLS ClientHello info."""
    timestamp: str
    src: str
    dst: str
    sni: str
    alpn: List[str]
    tls_version: int

    def to_dict(self) -> dict:
        return {
            "ts": self.timestamp,
            "src": self.src,
            "dst": self.dst,
            "sni": self.sni,
            "alpn": self.alpn,
        }


def _extract_sni_from_raw(raw_bytes: bytes) -> Optional[str]:
    """Extract SNI hostname from raw TLS ClientHello bytes via regex."""
    # TLS ClientHello with SNI extension contains the hostname as ASCII
    # Structure: ext_type(0x0000) + ext_len + list_len + name_type(0x00) + host_len + hostname
    sni_match = re.search(
        rb'\x00\x00'          # server_name extension type (0x0000)
        rb'.{2}'               # extension length
        rb'.{2}'               # server_name_list length
        rb'\x00'              # host_name type (0)
        rb'.{2}'               # hostname length
        rb'([a-zA-Z0-9][a-zA-Z0-9.\-]+[a-zA-Z0-9])',  # hostname
        raw_bytes,
    )
    if sni_match:
        try:
            return sni_match.group(1).decode("ascii", errors="ignore")
        except Exception:
            pass
    return None


def extract_tls_info(packet) -> Optional[TLSInfo]:
    """Extract SNI and other info from a TLS ClientHello packet."""
    sni = ""
    alpn: List[str] = []

    # Try scapy's TLSClientHello layer first
    if packet.haslayer(TLSClientHello):
        try:
            hello = packet[TLSClientHello]
            if hasattr(hello, "extensions"):
                for ext in hello.extensions:
                    if hasattr(ext, "servernames"):
                        for sn in ext.servernames:
                            if hasattr(sn, "servername"):
                                sni = _decode(sn.servername)
                                break
                    if hasattr(ext, "alpnprotocols"):
                        for proto in ext.alpnprotocols:
                            alpn.append(_decode(proto))
        except Exception:
            pass

    # Fallback: extract SNI from raw TLS bytes
    if not sni and packet.haslayer(scapy.Raw):
        try:
            raw = bytes(packet[scapy.Raw].load)
            sni = _extract_sni_from_raw(raw) or ""
        except Exception:
            pass

    if not sni:
        return None

    return TLSInfo(
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        src=_endpoint(packet, dst=False),
        dst=_endpoint(packet, dst=True),
        sni=sni,
        alpn=alpn,
        tls_version=0,
    )


# ---------------------------------------------------------------------------
# Packet analysis
# ---------------------------------------------------------------------------

@dataclass
class RequestInfo:
    method: str
    url: str
    host: str
    src: str
    dst: str
    headers: List[Tuple[str, str]]
    body: str
    findings: List[CredentialFinding]


def analyze_http(method: str, url: str, headers: List[Tuple[str, str]], body: str,
                 src: str = "", dst: str = "") -> RequestInfo:
    """Analyze a normalized HTTP request (shared by packet and proxy paths)."""
    host = urlsplit(url).hostname or ""
    findings = extract_credentials(url, headers, body)
    return RequestInfo(
        method=method, url=url, host=host, src=src, dst=dst,
        headers=headers, body=body, findings=findings,
    )


def analyze_request(packet) -> Optional[RequestInfo]:
    """Analyze a packet that contains an HTTP request. Returns None otherwise."""
    if HTTPRequest is None or not packet.haslayer(HTTPRequest):
        return None
    try:
        request = packet[HTTPRequest]
        method = _decode(getattr(request, "Method", None)) or "GET"
        url = extract_url(request, packet)
        src = _endpoint(packet, dst=False)
        dst = _endpoint(packet, dst=True)
        headers = list(iter_request_headers(request))
        raw = packet[scapy.Raw].load if packet.haslayer(scapy.Raw) else b""
        return analyze_http(method, url, headers, _decode(raw), src, dst)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Interface listing (cross-platform)
# ---------------------------------------------------------------------------

def list_interfaces() -> List[Tuple[str, str]]:
    """Return [(name, description)] for every available network interface."""
    names: List[str] = []
    try:
        names = list(scapy.get_if_list())
    except Exception:
        pass

    if not names and os.path.isdir("/sys/class/net"):
        names = sorted(os.listdir("/sys/class/net"))

    descriptions: Dict[str, str] = {}
    try:
        for iface in scapy.conf.ifaces.values():
            descriptions[iface.name] = getattr(iface, "description", "") or ""
    except Exception:
        pass

    if not names and sys.platform.startswith("win"):
        try:
            from scapy.arch.windows import get_windows_if_list

            return [(i.get("name", ""), i.get("description", "")) for i in get_windows_if_list()]
        except Exception:
            pass

    return [(name, descriptions.get(name, "")) for name in names]


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def host_matches(pattern: str, host: str) -> bool:
    """Match a host filter: exact, subdomain, or '*.domain' wildcard."""
    pattern = pattern.strip().lower()
    host = host.lower()
    if pattern.startswith("*."):
        pattern = pattern[2:]
    return host == pattern or host.endswith("." + pattern)


def host_matches_regex(pattern: str, host: str) -> bool:
    """Match a host filter using a regex pattern."""
    try:
        return bool(re.search(pattern, host, re.IGNORECASE))
    except re.error:
        return host_matches(pattern, host)


def matches_filters(host: str, url: str, body: str, host_filters,
                    keyword_filters, use_regex: bool = False) -> bool:
    if host_filters:
        matcher = host_matches_regex if use_regex else host_matches
        if not any(matcher(p, host) for p in host_filters):
            return False
    if keyword_filters:
        haystack = f"{url} {body}".lower()
        for kw in keyword_filters:
            if use_regex:
                try:
                    if re.search(kw, haystack, re.IGNORECASE):
                        break
                except re.error:
                    if kw.lower() in haystack:
                        break
            else:
                if kw.lower() in haystack:
                    break
        else:
            return False
    return True


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

@dataclass
class Stats:
    started: float = field(default_factory=time.time)
    packets_seen: int = 0
    http_requests: int = 0
    http_responses: int = 0
    credential_findings: int = 0
    dns_queries: int = 0
    tls_connections: int = 0
    bytes_captured: int = 0
    hosts: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    statuses: Counter = field(default_factory=Counter)
    tls_hostnames: Set[str] = field(default_factory=set)
    dns_names: Set[str] = field(default_factory=set)
    alert_count: int = 0

    def elapsed(self) -> float:
        return time.time() - self.started

    def summary_lines(self) -> List[str]:
        lines = [
            "=== SniffEx Summary ===",
            f"Duration:           {self.elapsed():.1f}s",
            f"Packets seen:       {self.packets_seen}",
            f"HTTP requests:      {self.http_requests}",
            f"HTTP responses:     {self.http_responses}",
            f"DNS queries:        {self.dns_queries}",
            f"TLS connections:    {self.tls_connections}",
            f"Credential hits:    {self.credential_findings}",
            f"Alerts triggered:   {self.alert_count}",
            f"Bytes captured:     {self.bytes_captured:,}",
        ]
        if self.hosts:
            top = self.hosts.most_common(10)
            lines.append("Top hosts:")
            for host, count in top:
                lines.append(f"  {host:<40} {count}")
        if self.methods:
            lines.append("Methods: " + ", ".join(f"{m}={c}" for m, c in self.methods.most_common()))
        if self.statuses:
            lines.append("Statuses: " + ", ".join(f"{s}={c}" for s, c in self.statuses.most_common()))
        if self.tls_hostnames:
            lines.append(f"TLS hostnames seen: {len(self.tls_hostnames)}")
        return lines


# ---------------------------------------------------------------------------
# Sniffer
# ---------------------------------------------------------------------------

class Sniffer:
    """Wraps scapy.sniff with filtering, logging and structured output."""

    def __init__(
        self,
        interface: Optional[str] = None,
        *,
        read_path: Optional[str] = None,
        hosts: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        json_path: Optional[str] = None,
        csv_path: Optional[str] = None,
        pcap_path: Optional[str] = None,
        quiet: bool = False,
        verbose: bool = False,
        color: bool = True,
        count: Optional[int] = None,
        timeout: Optional[float] = None,
        bpf_filter: Optional[str] = None,
        dns_logging: bool = False,
        use_regex: bool = False,
        alert_status_codes: Optional[List[int]] = None,
        alert_patterns: Optional[List[str]] = None,
        log_level: str = "WARNING",
    ):
        self.interface = interface
        self.read_path = read_path
        self.host_filters = hosts or []
        self.keyword_filters = keywords or []
        self.quiet = quiet
        self.verbose = verbose
        self.color = color
        self.count = count if count and count > 0 else None
        self.timeout = timeout
        self.bpf_filter = bpf_filter
        self.dns_logging = dns_logging
        self.use_regex = use_regex
        self.alert_status_codes = alert_status_codes or []
        self.alert_patterns = alert_patterns or []
        self.stats = Stats()
        self.deadline = time.time() + timeout if timeout else None
        self._stats_thread: Optional[threading.Thread] = None
        self._stats_stop = threading.Event()

        # Configure logging
        log_fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        logging.basicConfig(level=getattr(logging, log_level.upper(), logging.WARNING),
                            format=log_fmt, stream=sys.stderr)

        self._json_file = None
        if json_path:
            self._json_file = open(json_path, "a", encoding="utf-8")
        self._csv_file = None
        self._csv_writer = None
        if csv_path:
            needs_header = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0
            self._csv_file = open(csv_path, "a", encoding="utf-8", newline="")
            self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=CSV_FIELDNAMES)
            if needs_header:
                self._csv_writer.writeheader()
                self._csv_file.flush()
        self._pcap_writer = None
        if pcap_path:
            self._pcap_writer = PcapWriter(pcap_path, append=True, sync=True)
        self._mitm_master = None

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._stats_stop.set()
        if self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=2)
        if self._json_file:
            try:
                self._json_file.close()
            except Exception:
                pass
            self._json_file = None
        if self._csv_file:
            try:
                self._csv_file.close()
            except Exception:
                pass
            self._csv_file = None
            self._csv_writer = None
        if self._pcap_writer:
            try:
                self._pcap_writer.close()
            except Exception:
                pass
            self._pcap_writer = None

    # -- sniffing -----------------------------------------------------------

    def _should_stop(self) -> bool:
        if self.count is not None and self.stats.http_requests >= self.count:
            return True
        if self.deadline is not None and time.time() >= self.deadline:
            return True
        return False

    def _start_stats_display(self, interval: float = 5.0) -> None:
        """Start a background thread that prints periodic stats."""
        def _stats_loop():
            while not self._stats_stop.wait(interval):
                self._print_live_stats()
        self._stats_thread = threading.Thread(target=_stats_loop, daemon=True)
        self._stats_thread.start()

    def _print_live_stats(self) -> None:
        """Print a compact live stats line."""
        if self.quiet:
            return
        elapsed = self.stats.elapsed()
        line = (
            f"\r[*] {elapsed:.0f}s | "
            f"pkts={self.stats.packets_seen} | "
            f"reqs={self.stats.http_requests} | "
            f"creds={self.stats.credential_findings} | "
            f"dns={self.stats.dns_queries} | "
            f"tls={self.stats.tls_connections} | "
            f"alerts={self.stats.alert_count}"
        )
        sys.stderr.write(colorize(line, Colors.CYAN, self.color))
        sys.stderr.flush()

    def run(self, start_stats: bool = False) -> None:
        if start_stats:
            self._start_stats_display()
        if self.read_path:
            self._run_offline()
        else:
            scapy.sniff(
                iface=self.interface,
                store=False,
                prn=self.handle_packet,
                stop_filter=lambda _pkt: self._should_stop(),
                timeout=self.timeout,
                bpf_filter=self.bpf_filter,
            )

    def _run_offline(self) -> None:
        """Analyze packets from a pcap file (no live capture or privileges)."""
        from scapy.utils import PcapReader

        with PcapReader(self.read_path) as reader:
            for packet in reader:
                if self._should_stop():
                    break
                self.handle_packet(packet)

    # -- packet handling ----------------------------------------------------

    def handle_packet(self, packet) -> None:
        """Process one captured packet. Never raises."""
        try:
            self.stats.packets_seen += 1
            # Track bytes
            try:
                self.stats.bytes_captured += len(packet)
            except Exception:
                pass

            if HTTPRequest is not None and packet.haslayer(HTTPRequest):
                self._handle_request(packet)
            elif HTTPResponse is not None and packet.haslayer(HTTPResponse):
                self._handle_response(packet)

            # DNS logging
            if self.dns_logging and packet.haslayer(DNS):
                self._handle_dns(packet)

            # TLS SNI extraction (scapy-parsed layer OR raw TLS ClientHello)
            if packet.haslayer(TLSClientHello) or self._is_raw_tls_client_hello(packet):
                self._handle_tls(packet)

            if self._pcap_writer:
                self._pcap_writer.write(packet)
        except Exception:
            # A malformed packet must never kill the capture loop.
            logger.debug("Error handling packet", exc_info=True)

    def _handle_request(self, packet) -> None:
        info = analyze_request(packet)
        if info is None:
            return
        self.process_request_info(info)

    def _handle_dns(self, packet) -> None:
        """Process a DNS packet."""
        info = analyze_dns(packet)
        if info is None:
            return
        self.stats.dns_queries += 1
        self.stats.dns_names.add(info.query_name)
        self._emit_json("dns_query", info.to_dict())
        if self.verbose:
            label = "RESP" if info.is_response else "REQ"
            print(colorize(
                f"[D] DNS {label} {info.query_type_str} {info.query_name} "
                f"({info.src} -> {info.dst})",
                Colors.MAGENTA, self.color,
            ))

    def _is_raw_tls_client_hello(self, packet) -> bool:
        """Detect a TLS ClientHello from raw bytes (record type 0x16, handshake type 0x01)."""
        if not packet.haslayer(scapy.Raw):
            return False
        try:
            raw = bytes(packet[scapy.Raw].load)
            if len(raw) < 6:
                return False
            # TLS record: content type 0x16 (handshake), version 2 bytes, length 2 bytes
            # Then handshake: type 0x01 (ClientHello)
            return (raw[0] == 0x16 and raw[5] == 0x01)
        except Exception:
            return False

    def _handle_tls(self, packet) -> None:
        """Process a TLS ClientHello packet for SNI extraction."""
        info = extract_tls_info(packet)
        if info is None:
            return
        self.stats.tls_connections += 1
        self.stats.tls_hostnames.add(info.sni)
        self._emit_json("tls_hello", info.to_dict())
        if self.verbose:
            alpn_str = ",".join(info.alpn) if info.alpn else "none"
            print(colorize(
                f"[T] TLS SNI={info.sni} ALPN=[{alpn_str}] "
                f"({info.src} -> {info.dst})",
                Colors.BLUE, self.color,
            ))

    def process_request_info(self, info: RequestInfo, write_synthetic: bool = False) -> None:
        """Run filtering, stats, logging and output for one analyzed request.

        Shared by the live/offline packet paths and the MITM proxy path.
        """
        if not matches_filters(info.host, info.url, info.body,
                               self.host_filters, self.keyword_filters, self.use_regex):
            return

        self.stats.http_requests += 1
        self.stats.hosts[info.host or "(unknown)"] += 1
        self.stats.methods[info.method] += 1
        if info.findings:
            self.stats.credential_findings += len(info.findings)

        # Check alerts
        self._check_alerts(info)

        if write_synthetic:
            self._write_synthetic_request(info)
        self._emit_json("http_request", {
            "method": info.method,
            "url": info.url,
            "host": info.host,
            "src": info.src,
            "dst": info.dst,
            "headers": [{"name": n, "value": v} for n, v in info.headers],
            "body": info.body[:8192],
            "findings": [f.to_dict() for f in info.findings],
        })
        self._emit_csv(info)
        self._print_request(info)

    def _check_alerts(self, info: RequestInfo) -> None:
        """Check if a request triggers any configured alerts."""
        triggered = False
        for pattern in self.alert_patterns:
            if re.search(pattern, info.url, re.IGNORECASE):
                triggered = True
                break
        if triggered:
            self.stats.alert_count += 1
            alert_msg = f"[!!!] ALERT: URL matches pattern - {info.method} {info.url}"
            print(colorize(alert_msg, Colors.YELLOW, self.color))
            self._emit_json("alert", {
                "method": info.method,
                "url": info.url,
                "host": info.host,
                "src": info.src,
                "dst": info.dst,
                "alert_type": "pattern_match",
            })

    def _write_synthetic_request(self, info: RequestInfo) -> None:
        """Reconstruct a scapy HTTP request packet from analyzed data (MITM mode)."""
        if not self._pcap_writer:
            return
        try:
            src_ip, src_port = _split_endpoint(info.src)
            dst_ip, dst_port = _split_endpoint(info.dst)
            kwargs = {"Method": info.method, "Path": urlsplit(info.url).path or "/"}
            host = urlsplit(info.url).hostname or info.host
            if host:
                kwargs["Host"] = host
            for name, value in info.headers:
                field = _header_field_index().get(name.upper().replace("-", "_"))
                if field and field not in HTTP_PSEUDO_FIELDS and field != "Unknown_Headers":
                    kwargs[field] = value
            packet = (
                scapy.Ether()
                / scapy.IP(src=src_ip or "0.0.0.0", dst=dst_ip or "0.0.0.0")
                / scapy.TCP(sport=src_port or 0, dport=dst_port or 80)
                / HTTPRequest(**kwargs)
            )
            if info.body:
                packet = packet / scapy.Raw(load=info.body)
            self._pcap_writer.write(packet)
        except Exception:
            pass

    def _handle_response(self, packet) -> None:
        try:
            response = packet[HTTPResponse]
            status = _decode(getattr(response, "Status_Code", None)) or _decode(
                getattr(response, "Status", None)
            )
            if status:
                self.stats.statuses[status] += 1
            self.stats.http_responses += 1

            # Check for alert status codes
            try:
                status_int = int(status) if status else 0
                if status_int in self.alert_status_codes:
                    self.stats.alert_count += 1
                    alert_msg = f"[!!!] ALERT: Status {status} from {_endpoint(packet, dst=False)}"
                    print(colorize(alert_msg, Colors.YELLOW, self.color))
                    self._emit_json("alert", {
                        "status": status,
                        "src": _endpoint(packet, dst=False),
                        "dst": _endpoint(packet, dst=True),
                        "alert_type": "status_code",
                    })
            except (ValueError, TypeError):
                pass

            # Extract response credentials
            response_findings = extract_response_credentials(packet)
            if response_findings:
                self.stats.credential_findings += len(response_findings)
                for finding in response_findings:
                    label = finding.kind.upper().replace("_", " ")
                    if not self.quiet:
                        print(colorize(
                            f"[!] Response credential ({label}) >> {finding.render()}",
                            Colors.RED, self.color,
                        ))
                self._emit_json("http_response", {
                    "status": status,
                    "src": _endpoint(packet, dst=False),
                    "dst": _endpoint(packet, dst=True),
                    "findings": [f.to_dict() for f in response_findings],
                })
            else:
                self._emit_json("http_response", {
                    "status": status,
                    "src": _endpoint(packet, dst=False),
                    "dst": _endpoint(packet, dst=True),
                })
        except Exception:
            pass

    # -- MITM proxy (HTTPS decryption) ---------------------------------------

    def run_mitm(self, port: int = 8080, mode: str = "regular") -> None:
        """Run an embedded mitmproxy to decrypt HTTPS and feed the pipeline."""
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._mitm_main(port, mode))
        finally:
            loop.close()

    async def _mitm_main(self, port: int, mode: str) -> None:
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        opts = options.Options(
            listen_host="0.0.0.0",
            listen_port=port,
            mode=[mode],
            ssl_insecure=True,  # accept self-signed upstream certs during tests
        )
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self._mitm_master = master
        master.addons.add(MitmHandler(self, on_stop=master.shutdown))
        if self.timeout:
            master.event_loop.call_later(self.timeout, master.shutdown)
        await master.run()

    def shutdown_mitm(self) -> None:
        if self._mitm_master is not None:
            try:
                self._mitm_master.shutdown()
            except Exception:
                pass
            self._mitm_master = None

    # -- output -------------------------------------------------------------

    def _emit_json(self, event_type: str, data: dict) -> None:
        if not self._json_file:
            return
        record = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "type": event_type, **data}
        try:
            self._json_file.write(json.dumps(record) + "\n")
            self._json_file.flush()
        except Exception:
            pass

    def _emit_csv(self, info: RequestInfo) -> None:
        """Append one CSV row per credential finding (requests only)."""
        if not self._csv_writer or not info.findings:
            return
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            for finding in info.findings:
                self._csv_writer.writerow({
                    "ts": ts,
                    "method": info.method,
                    "url": info.url,
                    "host": info.host,
                    "src": info.src,
                    "dst": info.dst,
                    "kind": finding.kind,
                    "fields": finding.render(),
                    "raw": finding.raw,
                })
            self._csv_file.flush()
        except Exception:
            pass

    def _print_request(self, info: RequestInfo) -> None:
        if self.quiet:
            return
        line = colorize(f"[+] {info.method} {info.url}", Colors.GREEN, self.color)
        if info.src:
            line += colorize(f"  ({info.src} -> {info.dst})", Colors.DIM, self.color)
        print(line)

        if self.verbose:
            for name, value in info.headers:
                print(colorize(f"    {name}: {value}", Colors.DIM, self.color))
            if info.body:
                print(colorize(f"    body: {info.body[:300]}", Colors.DIM, self.color))

        for finding in info.findings:
            label = finding.kind.upper().replace("_", " ")
            print(colorize(f"[!] Possible credentials ({label}) >> {finding.render()}", Colors.RED, self.color))

    def print_summary(self) -> None:
        print("\n".join(self.stats.summary_lines()))


# ---------------------------------------------------------------------------
# MITM proxy helpers (HTTPS decryption via embedded mitmproxy)
# ---------------------------------------------------------------------------

def _addr_str(addr) -> str:
    """Normalize an address (tuple or object) to 'ip:port'."""
    if not addr:
        return ""
    if isinstance(addr, (tuple, list)):
        host, port = addr[0], addr[1]
    else:
        host = getattr(addr, "host", str(addr))
        port = getattr(addr, "port", "")
    return f"{host}:{port}"


def _conn_str(conn) -> str:
    """Normalize a mitmproxy connection (Client/Server) to 'ip:port'."""
    if not conn:
        return ""
    for attr in ("address", "peername", "sockname"):
        value = getattr(conn, attr, None)
        if value:
            return _addr_str(value)
    return ""


def _split_endpoint(endpoint: str) -> Tuple[str, int]:
    """Split 'ip:port' into (ip, port). Returns ('', 0) for empty input."""
    if not endpoint:
        return "", 0
    ip, _, port = endpoint.rpartition(":")
    ip = ip.strip("[]")
    try:
        return ip, int(port)
    except ValueError:
        return endpoint, 0


def _mitm_available() -> bool:
    try:
        import mitmproxy  # noqa: F401
        return True
    except ImportError:
        return False


def _print_mitm_instructions(port: int, mode: str) -> None:
    print(f"[*] MITM proxy listening on 0.0.0.0:{port} ({mode} mode)")
    ca_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
    if os.path.isfile(ca_path):
        print(f"[*] Install this CA certificate on the target device to trust decrypted HTTPS:")
        print(f"    {ca_path}")
    print(f"[*] Point the target's proxy settings at <this-host-ip>:{port}")
    if mode == "transparent":
        print("[*] Transparent mode: enable IP forwarding and redirect 80/443, e.g.:")
        print(f"    iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port {port}")
        print(f"    iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port {port}")
    print("[*] To intercept a LAN target's traffic, ARP-spoof it onto this host first "
          "(e.g. with ghostarp or arpspoof).")


class MitmHandler:
    """mitmproxy addon that feeds decrypted HTTP requests into the Sniffer."""

    def __init__(self, sniffer: Sniffer, on_stop=None):
        self.sniffer = sniffer
        self._on_stop = on_stop

    def request(self, flow) -> None:
        try:
            req = flow.request
            if req is None:
                return
            if not req.method or not req.pretty_url:
                return
            headers = [(name, value) for name, value in req.headers.items()]
            body = req.get_text(strict=False) or ""
            info = analyze_http(
                req.method,
                req.pretty_url,
                headers,
                body,
                src=_conn_str(flow.client_conn),
                dst=_conn_str(flow.server_conn),
            )
            self.sniffer.process_request_info(info, write_synthetic=True)
            if self.sniffer._should_stop() and self._on_stop:
                self._on_stop()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Legacy / import-friendly API
# ---------------------------------------------------------------------------

def display_banner(color: bool = True) -> None:
    banner = r"""
               ________      _____________________________
               __  ___/_________(_)__  __/__  __/__  ____/___  __
               _____ \__  __ \_  /__  /_ __  /_ __  __/  __  |/ /
               ____/ /_  / / /  / _  __/ _  __/ _  /___  __>  <
               /____/ /_/ /_//_/  /_/    /_/    /_____/  /_/|_|
    """
    print(colorize(banner, Colors.YELLOW, color))
    print(colorize(BANNER_TAGLINE, Colors.CYAN, color))
    print(colorize("=" * 72, Colors.CYAN, color))
    print(colorize(f"Version: {VERSION}        Twitter: anishalx7", Colors.CYAN, color))
    print(colorize("=" * 72, Colors.CYAN, color))
    print(colorize(DISCLAIMER, Colors.RED, color))


def get_url(packet) -> Optional[str]:
    """Legacy API: extract the URL from an HTTP request packet."""
    if HTTPRequest is None or not packet.haslayer(HTTPRequest):
        return None
    return extract_url(packet[HTTPRequest], packet)


def get_login_info(packet) -> List[CredentialFinding]:
    """Legacy API: extract credential findings from an HTTP request packet."""
    info = analyze_request(packet)
    return info.findings if info else []


def process_sniffed_packet(packet) -> None:
    """Legacy API: packet callback that prints HTTP requests and credentials."""
    try:
        info = analyze_request(packet)
        if info is None:
            return
        print(f"[+] HTTP Request >> {info.method} {info.url}")
        for finding in info.findings:
            print(f"\n\n[+] Possible username/password ({finding.kind}) >> {finding.render()}\n\n")
    except Exception:
        pass


def sniff(interface: str, **kwargs) -> None:
    """Legacy API: start sniffing on the provided interface."""
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, **kwargs)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Real-time HTTP packet sniffer with credential detection (Advanced).",
        epilog=DISCLAIMER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-i", "--interface", metavar="IFACE",
                        help="Network interface to sniff (see --list-interfaces)")
    parser.add_argument("--read", metavar="FILE",
                        help="Analyze packets from a pcap file instead of capturing live")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List available interfaces and exit")
    parser.add_argument("--mitm", action="store_true",
                        help="Decrypt HTTPS with an embedded MITM proxy "
                             "(requires: pip install sniffex[mitm])")
    parser.add_argument("--mitm-port", type=int, default=8080, metavar="PORT",
                        help="MITM proxy listen port (default: 8080)")
    parser.add_argument("--mitm-mode", choices=["regular", "transparent"], default="regular",
                        help="Proxy mode: 'regular' (explicit proxy settings) or "
                             "'transparent' (iptables REDIRECT) (default: regular)")
    parser.add_argument("--host", action="append", default=[], metavar="HOST",
                        help="Only show requests to HOST (repeatable; matches subdomains, "
                             "supports *.example.com)")
    parser.add_argument("--keyword", action="append", default=[], metavar="WORD",
                        help="Only show requests whose URL or body contains WORD (repeatable)")
    parser.add_argument("--regex", action="store_true",
                        help="Treat --host and --keyword values as regular expressions")
    parser.add_argument("--json", metavar="FILE",
                        help="Append structured events as JSON Lines to FILE")
    parser.add_argument("--csv", metavar="FILE",
                        help="Append credential findings as CSV rows to FILE")
    parser.add_argument("--format", choices=["jsonl", "csv"], default=None,
                        help="Structured output format for --output (default: jsonl)")
    parser.add_argument("--output", metavar="FILE",
                        help="Write structured output to FILE in the format selected by --format")
    parser.add_argument("--pcap", metavar="FILE",
                        help="Write every captured packet to FILE (pcap format)")
    parser.add_argument("--count", type=int, metavar="N",
                        help="Stop after N matching HTTP requests")
    parser.add_argument("--timeout", type=float, metavar="SECONDS",
                        help="Stop capturing after SECONDS")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress per-request console output (files still written)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show request headers, endpoints, DNS and TLS info")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress the startup banner")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    # --- New advanced features ---

    parser.add_argument("--bpf", metavar="FILTER",
                        help="BPF filter expression for packet capture "
                             "(e.g. 'tcp port 80', 'host 10.0.0.1')")
    parser.add_argument("--dns", action="store_true",
                        help="Enable DNS query/response logging")
    parser.add_argument("--stats", action="store_true",
                        help="Display periodic live statistics during capture")
    parser.add_argument("--config", metavar="FILE",
                        help="Load settings from a TOML configuration file")
    parser.add_argument("--alert-status", type=int, action="append", default=[],
                        metavar="CODE", dest="alert_status",
                        help="Trigger an alert when this HTTP status code is seen "
                             "(repeatable, e.g. --alert-status 401 --alert-status 403)")
    parser.add_argument("--alert-pattern", action="append", default=[],
                        metavar="REGEX", dest="alert_pattern",
                        help="Trigger an alert when a URL matches this regex (repeatable)")
    parser.add_argument("--log-level",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        default="WARNING",
                        help="Set the logging verbosity (default: WARNING)")

    return parser


def _is_privileged() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return True


def _install_signal_handlers() -> None:
    try:
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    except (ValueError, OSError, AttributeError):
        pass


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    # Load TOML config if specified
    if args.config:
        if not os.path.isfile(args.config):
            print(f"error: config file not found: {args.config}", file=sys.stderr)
            return 2
        config = load_config(args.config)
        if config:
            args = _apply_config(args, config)

    color = not args.no_color and sys.stdout.isatty()

    if args.list_interfaces:
        interfaces = list_interfaces()
        if not interfaces:
            print("[!] No interfaces found. Install/configure Npcap (Windows) or libpcap (Linux/macOS).",
                  file=sys.stderr)
            return 1
        for name, description in interfaces:
            print(f"{name}\t{description}")
        return 0

    if args.read and args.mitm:
        print("error: --read and --mitm are mutually exclusive", file=sys.stderr)
        return 2

    if args.output and (args.json or args.csv):
        print("error: --output cannot be combined with --json or --csv", file=sys.stderr)
        return 2
    if args.json and args.format not in (None, "jsonl"):
        print("error: --json writes JSON Lines; use --csv (or --output --format csv) for CSV",
              file=sys.stderr)
        return 2
    if args.csv and args.format not in (None, "csv"):
        print("error: --csv writes CSV; use --json (or --output --format jsonl) for JSON Lines",
              file=sys.stderr)
        return 2

    if not args.interface and not args.read and not args.mitm:
        print("error: one of -i/--interface, --read or --mitm is required "
              "(use --list-interfaces to see options)", file=sys.stderr)
        return 2

    if HTTPRequest is None:
        print("[!] The scapy HTTP layer is unavailable. Upgrade scapy: pip install -U scapy",
              file=sys.stderr)
        return 1

    if args.mitm and not _mitm_available():
        print("[!] mitmproxy is not installed. Install it with: "
              "pip install sniffex[mitm]", file=sys.stderr)
        return 1

    if not args.no_banner:
        display_banner(color=color)
    if args.read:
        if not os.path.isfile(args.read):
            print(f"[!] Capture file not found: {args.read}", file=sys.stderr)
            return 2
    elif not args.mitm and not _is_privileged():
        print(colorize("[!] Warning: not running with elevated privileges — "
                       "packet capture may fail or capture nothing.", Colors.YELLOW, color))

    json_path, csv_path = args.json, args.csv
    if args.output:
        if (args.format or "jsonl") == "csv":
            csv_path = args.output
        else:
            json_path = args.output

    sniffer = Sniffer(
        args.interface,
        read_path=args.read,
        hosts=args.host,
        keywords=args.keyword,
        json_path=json_path,
        csv_path=csv_path,
        pcap_path=args.pcap,
        quiet=args.quiet,
        verbose=args.verbose,
        color=color,
        count=args.count,
        timeout=args.timeout,
        bpf_filter=args.bpf,
        dns_logging=args.dns,
        use_regex=args.regex,
        alert_status_codes=args.alert_status,
        alert_patterns=args.alert_pattern,
        log_level=args.log_level,
    )

    _install_signal_handlers()
    if args.read:
        print(f"[*] Analyzing {args.read}...")
    elif args.mitm:
        _print_mitm_instructions(args.mitm_port, args.mitm_mode)
        if args.interface:
            print(f"[*] Also sniffing on {args.interface}... (Ctrl+C to stop)")
        else:
            print("[*] MITM proxy running... (Ctrl+C to stop)")
    else:
        iface_info = f" on {args.interface}" if args.interface else ""
        bpf_info = f" [BPF: {args.bpf}]" if args.bpf else ""
        dns_info = " [DNS logging]" if args.dns else ""
        print(f"[*] Starting sniffing{iface_info}{bpf_info}{dns_info}... (Ctrl+C to stop)")

    proxy_thread = None
    try:
        if args.mitm and args.interface:
            # Run the decrypting proxy in a background thread, sniff in the main thread.
            proxy_thread = threading.Thread(
                target=sniffer.run_mitm,
                kwargs={"port": args.mitm_port, "mode": args.mitm_mode},
                daemon=True,
            )
            proxy_thread.start()
            sniffer.run(start_stats=args.stats)
        elif args.mitm:
            sniffer.run_mitm(args.mitm_port, args.mitm_mode)
        else:
            sniffer.run(start_stats=args.stats)
    except KeyboardInterrupt:
        print("\n[!] Sniffing interrupted. Exiting gracefully...")
    except scapy.error.Scapy_Exception as exc:
        print(f"[!] Sniffing error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] Unexpected error: {exc}", file=sys.stderr)
        return 1
    finally:
        sniffer.shutdown_mitm()
        if proxy_thread is not None:
            proxy_thread.join(timeout=5)
        sniffer.close()

    sniffer.print_summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
