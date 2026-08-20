# SniffEx

```text
               ________      _____________________________
               __  ___/_________(_)__  __/__  __/__  ____/___  __
               _____ \__  __ \_  /__  /_ __  /_ __  __/  __  |/_/
               ____/ /_  / / /  / _  __/ _  __/ _  /___  __>  <
               /____/ /_/ /_//_/  /_/    /_/    /_____/  /_/|_|
                        ---- Real-time HTTP Packet Sniffer ----
        ===================================================================
                       Version : 3.0     Twitter : anishalx7
        ===================================================================
```

> **DISCLAIMER:** Use SniffEx **only** on networks you own or have explicit
> written permission to test. Unauthorized traffic interception is illegal in
> most jurisdictions. The author is not responsible for any misuse.

## Overview

**SniffEx** is an advanced real-time HTTP packet sniffer built on [Scapy](https://scapy.readthedocs.io/).
It captures network traffic, extracts HTTP requests and URLs, and flags
potential credentials (usernames, passwords, tokens, cookies, API keys,
AWS keys, Stripe keys, GitHub tokens, JWTs, credit card numbers and more).

It works in multiple modes:

- **Live capture** — sniff packets straight off a network interface.
- **Offline analysis** — read a `.pcap` capture file, no root privileges needed.
- **MITM proxy** — decrypt HTTPS traffic via an embedded mitmproxy.

## Features

### Core
- Real-time HTTP request/response sniffing on any interface.
- Full URL extraction (scheme, host, port, path, query).
- Offline analysis of existing `.pcap` files (`--read`).
- Raw packet capture with `--pcap`.
- Cross-platform interface listing (Linux, macOS, Windows).
- Graceful Ctrl+C shutdown and per-packet error isolation.

### Credential Detection
- **Query strings** (`?user=bob&pass=secret`)
- **Form bodies** (`application/x-www-form-urlencoded`)
- **JSON bodies** (`application/json`, including nested fields)
- **Basic Auth** headers
- **Bearer tokens**
- **Cookies** (`sessionid`, `token`, …)
- **Sensitive headers** (`X-Api-Key`, `X-Auth-Token`, …)
- **AWS Access Key IDs** (`AKIA...`)
- **AWS Secret Access Keys** (matched by name pattern)
- **Stripe API keys** (`sk_live_`, `pk_live_`, `sk_test_`, etc.)
- **GitHub tokens** (`ghp_`, `gho_`, `github_pat_`, etc.)
- **Google API keys** (`AIza...`)
- **JWT tokens** (decoded and claims extracted)
- **Credit card numbers** (Luhn-validated Visa, MC, Amex, etc.)
- **PEM private keys** (RSA, EC, DSA, OpenSSH)
- **GCP service account keys**
- **Connection strings** with embedded passwords
- **HTTP response credentials** (Set-Cookie, auth headers, response body)

### Network Intelligence
- **DNS query/response logging** (`--dns` flag)
- **TLS SNI extraction** from ClientHello (see encrypted hostnames without decryption)
- **BPF filter support** (`--bpf` flag) for custom packet filtering

### Filtering & Alerts
- Host filters (exact, subdomain or `*.wildcard`)
- Keyword filters
- **Regex-based filtering** (`--regex` flag)
- **Alert system** — trigger on specific HTTP status codes (`--alert-status`) or URL patterns (`--alert-pattern`)

### Output
- **JSON Lines** event log (`--json`)
- **CSV** credential findings (`--csv`)
- **Structured output** with format selection (`--format {jsonl,csv}` + `--output`)
- **TOML config file** (`--config`) for reusable settings
- **Live periodic statistics** (`--stats` flag)
- Per-session statistics summary (packets, requests, hosts, methods, statuses, DNS, TLS)

## Requirements

- Python 3.8+
- Scapy **2.5.0+** (the HTTP layer is built into modern Scapy; the deprecated
  `scapy-http` package is **not** needed).
- For **live capture**: Npcap (Windows) or libpcap (Linux/macOS), plus
  elevated privileges (`sudo`).

## Installation

```bash
git clone https://github.com/anishalx/sniffex.git
cd sniffex
pip install -r requirements.txt        # or: pip install -e .
```

### Optional dependencies

```bash
pip install -e ".[mitm]"     # HTTPS decryption via embedded MITM proxy
pip install -e ".[config]"   # TOML config file support (Python <3.11)
```

## Usage

### List available interfaces

```bash
python3 sniffex.py --list-interfaces
```

### Live sniffing

```bash
sudo python3 sniffex.py -i eth0
```

### Offline analysis (no root needed)

```bash
python3 sniffex.py --read capture.pcap
```

### BPF filter

```bash
sudo python3 sniffex.py -i eth0 --bpf "tcp port 80"
sudo python3 sniffex.py -i eth0 --bpf "host 10.0.0.1 and tcp port 443"
```

### DNS logging

```bash
sudo python3 sniffex.py -i eth0 --dns -v
```

### TLS SNI extraction (see encrypted hostnames)

```bash
sudo python3 sniffex.py -i eth0 -v
# TLS SNI connections are automatically detected and logged
```

### Alerts

```bash
# Alert on 401/403 responses
sudo python3 sniffex.py -i eth0 --alert-status 401 --alert-status 403

# Alert on URLs matching a regex pattern
sudo python3 sniffex.py -i eth0 --alert-pattern '/admin' --alert-pattern '/secret'
```

### Regex-based filtering

```bash
# Only show requests matching regex patterns
sudo python3 sniffex.py -i eth0 --host 'api\.example\.com' --regex
sudo python3 sniffex.py -i eth0 --keyword 'log.*in' --regex
```

### HTTPS decryption (MITM proxy)

```bash
pip install -e ".[mitm]"
sudo python3 sniffex.py --mitm --mitm-port 8080
```

1. The proxy listens on `0.0.0.0:8080` and generates its CA certificate at
   `~/.mitmproxy/mitmproxy-ca-cert.pem`.
2. **Install that CA certificate on the target device** (trust it as a root
   CA) so the decrypted TLS sessions are accepted.
3. Point the target's traffic at this host:
   - **Explicit proxy**: set the target's HTTP(S) proxy to `<this-host-ip>:8080`
     (default `--mitm-mode regular`), or
   - **Transparent**: `--mitm-mode transparent` with IP forwarding and
     `iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080`

### TOML configuration file

Create a `config.toml`:

```toml
[sniffer]
interface = "eth0"
dns = true
bpf = "tcp port 80"
timeout = 60

[filters]
host = ["example.com", "*.github.com"]
keyword = ["login", "admin"]

[output]
json = "events.jsonl"
pcap = "capture.pcap"

[alerts]
status = [401, 403]
pattern = ["/admin", "/secret"]
stats = true
```

```bash
sudo python3 sniffex.py --config config.toml
```

CLI arguments override config file values.

### Filters

```bash
# Only requests to example.com (and subdomains) or *.github.com
sudo python3 sniffex.py -i eth0 --host example.com --host '*.github.com'

# Only requests whose URL or body mentions "login"
sudo python3 sniffex.py -i eth0 --keyword login
```

### Output to files

```bash
# JSON Lines event log + raw pcap of everything seen
sudo python3 sniffex.py -i eth0 --json traffic.jsonl --pcap raw.pcap

# Credential findings as CSV (one row per finding)
sudo python3 sniffex.py -i eth0 --csv findings.csv

# Or pick the format explicitly with --format + --output
sudo python3 sniffex.py -i eth0 --format csv --output findings.csv
```

### Stop conditions

```bash
# Stop after 10 matching HTTP requests, or after 60 seconds, whichever first
sudo python3 sniffex.py -i eth0 --count 10 --timeout 60
```

### Verbosity & live stats

```bash
sudo python3 sniffex.py -i eth0 -v              # show headers, DNS, TLS info
sudo python3 sniffex.py -i eth0 -q              # quiet mode; files still written
sudo python3 sniffex.py -i eth0 --no-color      # plain text output
sudo python3 sniffex.py -i eth0 --stats         # periodic live statistics
```

### Example output

```text
[+] GET http://example.com/login?user=bob&pass=secret  (10.0.0.5:54321 -> 93.184.216.34:80)
[!] Possible credentials (QUERY) >> user=bob&pass=secret
[+] POST http://example.com/api/login  (10.0.0.5:54322 -> 93.184.216.34:80)
[!] Possible credentials (FORM) >> password=wonderland
[!!!] ALERT: URL matches pattern - POST http://example.com/admin/secret
[D] DNS REQ A www.example.com (10.0.0.5:54321 -> 8.8.8.8:53)
[T] TLS SNI=api.github.com ALPN=[h2,http/1.1] (10.0.0.5:54323 -> 140.82.121.3:443)
[!] Possible credentials (AWS_KEY) >> access_key_id=AKIAIOSFODNN7EXAMPLE
[!] Possible credentials (JWT) >> sub=user123&email=test@example.com
[!] Response credential (RESPONSE_COOKIE) >> sessionid=abc123
```

At exit, a summary is printed:

```text
=== SniffEx Summary ===
Duration:           12.3s
Packets seen:       1842
HTTP requests:      37
HTTP responses:     31
DNS queries:        156
TLS connections:    42
Credential hits:    4
Alerts triggered:   2
Bytes captured:     204,800
Top hosts:
  example.com                               31
Methods: GET=24, POST=13
Statuses: 200=28, 401=2, 403=1
TLS hostnames seen: 12
```

## JSON Lines format

With `--json FILE`, every HTTP request is appended as one JSON object per
line, e.g.:

```json
{"ts": "2024-09-29T10:15:30+00:00", "type": "http_request", "method": "GET",
 "url": "http://example.com/login?user=bob&pass=secret", "host": "example.com",
 "src": "10.0.0.5:54321", "dst": "93.184.216.34:80",
 "headers": [{"name": "Host", "value": "example.com"}],
 "body": "", "findings": [{"kind": "query", "fields": {"user": "bob", "pass": "secret"}, "raw": ""}]}
```

DNS and TLS events are also logged:

```json
{"ts": "2024-09-29T10:15:31+00:00", "type": "dns_query", "query_name": "example.com", "query_type": "A", "is_response": false}
{"ts": "2024-09-29T10:15:32+00:00", "type": "tls_hello", "sni": "api.github.com", "alpn": ["h2", "http/1.1"]}
```

## CLI Reference

```
sniffex [-i IFACE | --read FILE | --mitm] [OPTIONS]

Network:
  -i, --interface IFACE   Network interface to sniff
  --read FILE             Analyze packets from a pcap file
  --mitm                  Run embedded MITM proxy for HTTPS decryption
  --mitm-port PORT        MITM proxy listen port (default: 8080)
  --mitm-mode {regular,transparent}
  --bpf FILTER            BPF filter expression (e.g. 'tcp port 80')
  --dns                   Enable DNS query/response logging

Filters:
  --host HOST             Only show requests to HOST (repeatable)
  --keyword WORD          Only show requests matching WORD (repeatable)
  --regex                 Treat --host/--keyword as regular expressions

Output:
  --json FILE             Append JSON Lines events to FILE
  --csv FILE              Append credential findings as CSV to FILE
  --pcap FILE             Write captured packets to FILE
  --format {jsonl,csv}    Output format for --output
  --output FILE           Write structured output to FILE

Alerts:
  --alert-status CODE     Alert on this HTTP status code (repeatable)
  --alert-pattern REGEX   Alert when URL matches this regex (repeatable)

Control:
  --count N               Stop after N matching HTTP requests
  --timeout SECONDS       Stop after SECONDS
  -q, --quiet             Suppress console output
  -v, --verbose           Show headers, DNS, and TLS info
  --stats                 Display periodic live statistics

Config & display:
  --config FILE           Load settings from a TOML file
  --no-color              Disable ANSI colors
  --no-banner             Suppress startup banner
  --log-level {DEBUG,INFO,WARNING,ERROR}
  --version               Show version
  --list-interfaces       List available interfaces
```

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
```

The test suite builds synthetic Scapy packets — no live capture, no root
privileges, and it runs on Linux, macOS and Windows. It includes **121 tests**
covering URL extraction, credential detection (including AWS/Stripe/GitHub/JWT/credit
cards), DNS logging, TLS SNI extraction, alert system, TOML config loading,
regex filtering, CSV/JSON output, MITM proxy integration, and more.

## What's new in v3.0

- **BPF filter support** (`--bpf`) for custom packet filtering at capture time.
- **Enhanced credential detection**: AWS keys, Stripe API keys, GitHub tokens, Google API keys, JWT deep inspection (payload decoding), credit card numbers (Luhn-validated), PEM private keys, GCP service account keys, connection strings with embedded passwords.
- **HTTP response credential extraction**: Set-Cookie, auth headers, and body scanning for response packets.
- **DNS query/response logging** (`--dns` flag) — capture and display DNS traffic alongside HTTP.
- **TLS SNI extraction** — see encrypted hostnames from TLS ClientHello without decryption.
- **TOML config file support** (`--config`) for reusable configuration.
- **Alert system** — trigger on HTTP status codes (`--alert-status`) or URL regex patterns (`--alert-pattern`).
- **Regex-based filtering** (`--regex`) for host and keyword filters.
- **Live periodic statistics** (`--stats` flag) during capture.
- **Improved logging** with Python's `logging` module.
- **Bytes captured** tracking in statistics.
- **121 tests** (up from 64), including DNS, TLS, alerts, config, regex, and enhanced credential tests.
- Version bumped to 3.0.0.

## Contributing

1. Fork the repository.
2. Create a branch (`git checkout -b feature/YourFeature`).
3. Make your changes, add tests, and run `python -m pytest`.
4. Push and open a pull request.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- [Scapy](https://scapy.readthedocs.io/) — the packet manipulation library this
  tool is built on.
- Inspired by various network scanning tools and the open-source community.
