"""Regression tests for SniffEx robustness fixes.

1. Concurrent request processing (MITM proxy thread + capture thread in
   ``--mitm --interface`` mode) must never interleave JSON/CSV rows or lose
   stat counter updates.
2. An invalid ``--alert-pattern`` regex must be rejected up front instead of
   raising on every request and silently dropping request processing.
"""

import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sniffex import (  # noqa: E402
    CredentialFinding,
    RequestInfo,
    Sniffer,
)


def _make_info(url="http://example.com/login", body=""):
    """Build a RequestInfo that passes filtering and yields no credentials."""
    return RequestInfo(
        method="GET",
        url=url,
        host="example.com",
        src="10.0.0.1:5000",
        dst="93.184.216.34:80",
        headers=[("Host", "example.com")],
        body=body,
        findings=[],
    )


class TestConcurrentOutput:
    """Shared output files and counters survive concurrent processing."""

    def test_concurrent_json_output_is_not_corrupted(self, tmp_path):
        log = tmp_path / "events.jsonl"
        sniffer = Sniffer("eth0", json_path=str(log))
        errors = []
        total = 200

        def worker(start):
            try:
                for i in range(start, start + total // 2):
                    sniffer.process_request_info(
                        _make_info(url=f"http://example.com/p{i}")
                    )
            except Exception as exc:  # pragma: no cover - failure surfaced below
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(0,)),
            threading.Thread(target=worker, args=(total // 2,)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        sniffer.close()

        assert errors == []
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == total
        # Every line must be complete, valid JSON (no interleaved writes).
        for line in lines:
            record = json.loads(line)
            assert record["type"] == "http_request"
            assert record["host"] == "example.com"
        assert sniffer.stats.http_requests == total

    def test_concurrent_stats_are_not_lost(self, tmp_path):
        log = tmp_path / "events.jsonl"
        sniffer = Sniffer("eth0", json_path=str(log), quiet=True)
        total = 100

        def worker():
            for _ in range(total):
                sniffer.process_request_info(_make_info())

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        sniffer.close()

        # All 400 processed requests must be counted exactly once.
        assert sniffer.stats.http_requests == total * 4
        assert sniffer.stats.hosts["example.com"] == total * 4


class TestAlertPatternValidation:
    """Invalid --alert-pattern regexes are ignored, not fatal."""

    def test_invalid_pattern_is_dropped_at_construction(self):
        sniffer = Sniffer("eth0", alert_patterns=["(", "valid-pattern"])
        assert sniffer.alert_patterns == ["valid-pattern"]

    def test_invalid_pattern_does_not_break_request_processing(self, tmp_path):
        log = tmp_path / "events.jsonl"
        sniffer = Sniffer(
            "eth0", json_path=str(log), quiet=True, alert_patterns=["("]
        )
        sniffer.process_request_info(_make_info())
        sniffer.close()

        assert sniffer.stats.http_requests == 1
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1

    def test_valid_pattern_still_alerts(self, capsys):
        sniffer = Sniffer("eth0", color=False, alert_patterns=[r"/admin"])
        sniffer.process_request_info(_make_info(url="http://example.com/admin"))
        sniffer.close()

        assert sniffer.stats.alert_count == 1
        assert "ALERT" in capsys.readouterr().out

    def test_credential_findings_survive_locking(self, tmp_path):
        """Credential-carrying requests still emit CSV rows under the lock."""
        csv_path = tmp_path / "creds.csv"
        sniffer = Sniffer("eth0", csv_path=str(csv_path), quiet=True)
        info = _make_info()
        info.findings = [
            CredentialFinding(
                kind="query",
                fields={"password": "hunter2"},
                raw="password=hunter2",
            )
        ]
        sniffer.process_request_info(info)
        sniffer.close()

        assert sniffer.stats.credential_findings == 1
        content = csv_path.read_text(encoding="utf-8")
        assert "password=hunter2" in content
