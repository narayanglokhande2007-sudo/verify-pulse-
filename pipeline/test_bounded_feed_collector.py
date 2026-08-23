#!/usr/bin/env python3
"""Deterministic checks for VerifyPulse's compact bounded feed collector."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from urllib.error import HTTPError

import fetch_indian_bulk_scams as collector
import source_health_policy as health_policy
import daily_fetcher_report as daily_report_tests
import test_daily_fetcher_restore as restore_point_tests
import test_source_health_policy as health_policy_tests


class FakeResponse:
    def __init__(self, content: bytes):
        self.content = content

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_: object) -> bool:
        return False

    def read(self, _: int) -> bytes:
        return self.content


def test_retry_recovers_only_from_transient_failure() -> None:
    original_urlopen = collector.urlopen
    original_sleep = collector.time.sleep
    calls: list[int] = []
    delays: list[int] = []

    def flaky_urlopen(_: object, *, timeout: int) -> FakeResponse:
        calls.append(timeout)
        if len(calls) < 3:
            raise TimeoutError("temporary upstream timeout")
        return FakeResponse(b"https://fake-sbi-kyc.example.in/login\n")

    try:
        collector.urlopen = flaky_urlopen
        collector.time.sleep = delays.append
        records, health = collector.fetch_source(
            "https://example.test/feed.txt",
            "Test Source",
            max_records=10,
            observed_at="2026-08-23T00:00:00+00:00",
        )
    finally:
        collector.urlopen = original_urlopen
        collector.time.sleep = original_sleep

    assert len(records) == 1
    assert health["status"] == "ok"
    assert health["attempts"] == 3
    assert health["retryRecovered"] is True
    assert calls == [collector.REQUEST_TIMEOUT_SECONDS] * 3
    assert delays == list(collector.RETRY_BACKOFF_SECONDS)


def test_non_retryable_failure_stops_without_retries() -> None:
    original_urlopen = collector.urlopen
    original_sleep = collector.time.sleep
    calls: list[int] = []
    delays: list[int] = []

    def missing_urlopen(_: object, *, timeout: int) -> FakeResponse:
        calls.append(timeout)
        raise HTTPError("https://example.test/feed.txt", 404, "not found", hdrs=None, fp=None)

    try:
        collector.urlopen = missing_urlopen
        collector.time.sleep = delays.append
        records, health = collector.fetch_source(
            "https://example.test/feed.txt",
            "Test Source",
            max_records=10,
            observed_at="2026-08-23T00:00:00+00:00",
        )
    finally:
        collector.urlopen = original_urlopen
        collector.time.sleep = original_sleep

    assert records == []
    assert health["status"] == "failed"
    assert health["attempts"] == 1
    assert health["retryRecovered"] is False
    assert health["retryableFailure"] is False
    assert calls == [collector.REQUEST_TIMEOUT_SECONDS]
    assert delays == []


def test_cooldown_never_bypasses_minimum_sources() -> None:
    original_catalog = collector.SOURCE_CATALOG
    original_fetch_source = collector.fetch_source
    original_paths = (
        collector.INDIA_OUTPUT,
        collector.GLOBAL_OUTPUT,
        collector.LATEST_OUTPUT,
        collector.HEALTH_OUTPUT,
        collector.HEALTH_HISTORY_OUTPUT,
    )
    catalog = (
        ("https://first.example/feed", "First"),
        ("https://second.example/feed", "Second"),
        ("https://third.example/feed", "Third"),
        ("https://fourth.example/feed", "Fourth"),
    )
    fetched_names: list[str] = []

    def healthy_fetch(url: str, name: str, *, max_records: int, observed_at: str) -> tuple[list[dict[str, str]], dict[str, object]]:
        fetched_names.append(name)
        return [{"url": f"https://{name.lower()}.example/path", "source": url, "type": "test", "date_added": observed_at}], {
            "name": name,
            "provenance": url,
            "checkedAt": observed_at,
            "status": "ok",
            "acceptedRecords": 1,
            "bytesRead": 1,
            "truncated": False,
            "attempts": 1,
            "retryRecovered": False,
        }

    try:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary)
            history = health_policy.empty_history()
            history["sources"]["First"] = {
                "consecutiveFailures": health_policy.FAILURES_BEFORE_COOLDOWN,
                "cooldownRunsRemaining": 1,
                "recentOutcomes": [],
            }
            (data_dir / "source_health_history.json").write_text(json.dumps(history), encoding="utf-8")
            collector.SOURCE_CATALOG = catalog
            collector.fetch_source = healthy_fetch
            collector.INDIA_OUTPUT = data_dir / "india_scams.jsonl"
            collector.GLOBAL_OUTPUT = data_dir / "global_scams.jsonl"
            collector.LATEST_OUTPUT = data_dir / "latest_scams.json"
            collector.HEALTH_OUTPUT = data_dir / "source_health.json"
            collector.HEALTH_HISTORY_OUTPUT = data_dir / "source_health_history.json"
            result = collector.collect(max_records_per_source=10, minimum_successful_sources=2)

            assert result["successfulSources"] == 3
            assert result["healthPolicy"]["deferredSources"] == ["First"]
            assert "First" not in fetched_names
            assert set(fetched_names) == {"Second", "Third", "Fourth"}
            updated_history = json.loads((data_dir / "source_health_history.json").read_text(encoding="utf-8"))
            assert updated_history["sources"]["First"]["cooldownRunsRemaining"] == 0
    finally:
        collector.SOURCE_CATALOG = original_catalog
        collector.fetch_source = original_fetch_source
        (
            collector.INDIA_OUTPUT,
            collector.GLOBAL_OUTPUT,
            collector.LATEST_OUTPUT,
            collector.HEALTH_OUTPUT,
            collector.HEALTH_HISTORY_OUTPUT,
        ) = original_paths


def main() -> int:
    assert len(collector.SOURCE_CATALOG) == 5, collector.SOURCE_CATALOG
    assert collector.DEFAULT_MAX_RECORDS_PER_SOURCE <= 600
    assert collector.MAX_RESPONSE_BYTES <= 2 * 1024 * 1024
    assert collector.REQUEST_TIMEOUT_SECONDS <= 12
    assert collector.MAX_FETCH_ATTEMPTS == 3
    assert collector.RETRY_BACKOFF_SECONDS == (1, 2)

    assert collector.canonical_indicator("https://safe-example.test/path?token=remove#fragment") == "https://safe-example.test/path"
    assert collector.canonical_indicator("0.0.0.0 phishing-example.test") == "https://phishing-example.test"
    assert collector.canonical_indicator("http://user:pass@example.test/") is None
    assert collector.canonical_indicator("http://127.0.0.1/private") is None
    assert collector.canonical_indicator("http://10.0.0.1/private") is None
    assert collector.canonical_indicator("localhost") is None
    assert collector.canonical_indicator("# comment") is None

    assert collector.india_related("https://fake-sbi-kyc.example.in/login")
    assert not collector.india_related("https://ordinary-example.test/path")

    test_retry_recovers_only_from_transient_failure()
    test_non_retryable_failure_stops_without_retries()
    test_cooldown_never_bypasses_minimum_sources()
    health_policy_tests.main()
    daily_report_tests.main()
    restore_point_tests.main()

    print("Bounded feed collector checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
