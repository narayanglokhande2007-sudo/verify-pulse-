#!/usr/bin/env python3
"""Deterministic checks for VerifyPulse's compact bounded feed collector."""

from __future__ import annotations

import sys
from urllib.error import HTTPError

import fetch_indian_bulk_scams as collector


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

    print("Bounded feed collector checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
