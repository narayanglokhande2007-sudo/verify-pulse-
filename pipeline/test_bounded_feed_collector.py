#!/usr/bin/env python3
"""Deterministic checks for VerifyPulse's compact bounded feed collector."""

from __future__ import annotations

import sys

import fetch_indian_bulk_scams as collector


def main() -> int:
    assert len(collector.SOURCE_CATALOG) == 5, collector.SOURCE_CATALOG
    assert collector.DEFAULT_MAX_RECORDS_PER_SOURCE <= 600
    assert collector.MAX_RESPONSE_BYTES <= 2 * 1024 * 1024
    assert collector.REQUEST_TIMEOUT_SECONDS <= 12

    assert collector.canonical_indicator("https://safe-example.test/path?token=remove#fragment") == "https://safe-example.test/path"
    assert collector.canonical_indicator("0.0.0.0 phishing-example.test") == "https://phishing-example.test"
    assert collector.canonical_indicator("http://user:pass@example.test/") is None
    assert collector.canonical_indicator("http://127.0.0.1/private") is None
    assert collector.canonical_indicator("http://10.0.0.1/private") is None
    assert collector.canonical_indicator("localhost") is None
    assert collector.canonical_indicator("# comment") is None

    assert collector.india_related("https://fake-sbi-kyc.example.in/login")
    assert not collector.india_related("https://ordinary-example.test/path")

    print("Bounded feed collector checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
