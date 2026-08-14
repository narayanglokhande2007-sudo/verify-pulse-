#!/usr/bin/env python3
"""Deterministic unit tests for VerifyPulse threat-intelligence fusion."""

from datetime import datetime, timezone

from build_threat_intelligence import build_snapshot

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=timezone.utc)
RECORDS = [
    {
        "url": "https://hdfc-login.example/verify?token=should-not-be-kept",
        "source": "https://urlhaus.abuse.ch/downloads/text/",
        "date_added": "2026-08-14T10:00:00+00:00",
    },
    {
        "url": "hdfc-login.example/verify",
        "source": "https://www.phishtank.com/",
        "date_added": "2026-08-14T11:00:00+00:00",
    },
    {
        "url": "https://expired.example/path",
        "source": "https://openphish.com/feed.txt",
        "date_added": "2026-06-01T00:00:00+00:00",
    },
    {
        "url": "http://127.0.0.1/private",
        "source": "https://urlhaus.abuse.ch/downloads/text/",
        "date_added": "2026-08-14T11:00:00+00:00",
    },
]

snapshot, stats = build_snapshot(RECORDS, now=NOW)
assert snapshot["schemaVersion"] == "vp-threat-intel-1"
assert snapshot["indicatorCount"] == 1
assert stats["processedRecords"] == 4
assert stats["rejectedRecords"] == 1

indicator = snapshot["indicators"][0]
assert indicator["indicator"] == "https://hdfc-login.example/verify"
assert indicator["indicatorType"] == "url"
assert indicator["sourceCount"] == 2
assert indicator["confidence"] == 99
assert set(indicator["sources"]) == {"URLhaus", "PhishTank"}
assert "token" not in indicator["indicator"]

print("Threat-intelligence fusion suite passed: 1 corroborated active indicator, 1 expired indicator skipped, 1 private indicator rejected.")
