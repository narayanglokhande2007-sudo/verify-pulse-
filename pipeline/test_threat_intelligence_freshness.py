#!/usr/bin/env python3
"""Deterministic regression checks for the published threat-intelligence health gate."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import check_threat_intelligence_freshness as gate


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def snapshot(generated: datetime, expires: datetime, indicator_expires: datetime, count: int = 1) -> dict:
    indicators = [{
        "indicator": "https://example.test/path",
        "indicatorType": "url",
        "expiresAt": indicator_expires.isoformat(),
    } for _ in range(count)]
    return {
        "schemaVersion": "vp-threat-intel-1",
        "generatedAt": generated.isoformat(),
        "expiresAt": expires.isoformat(),
        "indicatorCount": count,
        "indicators": indicators,
    }


def stats(generated: datetime) -> dict:
    return {"schemaVersion": "vp-threat-intel-1", "generatedAt": generated.isoformat(), "processedRecords": 1}


def main() -> int:
    original_snapshot = gate.SNAPSHOT_PATH
    original_stats = gate.STATS_PATH
    now = datetime.now(timezone.utc)
    try:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gate.SNAPSHOT_PATH = root / "latest_threat_intel.json"
            gate.STATS_PATH = root / "threat_intel_stats.json"

            write_json(gate.SNAPSHOT_PATH, snapshot(now, now + timedelta(hours=24), now + timedelta(days=1)))
            write_json(gate.STATS_PATH, stats(now))
            healthy = gate.validate(max_age_hours=30, minimum_indicators=1, require_same_day=True)
            assert healthy["valid"], healthy
            assert healthy["activeIndicators"] == 1

            write_json(gate.SNAPSHOT_PATH, snapshot(now - timedelta(hours=31), now + timedelta(hours=1), now + timedelta(days=1)))
            write_json(gate.STATS_PATH, stats(now - timedelta(hours=31)))
            stale = gate.validate(max_age_hours=30, minimum_indicators=1, require_same_day=False)
            assert not stale["valid"]
            assert any("exceeds" in item["issue"] for item in stale["issues"])

            write_json(gate.SNAPSHOT_PATH, snapshot(now, now - timedelta(minutes=1), now - timedelta(minutes=1)))
            write_json(gate.STATS_PATH, stats(now))
            expired = gate.validate(max_age_hours=30, minimum_indicators=1, require_same_day=True)
            assert not expired["valid"]
            assert any("expired" in item["issue"] for item in expired["issues"])

            write_json(gate.SNAPSHOT_PATH, snapshot(now, now + timedelta(hours=24), now + timedelta(days=1), count=2))
            write_json(gate.STATS_PATH, stats(now))
            mismatch = gate.validate(max_age_hours=30, minimum_indicators=3, require_same_day=True)
            assert not mismatch["valid"]
            assert any("only 2 active indicators" in item["issue"] for item in mismatch["issues"])
    finally:
        gate.SNAPSHOT_PATH = original_snapshot
        gate.STATS_PATH = original_stats

    print("Threat-intelligence freshness gate checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
