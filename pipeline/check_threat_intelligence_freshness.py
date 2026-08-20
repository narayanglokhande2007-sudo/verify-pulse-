#!/usr/bin/env python3
"""Fail-closed health gate for the published VerifyPulse threat-intelligence snapshot.

This checker does not fetch feeds and does not modify data. It validates that the
already-built runtime snapshot is recent, internally coherent, and contains active
indicators before an automation workflow stages it for publication.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SNAPSHOT_PATH = ROOT / "daily-data" / "latest_threat_intel.json"
STATS_PATH = ROOT / "daily-data" / "threat_intel_stats.json"
EXPECTED_SCHEMA = "vp-threat-intel-1"


def parse_timestamp(value: Any, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing {field_name}")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"missing required file: {path.name}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return payload


def validate(*, max_age_hours: int, minimum_indicators: int, require_same_day: bool) -> dict[str, Any]:
    checked_at = datetime.now(timezone.utc)
    issues: list[dict[str, str]] = []
    summary: dict[str, Any] = {
        "checkedAt": checked_at.isoformat(),
        "maxAgeHours": max_age_hours,
        "minimumIndicators": minimum_indicators,
        "requireSameDay": require_same_day,
        "valid": False,
        "issues": issues,
    }

    try:
        snapshot = load_json(SNAPSHOT_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        issues.append({"file": SNAPSHOT_PATH.name, "issue": str(error)})
        return summary
    try:
        stats = load_json(STATS_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        issues.append({"file": STATS_PATH.name, "issue": str(error)})
        return summary

    generated_at: datetime | None = None
    expires_at: datetime | None = None
    try:
        generated_at = parse_timestamp(snapshot.get("generatedAt"), "snapshot generatedAt")
        expires_at = parse_timestamp(snapshot.get("expiresAt"), "snapshot expiresAt")
        stats_generated_at = parse_timestamp(stats.get("generatedAt"), "stats generatedAt")
        age_hours = max(0.0, (checked_at - generated_at).total_seconds() / 3600)
        summary.update({
            "generatedAt": generated_at.isoformat(),
            "expiresAt": expires_at.isoformat(),
            "ageHours": round(age_hours, 3),
            "statsGeneratedAt": stats_generated_at.isoformat(),
        })
        if age_hours > max_age_hours:
            issues.append({"file": SNAPSHOT_PATH.name, "issue": f"snapshot age {age_hours:.2f}h exceeds {max_age_hours}h"})
        if require_same_day and generated_at.date() != checked_at.date():
            issues.append({"file": SNAPSHOT_PATH.name, "issue": "snapshot was not generated today (UTC)"})
        if expires_at <= checked_at:
            issues.append({"file": SNAPSHOT_PATH.name, "issue": "snapshot is expired"})
        if abs((stats_generated_at - generated_at).total_seconds()) > 300:
            issues.append({"file": STATS_PATH.name, "issue": "stats generatedAt does not match snapshot within 5 minutes"})
    except ValueError as error:
        issues.append({"file": "metadata", "issue": str(error)})

    if snapshot.get("schemaVersion") != EXPECTED_SCHEMA:
        issues.append({"file": SNAPSHOT_PATH.name, "issue": "unexpected schemaVersion"})
    if stats.get("schemaVersion") != EXPECTED_SCHEMA:
        issues.append({"file": STATS_PATH.name, "issue": "unexpected schemaVersion"})

    indicators = snapshot.get("indicators")
    declared_count = snapshot.get("indicatorCount")
    if not isinstance(indicators, list):
        issues.append({"file": SNAPSHOT_PATH.name, "issue": "indicators must be a list"})
        indicators = []
    if not isinstance(declared_count, int) or declared_count != len(indicators):
        issues.append({"file": SNAPSHOT_PATH.name, "issue": "indicatorCount does not match indicators"})

    active = 0
    malformed = 0
    for indicator in indicators:
        if not isinstance(indicator, dict) or not isinstance(indicator.get("indicator"), str) or not indicator.get("indicator"):
            malformed += 1
            continue
        try:
            indicator_expiry = parse_timestamp(indicator.get("expiresAt"), "indicator expiresAt")
            if indicator_expiry > checked_at:
                active += 1
        except ValueError:
            malformed += 1
    if malformed:
        issues.append({"file": SNAPSHOT_PATH.name, "issue": f"{malformed} malformed indicator records"})
    if active < minimum_indicators:
        issues.append({"file": SNAPSHOT_PATH.name, "issue": f"only {active} active indicators; need {minimum_indicators}"})

    summary.update({
        "publishedIndicators": len(indicators),
        "activeIndicators": active,
        "processedRecords": stats.get("processedRecords"),
        "valid": not issues,
    })
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate VerifyPulse published threat-intelligence freshness")
    parser.add_argument("--max-age-hours", type=int, default=30, help="Maximum allowed snapshot age in hours")
    parser.add_argument("--min-active-indicators", type=int, default=1, help="Minimum non-expired indicators required")
    parser.add_argument("--require-same-day", action="store_true", help="Require snapshot generation on the current UTC date")
    args = parser.parse_args()
    if args.max_age_hours < 1 or args.max_age_hours > 168:
        parser.error("--max-age-hours must be between 1 and 168")
    if args.min_active_indicators < 1:
        parser.error("--min-active-indicators must be at least 1")

    report = validate(
        max_age_hours=args.max_age_hours,
        minimum_indicators=args.min_active_indicators,
        require_same_day=args.require_same_day,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
