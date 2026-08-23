#!/usr/bin/env python3
"""Deterministic privacy and content checks for Daily Fetcher reports."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import daily_fetcher_report as report_module


def main() -> int:
    original_paths = (
        report_module.CURRENT_HEALTH_PATH,
        report_module.HISTORICAL_HEALTH_PATH,
        report_module.SNAPSHOT_PATH,
        report_module.STATS_PATH,
    )
    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root / "source_health.json"
            historical = root / "historical_health.json"
            snapshot = root / "latest_threat_intel.json"
            stats = root / "threat_intel_stats.json"
            current.write_text(json.dumps({
                "sourceCount": 5,
                "successfulSources": 4,
                "healthPolicy": {"deferredSources": ["Slow Feed"]},
                "sources": [
                    {"name": "Recovered Feed", "status": "ok", "attempts": 3, "retryRecovered": True, "provenance": "https://private-should-not-appear.example/path"},
                    {"name": "Failed Feed", "status": "failed", "attempts": 3, "error": "secret-like-error-body"},
                ],
            }), encoding="utf-8")
            historical.write_text(json.dumps({"sourceCount": 8, "successfulSources": 6, "sources": []}), encoding="utf-8")
            snapshot.write_text("{}", encoding="utf-8")
            stats.write_text("{}", encoding="utf-8")
            report_module.CURRENT_HEALTH_PATH = current
            report_module.HISTORICAL_HEALTH_PATH = historical
            report_module.SNAPSHOT_PATH = snapshot
            report_module.STATS_PATH = stats

            payload = report_module.report("failure")
            rendered = report_module.markdown(payload)
            serialized = json.dumps(payload)
            assert payload["workflowOutcome"] == "failure"
            assert payload["retryRecoveredSources"] == ["Recovered Feed"]
            assert payload["failedSourceNames"] == ["Failed Feed"]
            assert payload["currentCollection"]["deferredSources"] == ["Slow Feed"]
            assert "private-should-not-appear" not in serialized
            assert "secret-like-error-body" not in serialized
            assert "private-should-not-appear" not in rendered
            assert "secret-like-error-body" not in rendered
            assert "raw indicators" in rendered
    finally:
        (
            report_module.CURRENT_HEALTH_PATH,
            report_module.HISTORICAL_HEALTH_PATH,
            report_module.SNAPSHOT_PATH,
            report_module.STATS_PATH,
        ) = original_paths

    print("Daily fetcher report checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
