#!/usr/bin/env python3
"""Create a privacy-safe Daily Indian Scam Fetcher run report.

The report intentionally contains only operational counts, source names, bounded
attempt metadata, and validation-file presence. It never includes raw URLs,
raw feed responses, user submissions, API keys, or provider error bodies.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "daily-data"
CURRENT_HEALTH_PATH = DATA_DIR / "source_health.json"
HISTORICAL_HEALTH_PATH = DATA_DIR / "historical-reputation-index" / "source_health.json"
SNAPSHOT_PATH = DATA_DIR / "latest_threat_intel.json"
STATS_PATH = DATA_DIR / "threat_intel_stats.json"
REPORT_SCHEMA = "vp-daily-fetcher-run-report-1"


def load_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None, "missing-or-invalid"
    return payload if isinstance(payload, dict) else None, None


def source_summary(payload: dict[str, Any] | None) -> dict[str, Any]:
    if not payload:
        return {"available": False, "sourceCount": 0, "successfulSources": 0, "sources": []}
    rows = payload.get("sources", [])
    if not isinstance(rows, list):
        rows = []
    sources = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str):
            continue
        sources.append({
            "name": row["name"],
            "status": row.get("status") if isinstance(row.get("status"), str) else "unknown",
            "attempts": row.get("attempts") if isinstance(row.get("attempts"), int) else 0,
            "retryRecovered": bool(row.get("retryRecovered")),
        })
    return {
        "available": True,
        "sourceCount": payload.get("sourceCount") if isinstance(payload.get("sourceCount"), int) else len(sources),
        "successfulSources": payload.get("successfulSources") if isinstance(payload.get("successfulSources"), int) else 0,
        "sources": sources,
        "deferredSources": (
            payload.get("healthPolicy", {}).get("deferredSources", [])
            if isinstance(payload.get("healthPolicy"), dict) and isinstance(payload["healthPolicy"].get("deferredSources", []), list)
            else []
        ),
    }


def report(outcome: str) -> dict[str, Any]:
    current_payload, current_error = load_json(CURRENT_HEALTH_PATH)
    historical_payload, historical_error = load_json(HISTORICAL_HEALTH_PATH)
    _, snapshot_error = load_json(SNAPSHOT_PATH)
    _, stats_error = load_json(STATS_PATH)
    current = source_summary(current_payload)
    historical = source_summary(historical_payload)
    recovered = [item["name"] for item in current["sources"] if item["retryRecovered"]]
    failed = [item["name"] for item in current["sources"] if item["status"] == "failed"]
    return {
        "schemaVersion": REPORT_SCHEMA,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "workflowOutcome": outcome if outcome in {"success", "failure", "cancelled"} else "unknown",
        "currentCollection": current,
        "historicalCollection": historical,
        "retryRecoveredSources": recovered,
        "failedSourceNames": failed,
        "validationFiles": {
            "currentThreatSnapshot": "available" if not snapshot_error else snapshot_error,
            "currentThreatStats": "available" if not stats_error else stats_error,
        },
        "reportLimits": "No raw URLs, raw feed responses, user submissions, API keys, or provider error bodies are included.",
        "inputReadErrors": {
            "currentSourceHealth": current_error,
            "historicalSourceHealth": historical_error,
        },
    }


def markdown(payload: dict[str, Any]) -> str:
    current = payload["currentCollection"]
    historical = payload["historicalCollection"]
    lines = [
        "## VerifyPulse Daily Fetcher Report",
        "",
        f"- **Run outcome:** `{payload['workflowOutcome']}`",
        f"- **Current public feeds:** {current['successfulSources']}/{current['sourceCount']} usable",
        f"- **Historical public feeds:** {historical['successfulSources']}/{historical['sourceCount']} usable",
        f"- **Recovered after retry:** {', '.join(payload['retryRecoveredSources']) or 'none'}",
        f"- **Deferred for one run:** {', '.join(current['deferredSources']) or 'none'}",
        f"- **Failed sources:** {', '.join(payload['failedSourceNames']) or 'none'}",
        f"- **Threat snapshot file:** {payload['validationFiles']['currentThreatSnapshot']}",
        f"- **Threat stats file:** {payload['validationFiles']['currentThreatStats']}",
        "",
        "> This operational report intentionally excludes raw indicators, raw source responses, user content, API keys, and provider error bodies.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Write a privacy-safe Daily Fetcher operational report")
    parser.add_argument("--outcome", default="unknown", help="GitHub job outcome: success, failure, or cancelled")
    parser.add_argument("--github-summary", type=Path, help="Optional GitHub Actions summary file")
    parser.add_argument("--output", type=Path, help="Optional temporary JSON output path")
    args = parser.parse_args()

    payload = report(args.outcome)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.github_summary:
        args.github_summary.parent.mkdir(parents=True, exist_ok=True)
        with args.github_summary.open("a", encoding="utf-8") as handle:
            handle.write(markdown(payload))
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
