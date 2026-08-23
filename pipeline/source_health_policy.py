#!/usr/bin/env python3
"""Deterministic, privacy-safe health policy for public threat-feed sources.

The policy can change the order in which sources are tried and can defer a source
for one run only after repeated failures *and* after three other sources have
already succeeded in the current run. It never treats a deferred source as
successful and never relaxes the collector's minimum-source requirement.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "vp-source-health-history-1"
MAX_RECENT_OUTCOMES = 14
FAILURES_BEFORE_COOLDOWN = 3
HEALTHY_SOURCES_BEFORE_DEFERRAL = 3


def empty_history() -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "sources": {},
    }


def _integer(value: Any, default: int = 0) -> int:
    return value if isinstance(value, int) and value >= 0 else default


def load_history(path: Path) -> tuple[dict[str, Any], str]:
    """Load compact historical health state without trusting malformed input."""
    if not path.is_file():
        return empty_history(), "new"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return empty_history(), "reset-invalid-history"
    if payload.get("schemaVersion") != SCHEMA_VERSION or not isinstance(payload.get("sources"), dict):
        return empty_history(), "reset-invalid-history"
    return payload, "loaded"


def source_state(history: dict[str, Any], name: str) -> dict[str, Any]:
    raw = history.get("sources", {}).get(name, {})
    if not isinstance(raw, dict):
        raw = {}
    outcomes = raw.get("recentOutcomes", [])
    if not isinstance(outcomes, list):
        outcomes = []
    return {
        "consecutiveFailures": _integer(raw.get("consecutiveFailures")),
        "cooldownRunsRemaining": _integer(raw.get("cooldownRunsRemaining")),
        "recentOutcomes": [item for item in outcomes if isinstance(item, dict)][-MAX_RECENT_OUTCOMES:],
    }


def order_sources(catalog: Iterable[tuple[str, str]], history: dict[str, Any]) -> list[tuple[str, str]]:
    """Prefer healthier sources first; all sources still remain eligible."""
    indexed = list(enumerate(catalog))
    return [source for _, source in sorted(
        indexed,
        key=lambda item: (
            source_state(history, item[1][1])["cooldownRunsRemaining"] > 0,
            source_state(history, item[1][1])["consecutiveFailures"],
            item[0],
        ),
    )]


def may_defer_source(history: dict[str, Any], source_name: str, successful_sources: int) -> bool:
    """Allow exactly one-run deferral only after surplus current healthy sources."""
    state = source_state(history, source_name)
    return (
        state["cooldownRunsRemaining"] > 0
        and successful_sources >= HEALTHY_SOURCES_BEFORE_DEFERRAL
    )


def deferred_health(name: str, provenance: str, observed_at: str) -> dict[str, Any]:
    return {
        "name": name,
        "provenance": provenance,
        "checkedAt": observed_at,
        "status": "deferred",
        "acceptedRecords": 0,
        "bytesRead": 0,
        "truncated": False,
        "attempts": 0,
        "retryRecovered": False,
        "healthPolicy": "one-run-cooldown-after-repeated-failures",
    }


def update_history(history: dict[str, Any], health_entries: Iterable[dict[str, Any]], observed_at: str) -> dict[str, Any]:
    """Produce a bounded next-state record from the completed current run."""
    next_history = empty_history()
    next_history["updatedAt"] = observed_at
    previous_sources = history.get("sources", {}) if isinstance(history.get("sources"), dict) else {}
    names = {name for name in previous_sources if isinstance(name, str)}
    names.update(str(entry.get("name")) for entry in health_entries if isinstance(entry.get("name"), str))

    by_name = {str(entry.get("name")): entry for entry in health_entries if isinstance(entry.get("name"), str)}
    for name in sorted(names):
        previous = source_state(history, name)
        entry = by_name.get(name)
        if entry is None:
            continue
        status = entry.get("status")
        usable = status in {"ok", "partial"} and _integer(entry.get("acceptedRecords")) > 0
        if usable:
            failures = 0
            cooldown = 0
            outcome = "usable"
        elif status == "deferred":
            failures = previous["consecutiveFailures"]
            cooldown = 0
            outcome = "deferred"
        else:
            failures = previous["consecutiveFailures"] + 1
            cooldown = 1 if failures >= FAILURES_BEFORE_COOLDOWN else 0
            outcome = "failed"
        recent = previous["recentOutcomes"] + [{
            "at": observed_at,
            "outcome": outcome,
            "attempts": _integer(entry.get("attempts")),
        }]
        next_history["sources"][name] = {
            "consecutiveFailures": failures,
            "cooldownRunsRemaining": cooldown,
            "recentOutcomes": recent[-MAX_RECENT_OUTCOMES:],
        }
    return next_history
