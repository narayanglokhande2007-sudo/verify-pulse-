#!/usr/bin/env python3
"""Deterministic tests for the bounded Daily Fetcher source-health policy."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import source_health_policy as policy


CATALOG = (
    ("https://first.example/feed", "First"),
    ("https://second.example/feed", "Second"),
    ("https://third.example/feed", "Third"),
    ("https://fourth.example/feed", "Fourth"),
)


def failed(name: str) -> dict:
    return {"name": name, "status": "failed", "acceptedRecords": 0, "attempts": 3}


def usable(name: str) -> dict:
    return {"name": name, "status": "ok", "acceptedRecords": 1, "attempts": 1}


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        history_path = Path(temporary) / "history.json"
        history, state = policy.load_history(history_path)
        assert state == "new"
        assert history == policy.empty_history()

        history = policy.update_history(history, [failed("First")], "2026-08-20T00:00:00+00:00")
        history = policy.update_history(history, [failed("First")], "2026-08-21T00:00:00+00:00")
        assert not policy.may_defer_source(history, "First", successful_sources=4)

        history = policy.update_history(history, [failed("First")], "2026-08-22T00:00:00+00:00")
        assert policy.source_state(history, "First")["consecutiveFailures"] == 3
        assert policy.may_defer_source(history, "First", successful_sources=3)
        assert not policy.may_defer_source(history, "First", successful_sources=2)
        assert policy.order_sources(CATALOG, history)[-1][1] == "First"

        deferred = policy.deferred_health("First", "https://first.example/feed", "2026-08-23T00:00:00+00:00")
        history = policy.update_history(history, [deferred], "2026-08-23T00:00:00+00:00")
        assert policy.source_state(history, "First")["cooldownRunsRemaining"] == 0
        assert policy.source_state(history, "First")["consecutiveFailures"] == 3

        history = policy.update_history(history, [usable("First")], "2026-08-24T00:00:00+00:00")
        assert policy.source_state(history, "First")["consecutiveFailures"] == 0
        assert policy.source_state(history, "First")["cooldownRunsRemaining"] == 0

        history_path.write_text("not-json", encoding="utf-8")
        reset, reset_state = policy.load_history(history_path)
        assert reset_state == "reset-invalid-history"
        assert reset == policy.empty_history()

        history_path.write_text(json.dumps(history), encoding="utf-8")
        loaded, loaded_state = policy.load_history(history_path)
        assert loaded_state == "loaded"
        assert loaded == history

    print("Source health policy checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
