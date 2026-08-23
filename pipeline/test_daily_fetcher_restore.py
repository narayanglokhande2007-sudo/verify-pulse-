#!/usr/bin/env python3
"""Deterministic tests for fail-closed Daily Fetcher workflow restore points."""

from __future__ import annotations

import tempfile
from pathlib import Path

import daily_fetcher_restore as restore_point


WORKFLOW = "name: Daily Indian Scam Fetcher\nsteps: []\n"
BROKEN = "name: Broken Workflow\nsteps: []\n"


def main() -> int:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        target = root / ".github/workflows/daily_scam_fetch.yml"
        target.parent.mkdir(parents=True)
        target.write_text(WORKFLOW, encoding="utf-8")

        dry = restore_point.bootstrap(root, write=False)
        assert dry["bootstrapped"] is False
        created = restore_point.bootstrap(root, write=True)
        assert created["bootstrapped"] is True
        assert created["validRestorePoint"] is True
        assert created["targetMatchesRestorePoint"] is True

        target.write_text(BROKEN, encoding="utf-8")
        planned = restore_point.inspect(root)
        assert planned["validRestorePoint"] is True
        assert planned["targetMatchesRestorePoint"] is False
        assert planned["canRestore"] is True

        dry_restore = restore_point.restore(root, apply=False)
        assert dry_restore["restored"] is False
        assert target.read_text(encoding="utf-8") == BROKEN

        applied = restore_point.restore(root, apply=True)
        assert applied["restored"] is True
        assert target.read_text(encoding="utf-8") == WORKFLOW

        copy_path = root / ".github/verify-pulse/restore-points/daily_scam_fetch.yml"
        copy_path.write_text("tampered\n", encoding="utf-8")
        target.write_text(BROKEN, encoding="utf-8")
        blocked = restore_point.restore(root, apply=True)
        assert blocked["restored"] is False
        assert blocked["status"]["validRestorePoint"] is False
        assert target.read_text(encoding="utf-8") == BROKEN

    print("Daily fetcher restore-point checks: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
