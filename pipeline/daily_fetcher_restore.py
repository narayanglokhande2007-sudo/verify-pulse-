#!/usr/bin/env python3
"""Fail-closed restore-point utility for Daily Indian Scam Fetcher workflow.

A restore point is a repository-local, reviewed copy of the workflow plus its
pinned SHA-256 hash. This tool never downloads code and cannot restore anything
unless the stored copy exactly matches the committed hash. It plans by default;
writing requires an explicit --apply acknowledgement.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = ".github/workflows/daily_scam_fetch.yml"
DEFAULT_RESTORE_COPY = ".github/verify-pulse/restore-points/daily_scam_fetch.yml"
DEFAULT_CONFIG = ".github/verify-pulse/daily_fetcher_restore_point.json"
SCHEMA_VERSION = "vp-daily-fetcher-restore-point-1"


def safe_path(root: Path, relative_path: str) -> Path:
    candidate = (root / relative_path).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"Unsafe restore-point path: {relative_path}")
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        temporary.write_bytes(source.read_bytes())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def build_config(root: Path, target_relative: str = DEFAULT_TARGET, copy_relative: str = DEFAULT_RESTORE_COPY) -> dict[str, Any]:
    target = safe_path(root, target_relative)
    restore_copy = safe_path(root, copy_relative)
    if not target.is_file():
        raise FileNotFoundError(f"Missing workflow target: {target_relative}")
    if not restore_copy.is_file():
        raise FileNotFoundError(f"Missing restore-point copy: {copy_relative}")
    target_hash = sha256_file(target)
    copy_hash = sha256_file(restore_copy)
    if target_hash != copy_hash:
        raise ValueError("Restore-point copy does not match the workflow target; bootstrap refused.")
    return {
        "schemaVersion": SCHEMA_VERSION,
        "targetPath": target_relative,
        "restoreCopyPath": copy_relative,
        "sha256": copy_hash,
    }


def load_config(root: Path, config_relative: str = DEFAULT_CONFIG) -> dict[str, Any]:
    config_path = safe_path(root, config_relative)
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("Invalid restore-point configuration.")
    for key in ("targetPath", "restoreCopyPath", "sha256"):
        if not isinstance(payload.get(key), str) or not payload[key]:
            raise ValueError(f"Missing restore-point field: {key}")
    if len(payload["sha256"]) != 64 or any(char not in "0123456789abcdef" for char in payload["sha256"].lower()):
        raise ValueError("Invalid restore-point SHA-256.")
    safe_path(root, payload["targetPath"])
    safe_path(root, payload["restoreCopyPath"])
    return payload


def inspect(root: Path, config_relative: str = DEFAULT_CONFIG) -> dict[str, Any]:
    try:
        config = load_config(root, config_relative)
        target = safe_path(root, config["targetPath"])
        restore_copy = safe_path(root, config["restoreCopyPath"])
        copy_matches = restore_copy.is_file() and sha256_file(restore_copy) == config["sha256"]
        target_matches = target.is_file() and sha256_file(target) == config["sha256"]
        return {
            "validRestorePoint": copy_matches,
            "targetMatchesRestorePoint": target_matches,
            "targetPath": config["targetPath"],
            "restoreCopyPath": config["restoreCopyPath"],
            "canRestore": copy_matches and not target_matches,
        }
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {"validRestorePoint": False, "targetMatchesRestorePoint": False, "canRestore": False, "error": str(error)}


def bootstrap(root: Path, config_relative: str = DEFAULT_CONFIG, *, write: bool = False) -> dict[str, Any]:
    if not write:
        return {"bootstrapped": False, "message": "Dry run only. Re-run bootstrap with --write after reviewing the trusted workflow."}
    config_path = safe_path(root, config_relative)
    if config_path.exists():
        raise FileExistsError("Restore-point configuration already exists; refusing to replace it automatically.")
    target = safe_path(root, DEFAULT_TARGET)
    restore_copy = safe_path(root, DEFAULT_RESTORE_COPY)
    atomic_copy(target, restore_copy)
    config = build_config(root)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"bootstrapped": True, **inspect(root, config_relative)}


def restore(root: Path, config_relative: str = DEFAULT_CONFIG, *, apply: bool = False) -> dict[str, Any]:
    status = inspect(root, config_relative)
    if not status.get("validRestorePoint"):
        return {"restored": False, "status": status, "message": "Restore blocked: trusted restore point is invalid."}
    if status.get("targetMatchesRestorePoint"):
        return {"restored": False, "status": status, "message": "No restore needed: target already matches trusted restore point."}
    if not apply:
        return {"restored": False, "status": status, "message": "Dry run only. Re-run restore with --apply after review."}
    config = load_config(root, config_relative)
    atomic_copy(safe_path(root, config["restoreCopyPath"]), safe_path(root, config["targetPath"]))
    final_status = inspect(root, config_relative)
    if not final_status.get("targetMatchesRestorePoint"):
        raise RuntimeError("Restore copy verification failed after atomic replacement.")
    return {"restored": True, "status": final_status, "message": "Trusted workflow restore point applied."}


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail-closed Daily Fetcher workflow restore point")
    parser.add_argument("--project-root", type=Path, default=PROJECT_ROOT, help="Repository root; intended for deterministic tests")
    subparsers = parser.add_subparsers(dest="command", required=True)
    bootstrap_parser = subparsers.add_parser("bootstrap", help="Create one reviewed local restore point")
    bootstrap_parser.add_argument("--write", action="store_true")
    subparsers.add_parser("verify", help="Verify restore point without changing files")
    subparsers.add_parser("plan", help="Show whether a trusted restore is possible")
    restore_parser = subparsers.add_parser("restore", help="Restore only from exact-hash local copy")
    restore_parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.project_root.resolve()
    try:
        if args.command == "bootstrap":
            result = bootstrap(root, write=args.write)
        elif args.command in {"verify", "plan"}:
            result = inspect(root)
        else:
            result = restore(root, apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        if args.command in {"verify", "plan"}:
            return 0 if result.get("validRestorePoint") else 1
        return 0
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
