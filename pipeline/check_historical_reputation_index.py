#!/usr/bin/env python3
"""Fail-closed integrity and health validation for VerifyPulse historical index."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
INDEX_DIR = ROOT / "daily-data" / "historical-reputation-index"
MANIFEST_PATH = INDEX_DIR / "manifest.json"
INTEGRITY_PATH = INDEX_DIR / "integrity.json"
SOURCE_HEALTH_PATH = INDEX_DIR / "source_health.json"
SCHEMA_VERSION = "vp-historical-reputation-index-1"
MAX_RUNTIME_MANIFEST_BYTES = 25_000
MAX_SHARD_BYTES = 25_000
MAX_SHARD_RECORDS = 12_000


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate(full: bool, require_fresh: bool, minimum_successful_sources: int) -> dict[str, Any]:
    issues: list[dict[str, str]] = []
    now = datetime.now(timezone.utc)
    summary: dict[str, Any] = {"checkedAt": now.isoformat(), "full": full, "requireFresh": require_fresh, "minimumSuccessfulSources": minimum_successful_sources}
    try:
        manifest = load_json(MANIFEST_PATH)
    except (OSError, json.JSONDecodeError) as error:
        return {**summary, "valid": False, "issues": [{"file": "manifest.json", "issue": f"invalid or missing: {error}"}]}
    try:
        integrity = load_json(INTEGRITY_PATH)
    except (OSError, json.JSONDecodeError) as error:
        return {**summary, "valid": False, "issues": [{"file": "integrity.json", "issue": f"invalid or missing: {error}"}]}

    if manifest.get("schemaVersion") != SCHEMA_VERSION:
        issues.append({"file": "manifest.json", "issue": "unexpected schemaVersion"})
    if integrity.get("schemaVersion") != SCHEMA_VERSION:
        issues.append({"file": "integrity.json", "issue": "unexpected schemaVersion"})
    if MANIFEST_PATH.stat().st_size > MAX_RUNTIME_MANIFEST_BYTES:
        issues.append({"file": "manifest.json", "issue": "runtime manifest exceeds latency size bound"})
    if manifest.get("integrityFile") != "integrity.json":
        issues.append({"file": "manifest.json", "issue": "integrity-file reference mismatch"})

    shard_prefix_length = manifest.get("shardPrefixLength")
    shards = integrity.get("shards")
    if shard_prefix_length != 3 or integrity.get("shardPrefixLength") != 3:
        issues.append({"file": "index", "issue": "unexpected shard prefix length"})
    if not isinstance(shards, dict) or not shards:
        issues.append({"file": "integrity.json", "issue": "missing shard metadata"})
        shards = {}
    if manifest.get("shardCount") != len(shards):
        issues.append({"file": "index", "issue": "manifest shard count mismatch"})
    if not isinstance(manifest.get("sourceCatalog"), list) or not manifest["sourceCatalog"]:
        issues.append({"file": "manifest.json", "issue": "missing source catalog"})
    if not isinstance(manifest.get("uniqueIndexedKeys"), int) or manifest["uniqueIndexedKeys"] <= 0:
        issues.append({"file": "manifest.json", "issue": "invalid unique key count"})

    checked_shards = 0
    total_records = 0
    total_bytes = 0
    for prefix, metadata in shards.items():
        if not isinstance(prefix, str) or len(prefix) != 3 or not isinstance(metadata, dict):
            issues.append({"file": "integrity.json", "issue": "invalid shard metadata entry"})
            continue
        relative = metadata.get("path")
        path = INDEX_DIR / str(relative or "")
        if not path.is_file() or not path.resolve().is_relative_to(INDEX_DIR.resolve()):
            issues.append({"file": str(relative), "issue": "missing or unsafe shard path"})
            continue
        size = path.stat().st_size
        total_bytes += size
        if size > MAX_SHARD_BYTES:
            issues.append({"file": str(relative), "issue": "shard exceeds size bound"})
        if metadata.get("bytes") != size:
            issues.append({"file": str(relative), "issue": "recorded byte size mismatch"})
        if full:
            try:
                payload = load_json(path)
                if payload.get("v") != 1 or payload.get("p") != prefix or not isinstance(payload.get("r"), list):
                    issues.append({"file": str(relative), "issue": "invalid shard structure"})
                elif len(payload["r"]) > MAX_SHARD_RECORDS or len(payload["r"]) != metadata.get("records"):
                    issues.append({"file": str(relative), "issue": "record count out of bounds or mismatched"})
                if sha256_file(path) != metadata.get("sha256"):
                    issues.append({"file": str(relative), "issue": "SHA-256 mismatch"})
            except (OSError, json.JSONDecodeError) as error:
                issues.append({"file": str(relative), "issue": f"unreadable JSON: {error}"})
        total_records += int(metadata.get("records") or 0)
        checked_shards += 1

    source_health: dict[str, Any] = {}
    try:
        source_health = load_json(SOURCE_HEALTH_PATH)
        generated = datetime.fromisoformat(str(source_health.get("generatedAt") or "").replace("Z", "+00:00"))
        if generated.tzinfo is None:
            generated = generated.replace(tzinfo=timezone.utc)
        successful = int(source_health.get("successfulSources") or 0)
        if source_health.get("schemaVersion") != SCHEMA_VERSION:
            issues.append({"file": "source_health.json", "issue": "unexpected schemaVersion"})
        if require_fresh and generated.date() != now.date():
            issues.append({"file": "source_health.json", "issue": "not generated today"})
        if successful < minimum_successful_sources:
            issues.append({"file": "source_health.json", "issue": f"only {successful} successful sources; need {minimum_successful_sources}"})
    except (OSError, ValueError, json.JSONDecodeError) as error:
        issues.append({"file": "source_health.json", "issue": f"invalid or missing: {error}"})

    summary.update({
        "valid": not issues,
        "uniqueIndexedKeys": manifest.get("uniqueIndexedKeys"),
        "sourceCount": manifest.get("sourceCount"),
        "successfulSources": source_health.get("successfulSources"),
        "shardCount": len(shards),
        "checkedShards": checked_shards,
        "indexedShardRecords": total_records,
        "indexBytes": total_bytes,
        "issues": issues,
    })
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate VerifyPulse historical hashed reputation index")
    parser.add_argument("--full", action="store_true", help="Parse and hash-verify every shard")
    parser.add_argument("--require-fresh", action="store_true", help="Require a source-health record generated today")
    parser.add_argument("--min-successful-sources", type=int, default=0, help="Minimum current-run successful sources required")
    args = parser.parse_args()
    if args.min_successful_sources < 0:
        parser.error("--min-successful-sources must be zero or greater")
    report = validate(args.full, args.require_fresh, args.min_successful_sources)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
