#!/usr/bin/env python3
"""Refresh VerifyPulse's permanent hashed historical-reputation index.

New public feed observations are merged directly into the existing hashed index.
This preserves future reputation matches without appending unbounded raw URLs to
Git. Each source response and per-source record count is bounded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from build_historical_reputation_index import (
    INDEX_DIR,
    SCHEMA_VERSION,
    SHARD_PREFIX_LENGTH,
    canonical_url,
    profile_for_source,
    sha256_key,
)

MANIFEST_PATH = INDEX_DIR / "manifest.json"
INTEGRITY_PATH = INDEX_DIR / "integrity.json"
HEALTH_PATH = INDEX_DIR / "source_health.json"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_RECORDS_PER_SOURCE = 600
REQUEST_TIMEOUT_SECONDS = 12

SOURCE_CATALOG = (
    ("https://urlhaus.abuse.ch/downloads/text/", "URLhaus"),
    ("https://openphish.com/feed.txt", "OpenPhish"),
    ("https://phishing.army/download/phishing_army_blocklist_extended.txt", "Phishing Army"),
    ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt", "Phishing.Database"),
    ("https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt", "Blackbook"),
)


def now() -> datetime:
    return datetime.now(timezone.utc)


def atomic_json(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.replace(path)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_tokens(payload: str) -> list[str]:
    tokens: list[str] = []
    for line in payload.splitlines():
        value = line.strip()
        if not value or value.startswith(("#", "//", "!")):
            continue
        parts = value.split()
        if len(parts) > 1 and parts[0] in {"0.0.0.0", "127.0.0.1", "::"}:
            value = parts[1]
        else:
            value = parts[0].split(",", 1)[0]
        tokens.append(value)
    return tokens


def fetch_source(source_url: str, source_name: str, observed_at: int) -> tuple[list[tuple[str, str, int]], dict[str, Any]]:
    health: dict[str, Any] = {
        "name": source_name,
        "provenance": source_url,
        "checkedAt": datetime.fromtimestamp(observed_at, tz=timezone.utc).isoformat(),
        "status": "failed",
        "acceptedIndicators": 0,
        "bytesRead": 0,
        "truncated": False,
    }
    try:
        request = Request(source_url, headers={"User-Agent": "VerifyPulse-HistoricalIndex/1.0"})
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            content = response.read(MAX_RESPONSE_BYTES + 1)
        health["truncated"] = len(content) > MAX_RESPONSE_BYTES
        health["bytesRead"] = min(len(content), MAX_RESPONSE_BYTES)
        text = content[:MAX_RESPONSE_BYTES].decode("utf-8", errors="ignore")
        observations: list[tuple[str, str, int]] = []
        seen: set[str] = set()
        for token in extract_tokens(text):
            canonical = canonical_url(token)
            if not canonical or canonical in seen:
                continue
            seen.add(canonical)
            observations.append((canonical, source_url, observed_at))
            if len(observations) >= MAX_RECORDS_PER_SOURCE:
                break
        health["acceptedIndicators"] = len(observations)
        health["status"] = "partial" if health["truncated"] else "ok"
        return observations, health
    except Exception as error:
        health["error"] = f"{type(error).__name__}: {str(error)[:180]}"
        return [], health


def source_id(source_url: str, manifest: dict[str, Any]) -> int:
    catalog = manifest.setdefault("sourceCatalog", [])
    for entry in catalog:
        if entry.get("provenance") == source_url:
            return int(entry["id"])
    new_id = max((int(entry.get("id", -1)) for entry in catalog), default=-1) + 1
    profile = profile_for_source(source_url)
    catalog.append({
        "id": new_id,
        "name": profile["name"],
        "confidence": profile["confidence"],
        "qualityTier": profile["qualityTier"],
        "category": profile["category"],
        "provenance": source_url,
    })
    manifest["sourceCount"] = len(catalog)
    return new_id


def update_record(records: dict[tuple[str, str], list[Any]], key_type: str, value: str, origin_id: int, observed_at: int) -> bool:
    digest = sha256_key(value)
    key = (key_type, digest)
    record = records.get(key)
    if record is None:
        records[key] = [digest, key_type, [origin_id], observed_at, observed_at]
        return True
    changed = False
    if origin_id not in record[2]:
        record[2].append(origin_id)
        record[2].sort()
        changed = True
    if not record[3] or observed_at < record[3]:
        record[3] = observed_at
        changed = True
    if observed_at > record[4]:
        record[4] = observed_at
        changed = True
    return changed


def load_shard(prefix: str) -> tuple[dict[tuple[str, str], list[Any]], Path]:
    path = INDEX_DIR / "shards" / f"{prefix}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("v") != 1 or payload.get("p") != prefix or not isinstance(payload.get("r"), list):
        raise ValueError(f"Invalid shard payload: {prefix}")
    records: dict[tuple[str, str], list[Any]] = {}
    for record in payload["r"]:
        if isinstance(record, list) and len(record) == 5 and record[1] in {"u", "d"}:
            records[(record[1], record[0])] = record
    return records, path


def write_shard(prefix: str, records: dict[tuple[str, str], list[Any]], integrity: dict[str, Any]) -> tuple[int, int]:
    path = INDEX_DIR / "shards" / f"{prefix}.json"
    ordered = sorted(records.values(), key=lambda record: record[0])
    atomic_json(path, {"v": 1, "p": prefix, "r": ordered})
    raw = path.read_bytes()
    integrity["shards"][prefix] = {
        "path": f"shards/{prefix}.json",
        "records": len(ordered),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    return len(ordered), len(raw)


def refresh() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    integrity = json.loads(INTEGRITY_PATH.read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != SCHEMA_VERSION or integrity.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("Historical index schema mismatch; rebuild index before refresh.")
    if manifest.get("shardPrefixLength") != SHARD_PREFIX_LENGTH:
        raise ValueError("Historical index shard format mismatch; rebuild index before refresh.")

    observed_at = int(now().timestamp())
    pending: dict[str, list[tuple[str, str, int]]] = {}
    health_entries: list[dict[str, Any]] = []
    for source_url, source_name in SOURCE_CATALOG:
        observations, health = fetch_source(source_url, source_name, observed_at)
        health_entries.append(health)
        for canonical, provenance, timestamp in observations:
            prefix = sha256_key(canonical)[:SHARD_PREFIX_LENGTH]
            pending.setdefault(prefix, []).append((canonical, provenance, timestamp))
            host = canonical.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
            domain_prefix = sha256_key(host)[:SHARD_PREFIX_LENGTH]
            pending.setdefault(domain_prefix, []).append((f"domain:{host}", provenance, timestamp))

    changed_shards = 0
    newly_indexed = 0
    for prefix, observations in pending.items():
        records, _ = load_shard(prefix)
        was_changed = False
        for value, provenance, timestamp in observations:
            origin_id = source_id(provenance, manifest)
            if value.startswith("domain:"):
                changed = update_record(records, "d", value.split(":", 1)[1], origin_id, timestamp)
            else:
                changed = update_record(records, "u", value, origin_id, timestamp)
            if changed:
                was_changed = True
                if len(records) == 1 or changed:
                    newly_indexed += 1
        if was_changed:
            write_shard(prefix, records, integrity)
            changed_shards += 1

    shard_metadata = integrity["shards"]
    manifest["generatedAt"] = now().isoformat()
    manifest["uniqueIndexedKeys"] = sum(int(item.get("records") or 0) for item in shard_metadata.values())
    manifest["urlKeyCount"] = None
    manifest["domainKeyCount"] = None
    manifest["shardCount"] = len(shard_metadata)
    integrity["generatedAt"] = manifest["generatedAt"]
    atomic_json(MANIFEST_PATH, manifest)
    atomic_json(INTEGRITY_PATH, integrity)
    health = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": manifest["generatedAt"],
        "sourceCount": len(SOURCE_CATALOG),
        "successfulSources": sum(entry["status"] in {"ok", "partial"} for entry in health_entries),
        "changedShards": changed_shards,
        "observationsProcessed": sum(entry["acceptedIndicators"] for entry in health_entries),
        "sources": health_entries,
    }
    atomic_json(HEALTH_PATH, health)
    return health


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh VerifyPulse permanent historical hashed reputation index")
    parser.add_argument("--json", action="store_true", help="Print the refresh health summary as JSON")
    args = parser.parse_args()
    result = refresh()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"Historical refresh complete: {result['successfulSources']}/{result['sourceCount']} sources usable; {result['changedShards']} shards updated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
