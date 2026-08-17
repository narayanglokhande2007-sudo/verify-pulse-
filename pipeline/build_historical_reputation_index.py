#!/usr/bin/env python3
"""Build a fast, privacy-conscious historical URL reputation index for VerifyPulse.

The raw historical source files stay intact. This script creates an exact-match
lookup index containing SHA-256 keys for canonical URLs and hostnames, plus
source provenance and recency metadata. The live API fetches only the one or two
small hash shards needed for a submitted URL; it never downloads the full raw
history during a scan.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shutil
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "daily-data"
INPUT_FILES = (
    DATA_DIR / "india_scams.jsonl",
    DATA_DIR / "global_scams.jsonl",
    DATA_DIR / "all_scams_master.jsonl",
)
INDEX_DIR = DATA_DIR / "historical-reputation-index"
STAGING_DIR = DATA_DIR / ".historical-reputation-index-staging"
SCHEMA_VERSION = "vp-historical-reputation-index-1"
SHARD_PREFIX_LENGTH = 3  # 4,096 shards: fast per-scan reads without huge files.
MAX_RECORDS_PER_SHARD = 12_000

SOURCE_PROFILES = {
    "urlhaus": {"name": "URLhaus", "confidence": 95, "qualityTier": "verified", "category": "malware-url"},
    "openphish": {"name": "OpenPhish", "confidence": 90, "qualityTier": "verified", "category": "phishing-url"},
    "phishtank": {"name": "PhishTank", "confidence": 88, "qualityTier": "established-community", "category": "phishing-url"},
    "phishing.database": {"name": "Phishing.Database", "confidence": 82, "qualityTier": "community", "category": "phishing-url"},
    "phishing.army": {"name": "Phishing Army", "confidence": 78, "qualityTier": "community", "category": "phishing-url"},
    "blackbook": {"name": "Blackbook", "confidence": 70, "qualityTier": "community", "category": "suspicious-indicator"},
    "spam404": {"name": "Spam404", "confidence": 70, "qualityTier": "community", "category": "phishing-url"},
}
DEFAULT_PROFILE = {"name": "Community Threat Feed", "confidence": 65, "qualityTier": "unclassified", "category": "suspicious-indicator"}
QUALITY_ORDER = {"unclassified": 0, "community": 1, "established-community": 2, "verified": 3}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: Any) -> int:
    """Return UTC epoch seconds or zero when the historic record has no usable date."""
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp())
    except ValueError:
        return 0


def public_hostname(hostname: str) -> bool:
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host or host == "localhost" or host.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(host)
        return not any((
            address.is_private,
            address.is_loopback,
            address.is_link_local,
            address.is_multicast,
            address.is_reserved,
            address.is_unspecified,
        ))
    except ValueError:
        return bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host))


def canonical_url(value: Any) -> str | None:
    raw = str(value or "").strip().strip("'\"()[]{}<>,.;")
    if not raw or raw.startswith(("#", "//", "!")):
        return None
    candidate = raw if re.match(r"^https?://", raw, re.IGNORECASE) else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.username or parsed.password or not public_hostname(host):
        return None
    scheme = parsed.scheme.lower()
    try:
        raw_port = parsed.port
    except ValueError:
        return None
    # Node's URL parser (used by the live scanner) removes default ports. Match
    # that behavior so a historical key and a submitted URL hash identically.
    port = f":{raw_port}" if raw_port and not ((scheme == "http" and raw_port == 80) or (scheme == "https" and raw_port == 443)) else ""
    return urlunsplit((scheme, f"{host}{port}", parsed.path or "/", "", ""))


def sha256_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def profile_for_source(source: Any) -> dict[str, Any]:
    source_text = str(source or "").lower()
    for fragment, profile in SOURCE_PROFILES.items():
        if fragment in source_text:
            return profile
    return DEFAULT_PROFILE


def iter_records(paths: Iterable[Path]) -> Iterable[dict[str, Any]]:
    for path in paths:
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    yield record


def source_id_for(source_label: str, source_ids: dict[str, int], sources: list[dict[str, Any]]) -> int:
    existing = source_ids.get(source_label)
    if existing is not None:
        return existing
    profile = profile_for_source(source_label)
    source_id = len(sources)
    source_ids[source_label] = source_id
    sources.append({
        "id": source_id,
        "name": profile["name"],
        "confidence": profile["confidence"],
        "qualityTier": profile["qualityTier"],
        "category": profile["category"],
        "provenance": source_label[:220],
    })
    return source_id


def add_observation(index: dict[str, dict[str, Any]], key_type: str, canonical_value: str, source_id: int, observed_at: int) -> None:
    digest = sha256_key(canonical_value)
    key = f"{key_type}:{digest}"
    existing = index.get(key)
    if existing is None:
        index[key] = {
            "h": digest,
            "t": key_type,
            "s": {source_id},
            "f": observed_at,
            "l": observed_at,
        }
        return
    existing["s"].add(source_id)
    if observed_at:
        if not existing["f"] or observed_at < existing["f"]:
            existing["f"] = observed_at
        if observed_at > existing["l"]:
            existing["l"] = observed_at


def compact_record(record: dict[str, Any]) -> list[Any]:
    # [hash, type, sourceIds, firstSeenEpoch, lastSeenEpoch]
    return [record["h"], record["t"], sorted(record["s"]), record["f"], record["l"]]


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.replace(path)


def build_index() -> dict[str, Any]:
    records_by_key: dict[str, dict[str, Any]] = {}
    sources: list[dict[str, Any]] = []
    source_ids: dict[str, int] = {}
    file_counts: Counter[str] = Counter()
    total_records = 0
    usable_records = 0
    rejected_records = 0

    for record in iter_records(INPUT_FILES):
        total_records += 1
        canonical = canonical_url(record.get("url") or record.get("indicator"))
        if not canonical:
            rejected_records += 1
            continue
        usable_records += 1
        source_label = str(record.get("source") or record.get("sourceName") or "unknown").strip()
        source_id = source_id_for(source_label, source_ids, sources)
        observed_at = parse_time(record.get("date_added") or record.get("first_seen") or record.get("lastSeen"))
        add_observation(records_by_key, "u", canonical, source_id, observed_at)
        host = (urlsplit(canonical).hostname or "").lower().rstrip(".")
        if host:
            add_observation(records_by_key, "d", host, source_id, observed_at)
        region = str(record.get("region") or "").lower()
        if region:
            file_counts[region] += 1

    generated_at = utc_now().isoformat()
    shards: dict[str, list[list[Any]]] = defaultdict(list)
    for record in records_by_key.values():
        prefix = record["h"][:SHARD_PREFIX_LENGTH]
        shards[prefix].append(compact_record(record))

    if any(len(items) > MAX_RECORDS_PER_SHARD for items in shards.values()):
        largest = max(len(items) for items in shards.values())
        raise RuntimeError(f"Historical index shard limit exceeded: largest shard has {largest} records.")

    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)
    STAGING_DIR.mkdir(parents=True)

    shard_summaries: dict[str, dict[str, Any]] = {}
    for prefix, items in sorted(shards.items()):
        items.sort(key=lambda entry: entry[0])
        relative_path = f"shards/{prefix}.json"
        path = STAGING_DIR / relative_path
        payload = {"v": 1, "p": prefix, "r": items}
        atomic_write_json(path, payload)
        encoded = path.read_bytes()
        shard_summaries[prefix] = {
            "path": relative_path,
            "records": len(items),
            "bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": generated_at,
        "keyAlgorithm": "sha256-canonical-url-or-host-v1",
        "shardPrefixLength": SHARD_PREFIX_LENGTH,
        "recordEncoding": "[sha256, type(u=url|d=domain), sourceIds, firstSeenEpoch, lastSeenEpoch]",
        "dataHandling": "The index stores SHA-256 keys, source provenance metadata, and observation times. Raw historical URLs remain in their existing repository files and are not copied into lookup shards.",
        "sourceCatalog": sources,
        "inputFiles": [path.name for path in INPUT_FILES if path.is_file()],
        "inputRecordCount": total_records,
        "usableInputRecordCount": usable_records,
        "rejectedInputRecordCount": rejected_records,
        "uniqueIndexedKeys": len(records_by_key),
        "urlKeyCount": sum(record["t"] == "u" for record in records_by_key.values()),
        "domainKeyCount": sum(record["t"] == "d" for record in records_by_key.values()),
        "sourceCount": len(sources),
        "regionCounts": dict(sorted(file_counts.items())),
        "shardCount": len(shard_summaries),
        "integrityFile": "integrity.json",
    }
    # Runtime needs only the small manifest because shard paths are deterministic.
    # Per-shard size/hash metadata is kept separately for watchman validation.
    integrity = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": generated_at,
        "shardPrefixLength": SHARD_PREFIX_LENGTH,
        "shards": shard_summaries,
    }
    atomic_write_json(STAGING_DIR / "manifest.json", manifest)
    atomic_write_json(STAGING_DIR / "integrity.json", integrity)

    if INDEX_DIR.exists():
        backup = INDEX_DIR.with_name(f"{INDEX_DIR.name}.previous")
        if backup.exists():
            shutil.rmtree(backup)
        INDEX_DIR.replace(backup)
        STAGING_DIR.replace(INDEX_DIR)
        shutil.rmtree(backup)
    else:
        STAGING_DIR.replace(INDEX_DIR)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Build VerifyPulse historical hashed URL reputation index")
    parser.add_argument("--json", action="store_true", help="Print only the generated index manifest")
    args = parser.parse_args()
    manifest = build_index()
    if args.json:
        print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(
            f"Historical index built: {manifest['uniqueIndexedKeys']} exact keys, "
            f"{manifest['sourceCount']} sources, {manifest['shardCount']} shards."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
