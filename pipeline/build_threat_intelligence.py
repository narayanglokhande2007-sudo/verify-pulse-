#!/usr/bin/env python3
"""Build a compact, source-aware threat-intelligence snapshot for VerifyPulse.

The script never treats a raw feed line as proof by itself. It normalizes public
HTTP(S) indicators, records provenance, applies source-aware confidence and
expiry, and writes a compact snapshot that the serverless API can query quickly.
It uses only Python's standard library and the existing daily data files.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "daily-data"
INPUT_FILES = [DATA_DIR / "india_scams.jsonl", DATA_DIR / "global_scams.jsonl"]
OUTPUT_FILE = DATA_DIR / "latest_threat_intel.json"
STATS_FILE = DATA_DIR / "threat_intel_stats.json"
MAX_INDICATORS = 5000
SCHEMA_VERSION = "vp-threat-intel-1"

# Names are assigned from source URLs already present in the daily feed pipeline.
# Only high-confidence public phishing/malware feeds get the top confidence bands.
SOURCE_PROFILES = {
    "urlhaus.abuse.ch": {"name": "URLhaus", "confidence": 95, "ttl_days": 30, "category": "malware-url", "qualityTier": "verified"},
    "openphish.com": {"name": "OpenPhish", "confidence": 90, "ttl_days": 21, "category": "phishing-url", "qualityTier": "verified"},
    "phishtank.com": {"name": "PhishTank", "confidence": 88, "ttl_days": 21, "category": "phishing-url", "qualityTier": "established-community"},
    "phishing.database.red": {"name": "Phishing.Database", "confidence": 82, "ttl_days": 14, "category": "phishing-url", "qualityTier": "community"},
    "phishing.army": {"name": "Phishing Army", "confidence": 78, "ttl_days": 14, "category": "phishing-url", "qualityTier": "community"},
}
DEFAULT_PROFILE = {"name": "Community Threat Feed", "confidence": 65, "ttl_days": 10, "category": "suspicious-indicator", "qualityTier": "unclassified"}

# Keep live refresh intentionally small and source-attributed. These feeds are
# already part of the existing collection pipeline; this layer adds freshness,
# normalization, expiry and bounded publication rather than a blind blocklist.
LIVE_VERIFIED_FEEDS = [
    ("https://urlhaus.abuse.ch/downloads/text/", "URLhaus"),
    ("https://openphish.com/feed.txt", "OpenPhish"),
]
MAX_LIVE_RECORDS_PER_SOURCE = 2_000
MAX_LIVE_RESPONSE_BYTES = 2 * 1024 * 1024


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: Any) -> datetime:
    if not value:
        return utc_now()
    try:
        normalized = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return utc_now()


def profile_for_source(source: str) -> dict[str, Any]:
    source_text = str(source or "").lower()
    for fragment, profile in SOURCE_PROFILES.items():
        if fragment in source_text:
            return profile
    return DEFAULT_PROFILE


def is_public_hostname(hostname: str) -> bool:
    host = str(hostname or "").strip().lower().rstrip(".")
    if not host or host == "localhost" or host.endswith(".local"):
        return False
    try:
        return not ipaddress.ip_address(host).is_private and not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host))


def normalise_indicator(value: Any) -> dict[str, str] | None:
    raw = str(value or "").strip().strip("'\"()[]{}<>,.;")
    if not raw or raw.startswith(("#", "//")):
        return None
    candidate = raw if re.match(r"^https?://", raw, re.IGNORECASE) else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    if not is_public_hostname(host):
        return None
    path = parsed.path or "/"
    # Query strings and fragments often contain tokens and reduce deduplication value.
    canonical_url = urlunsplit((parsed.scheme.lower(), host, path, "", ""))
    indicator_type = "url" if path not in ("", "/") else "domain"
    return {"indicator": canonical_url if indicator_type == "url" else host, "indicatorType": indicator_type, "hostname": host}


def iter_records(paths: Iterable[Path]) -> Iterable[dict[str, Any]]:
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                try:
                    item = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    yield item


def iter_live_verified_records(now: datetime | None = None) -> Iterable[dict[str, Any]]:
    observed_at = (now or utc_now()).isoformat()
    for feed_url, source_name in LIVE_VERIFIED_FEEDS:
        emitted = 0
        try:
            request = Request(feed_url, headers={"User-Agent": "VerifyPulse-ThreatIntel/1.0"})
            with urlopen(request, timeout=12) as response:
                content = response.read(MAX_LIVE_RESPONSE_BYTES).decode("utf-8", errors="ignore")
            for line in content.splitlines():
                candidate = line.strip().split()[0] if line.strip() else ""
                if not candidate or candidate.startswith(("#", "//")):
                    continue
                yield {
                    "url": candidate,
                    "source": feed_url,
                    "type": f"{source_name} verified threat indicator",
                    "date_added": observed_at,
                }
                emitted += 1
                if emitted >= MAX_LIVE_RECORDS_PER_SOURCE:
                    break
            print(f"Fetched {emitted} bounded live indicators from {source_name}.")
        except Exception as error:
            # A feed failure must not publish stale data as fresh or stop the whole
            # daily pipeline. Existing unexpired data can still be represented.
            print(f"Live feed unavailable for {source_name}: {error}")


def build_snapshot(records: Iterable[dict[str, Any]], now: datetime | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    now = now or utc_now()
    merged: dict[str, dict[str, Any]] = {}
    rejected = 0
    processed = 0

    for record in records:
        processed += 1
        normalised = normalise_indicator(record.get("url") or record.get("indicator"))
        if not normalised:
            rejected += 1
            continue
        observed_at = parse_time(record.get("date_added") or record.get("first_seen"))
        profile = profile_for_source(record.get("source", ""))
        expires_at = observed_at + timedelta(days=profile["ttl_days"])
        if expires_at <= now:
            continue

        key = f"{normalised['indicatorType']}:{normalised['indicator']}"
        entry = merged.get(key)
        source_observation = {
            "name": profile["name"],
            "confidence": profile["confidence"],
            "category": profile["category"],
            "qualityTier": profile["qualityTier"],
            "observedAt": observed_at.isoformat(),
            "expiresAt": expires_at.isoformat(),
        }
        if not entry:
            merged[key] = {
                **normalised,
                "sources": [source_observation],
                "firstSeen": observed_at,
                "lastSeen": observed_at,
                "expiresAt": expires_at,
            }
            continue

        entry["firstSeen"] = min(entry["firstSeen"], observed_at)
        entry["lastSeen"] = max(entry["lastSeen"], observed_at)
        entry["expiresAt"] = max(entry["expiresAt"], expires_at)
        if not any(existing["name"] == source_observation["name"] for existing in entry["sources"]):
            entry["sources"].append(source_observation)

    indicators = []
    for entry in merged.values():
        source_confidence = max(source["confidence"] for source in entry["sources"])
        corroboration_bonus = min(10, 5 * max(0, len(entry["sources"]) - 1))
        confidence = min(99, source_confidence + corroboration_bonus)
        quality_tiers = {source["qualityTier"] for source in entry["sources"]}
        quality_tier = "verified" if "verified" in quality_tiers else "established-community" if "established-community" in quality_tiers else "community" if "community" in quality_tiers else "unclassified"
        indicators.append({
            "indicator": entry["indicator"],
            "indicatorType": entry["indicatorType"],
            "hostname": entry["hostname"],
            "confidence": confidence,
            "sourceCount": len(entry["sources"]),
            "qualityTier": quality_tier,
            "categories": sorted({source["category"] for source in entry["sources"]}),
            "sources": sorted({source["name"] for source in entry["sources"]}),
            "firstSeen": entry["firstSeen"].isoformat(),
            "lastSeen": entry["lastSeen"].isoformat(),
            "expiresAt": entry["expiresAt"].isoformat(),
        })

    indicators.sort(key=lambda item: (item["confidence"], item["lastSeen"]), reverse=True)
    snapshot = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": now.isoformat(),
        "expiresAt": (now + timedelta(hours=30)).isoformat(),
        "indicatorCount": min(len(indicators), MAX_INDICATORS),
        "indicators": indicators[:MAX_INDICATORS],
        "dataHandling": "Indicators are evidence signals with source and expiry metadata. They are not a guarantee that a URL is malicious or safe."
    }
    stats = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedAt": now.isoformat(),
        "processedRecords": processed,
        "rejectedRecords": rejected,
        "activeUniqueIndicators": len(indicators),
        "publishedIndicators": len(snapshot["indicators"]),
        "sourceCounts": dict(sorted(defaultdict(int, {source: sum(source in item["sources"] for item in indicators) for source in sorted({source for item in indicators for source in item["sources"]})}).items())),
    }
    return snapshot, stats


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> None:
    now = utc_now()
    # `chain` avoids retaining the raw feeds in memory while preserving a
    # deterministic source-aware merge into the compact published snapshot.
    from itertools import chain
    snapshot, stats = build_snapshot(chain(iter_live_verified_records(now), iter_records(INPUT_FILES)), now=now)
    write_json_atomic(OUTPUT_FILE, snapshot)
    write_json_atomic(STATS_FILE, stats)
    print(json.dumps({"publishedIndicators": snapshot["indicatorCount"], "processedRecords": stats["processedRecords"]}))


if __name__ == "__main__":
    main()
