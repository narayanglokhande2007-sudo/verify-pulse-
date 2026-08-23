#!/usr/bin/env python3
"""Bounded VerifyPulse scam-feed collector.

The live scanner does not need a permanently growing raw Git repository. This
collector fetches a small vetted public-feed set with strict per-source limits,
keeps only a compact current input set for threat-intelligence construction, and
writes source-health evidence. Permanent reputation observations are handled by
the separate hashed historical-index refresher.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from socket import timeout as SocketTimeout
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "daily-data"
INDIA_OUTPUT = DATA_DIR / "india_scams.jsonl"
GLOBAL_OUTPUT = DATA_DIR / "global_scams.jsonl"
LATEST_OUTPUT = DATA_DIR / "latest_scams.json"
HEALTH_OUTPUT = DATA_DIR / "source_health.json"

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_RECORDS_PER_SOURCE = 600
DEFAULT_MIN_SUCCESSFUL_SOURCES = 2
REQUEST_TIMEOUT_SECONDS = 12
MAX_FETCH_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = (1, 2)
RETRYABLE_HTTP_STATUS_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})

# Small, source-attributed set. Adding a source requires a health/reliability
# review; do not restore unbounded bulk collection here.
SOURCE_CATALOG = (
    ("https://urlhaus.abuse.ch/downloads/text/", "URLhaus"),
    ("https://openphish.com/feed.txt", "OpenPhish"),
    ("https://phishing.army/download/phishing_army_blocklist_extended.txt", "Phishing Army"),
    ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt", "Phishing.Database"),
    ("https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt", "Blackbook"),
)

INDIA_MARKERS = (
    "sbi", "onlinesbi", "yono", "hdfc", "icici", "axis", "pnb", "kotak", "rbi", "kyc", "aadhaar", "aadhar",
    "pan", "upi", "phonepe", "paytm", "gpay", "bhim", "razorpay", "cashfree", ".in", ".co.in", ".gov.in", ".nic.in",
    "india", "bharat", "irctc", "epfo", "income tax", "digital arrest",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def public_host(host: str) -> bool:
    candidate = host.strip().lower().rstrip(".")
    if not candidate or candidate == "localhost" or candidate.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(candidate)
        return not (address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified)
    except ValueError:
        return bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", candidate))


def canonical_indicator(raw: str) -> str | None:
    value = str(raw or "").strip()
    if not value or value.startswith(("#", "//", "!")):
        return None
    tokens = value.split()
    if len(tokens) > 1 and tokens[0] in {"0.0.0.0", "127.0.0.1", "::"}:
        value = tokens[1]
    else:
        value = tokens[0].split(",", 1)[0]
    value = value.strip("'\"()[]{}<>,.;")
    if not value:
        return None
    candidate = value if re.match(r"^https?://", value, re.IGNORECASE) else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if parsed.username or parsed.password or not public_host(parsed.hostname or ""):
        return None
    path = parsed.path or ""
    return urlunsplit((parsed.scheme.lower(), (parsed.hostname or "").lower(), path, "", ""))


def india_related(indicator: str) -> bool:
    lowered = indicator.lower()
    return any(marker in lowered for marker in INDIA_MARKERS)


def is_retryable_fetch_error(error: Exception) -> bool:
    """Return true only for short-lived network or upstream-service failures."""
    if isinstance(error, HTTPError):
        return error.code in RETRYABLE_HTTP_STATUS_CODES
    return isinstance(error, (SocketTimeout, TimeoutError, URLError))


def fetch_source(url: str, name: str, *, max_records: int, observed_at: str) -> tuple[list[dict[str, str]], dict[str, Any]]:
    health: dict[str, Any] = {
        "name": name,
        "provenance": url,
        "checkedAt": observed_at,
        "status": "failed",
        "acceptedRecords": 0,
        "bytesRead": 0,
        "truncated": False,
        "attempts": 0,
        "retryRecovered": False,
    }
    content: bytes | None = None
    last_error: Exception | None = None

    for attempt in range(1, MAX_FETCH_ATTEMPTS + 1):
        health["attempts"] = attempt
        try:
            request = Request(url, headers={"User-Agent": "VerifyPulse-BoundedCollector/1.0"})
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                content = response.read(MAX_RESPONSE_BYTES + 1)
            health["retryRecovered"] = attempt > 1
            break
        except Exception as error:
            last_error = error
            if attempt == MAX_FETCH_ATTEMPTS or not is_retryable_fetch_error(error):
                break
            time.sleep(RETRY_BACKOFF_SECONDS[attempt - 1])

    if content is None:
        if last_error is not None:
            health["error"] = f"{type(last_error).__name__}: {str(last_error)[:180]}"
            health["retryableFailure"] = is_retryable_fetch_error(last_error)
        return [], health

    health["truncated"] = len(content) > MAX_RESPONSE_BYTES
    health["bytesRead"] = min(len(content), MAX_RESPONSE_BYTES)
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in content[:MAX_RESPONSE_BYTES].decode("utf-8", errors="ignore").splitlines():
        indicator = canonical_indicator(line)
        if not indicator or indicator in seen:
            continue
        seen.add(indicator)
        records.append({
            "url": indicator,
            "source": url,
            "type": f"{name} public threat indicator",
            "date_added": observed_at,
        })
        if len(records) >= max_records:
            break
    health["acceptedRecords"] = len(records)
    health["status"] = "partial" if health["truncated"] else "ok"
    return records, health


def write_records(path: Path, records: list[dict[str, str]]) -> None:
    atomic_write(path, "".join(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n" for record in records))


def collect(*, max_records_per_source: int, minimum_successful_sources: int) -> dict[str, Any]:
    observed_at = utc_now().isoformat()
    all_records: list[dict[str, str]] = []
    health_entries: list[dict[str, Any]] = []
    seen: set[str] = set()

    for url, name in SOURCE_CATALOG:
        records, health = fetch_source(url, name, max_records=max_records_per_source, observed_at=observed_at)
        health_entries.append(health)
        for record in records:
            if record["url"] in seen:
                continue
            seen.add(record["url"])
            all_records.append(record)

    successful_sources = sum(item["status"] in {"ok", "partial"} and item["acceptedRecords"] > 0 for item in health_entries)
    india_records = [record for record in all_records if india_related(record["url"])]
    global_records = [record for record in all_records if record not in india_records]
    write_records(INDIA_OUTPUT, india_records)
    write_records(GLOBAL_OUTPUT, global_records)
    atomic_write(LATEST_OUTPUT, json.dumps([record["url"] for record in all_records[:200]], ensure_ascii=False, indent=2) + "\n")

    health = {
        "schemaVersion": "vp-bounded-feed-health-1",
        "generatedAt": observed_at,
        "sourceCount": len(SOURCE_CATALOG),
        "successfulSources": successful_sources,
        "acceptedRecords": len(all_records),
        "indiaRecords": len(india_records),
        "globalRecords": len(global_records),
        "maxRecordsPerSource": max_records_per_source,
        "sources": health_entries,
    }
    atomic_write(HEALTH_OUTPUT, json.dumps(health, ensure_ascii=False, indent=2) + "\n")
    if successful_sources < minimum_successful_sources:
        raise RuntimeError(f"Only {successful_sources} usable sources; require at least {minimum_successful_sources}.")
    return health


def main() -> int:
    parser = argparse.ArgumentParser(description="Build compact VerifyPulse scam-feed inputs")
    parser.add_argument("--max-records-per-source", type=int, default=DEFAULT_MAX_RECORDS_PER_SOURCE)
    parser.add_argument("--min-successful-sources", type=int, default=DEFAULT_MIN_SUCCESSFUL_SOURCES)
    args = parser.parse_args()
    if not 1 <= args.max_records_per_source <= 1000:
        parser.error("--max-records-per-source must be between 1 and 1000")
    if not 1 <= args.min_successful_sources <= len(SOURCE_CATALOG):
        parser.error("--min-successful-sources must fit the source catalog")
    try:
        result = collect(max_records_per_source=args.max_records_per_source, minimum_successful_sources=args.min_successful_sources)
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except RuntimeError as error:
        print(json.dumps({"valid": False, "error": str(error)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
