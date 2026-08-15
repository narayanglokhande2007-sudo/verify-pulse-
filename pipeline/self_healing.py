#!/usr/bin/env python3
"""VerifyPulse controlled integrity verification and recovery planner.

This tool is intentionally fail-closed. It never downloads code, never contacts
external services, never deletes files, and never modifies the repository unless
a maintainer explicitly runs `restore --apply` with a local, trusted recovery
source. Any proposed replacement must match the expected SHA-256 hash in the
committed manifest before it is written.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_DIR = PROJECT_ROOT / "pipeline"
MANIFEST_PATH = PIPELINE_DIR / "critical_files_manifest.json"

CRITICAL_FILES = (
    "package.json",
    "index.html",
    "vercel.json",
    "api/verify.js",
    "lib/security_controls.js",
    "api/v1/scan.js",
    "lib/privacy_guard.js",
    "lib/canary_engine.js",
    "lib/ghost_agent.js",
    "lib/ghost_agent_pooled.js",
    "lib/db_helper.js",
    "lib/url_forensics.js",
    "lib/threat_intelligence.js",
    "lib/request_budget.js",
    "lib/intent_forensics.js",
    "lib/decision_calibration.js",
    "lib/shadow_evaluation.js",
    "api/brand_protection_api.js",
    "api/insurance_partnership_api.js",
    "pipeline/scam_hunter.py",
    "pipeline/build_threat_intelligence.py",
    "pipeline/brand_protection.py",
    "pipeline/threat_intelligence_report.py",
    "pipeline/pulse_agent_war_games.py",
    "pipeline/integrity_monitor.py",
    "pipeline/self_healing.py",
)


def safe_path(root: Path, relative_path: str) -> Path:
    """Resolve a manifest path without allowing traversal outside `root`."""
    candidate = (root / relative_path).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"Unsafe path in manifest: {relative_path}")
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest() -> Dict[str, str]:
    if not MANIFEST_PATH.is_file():
        raise FileNotFoundError(f"Missing required manifest: {MANIFEST_PATH}")

    raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    # Support the repository's flat JSON manifest to avoid breaking existing tooling.
    if not isinstance(raw, dict) or not all(isinstance(path, str) and isinstance(value, str) for path, value in raw.items()):
        raise ValueError("Manifest must be an object mapping repository paths to SHA-256 hashes.")

    for path, digest in raw.items():
        safe_path(PROJECT_ROOT, path)
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest.lower()):
            raise ValueError(f"Invalid SHA-256 digest for {path}")
    return raw


def build_manifest(files: Iterable[str] = CRITICAL_FILES) -> Dict[str, str]:
    manifest: Dict[str, str] = {}
    missing = []
    for relative_path in files:
        target = safe_path(PROJECT_ROOT, relative_path)
        if not target.is_file():
            missing.append(relative_path)
            continue
        manifest[relative_path] = sha256_file(target)
    if missing:
        raise FileNotFoundError(f"Cannot build manifest; missing critical files: {', '.join(missing)}")
    return dict(sorted(manifest.items()))


def verify_manifest(manifest: Dict[str, str]) -> Tuple[dict, list[dict]]:
    checked_at = datetime.now(timezone.utc).isoformat()
    issues: list[dict] = []
    entries: list[dict] = []

    for relative_path, expected_hash in manifest.items():
        target = safe_path(PROJECT_ROOT, relative_path)
        if not target.is_file():
            entry = {"path": relative_path, "status": "missing", "expectedSha256": expected_hash}
            issues.append(entry)
        else:
            actual_hash = sha256_file(target)
            if actual_hash != expected_hash:
                entry = {
                    "path": relative_path,
                    "status": "modified",
                    "expectedSha256": expected_hash,
                    "actualSha256": actual_hash,
                }
                issues.append(entry)
            else:
                entry = {"path": relative_path, "status": "verified", "sha256": actual_hash}
        entries.append(entry)

    report = {
        "checkedAt": checked_at,
        "repositoryRoot": str(PROJECT_ROOT),
        "manifestPath": str(MANIFEST_PATH),
        "verified": not issues,
        "entries": entries,
    }
    return report, issues


def print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def command_generate(args: argparse.Namespace) -> int:
    if not args.write:
        print_json({
            "generated": False,
            "message": "Dry run only. Re-run with --write after reviewing the intended critical-file baseline.",
            "proposedManifest": build_manifest(),
        })
        return 0

    manifest = build_manifest()
    temporary = MANIFEST_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(MANIFEST_PATH)
    print_json({"generated": True, "manifestPath": str(MANIFEST_PATH), "fileCount": len(manifest)})
    return 0


def command_verify(_: argparse.Namespace) -> int:
    report, issues = verify_manifest(load_manifest())
    print_json(report)
    return 0 if not issues else 1


def command_plan(_: argparse.Namespace) -> int:
    report, issues = verify_manifest(load_manifest())
    plan = {
        "createdAt": report["checkedAt"],
        "automaticChanges": False,
        "recoveryPolicy": "A human maintainer must review every item and supply a local trusted source before restore.",
        "issues": issues,
    }
    print_json(plan)
    return 0 if not issues else 1


def command_restore(args: argparse.Namespace) -> int:
    if not args.apply:
        print_json({
            "restored": False,
            "message": "Dry run only. No files were changed. Re-run with --apply and a verified local --source-root after human review.",
        })
        return 0

    source_root = Path(args.source_root).resolve()
    if not source_root.is_dir():
        raise FileNotFoundError(f"Trusted source root does not exist: {source_root}")

    manifest = load_manifest()
    _, issues = verify_manifest(manifest)
    candidates = [issue for issue in issues if issue["status"] in {"missing", "modified"}]
    restored = []
    rejected = []

    for issue in candidates:
        relative_path = issue["path"]
        expected_hash = manifest[relative_path]
        source = safe_path(source_root, relative_path)
        destination = safe_path(PROJECT_ROOT, relative_path)

        if not source.is_file():
            rejected.append({"path": relative_path, "reason": "trusted-source-file-missing"})
            continue
        if sha256_file(source) != expected_hash:
            rejected.append({"path": relative_path, "reason": "trusted-source-hash-mismatch"})
            continue

        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
            temporary_path = Path(handle.name)
        try:
            shutil.copyfile(source, temporary_path)
            if sha256_file(temporary_path) != expected_hash:
                raise RuntimeError("Temporary recovery copy did not match expected hash.")
            os.replace(temporary_path, destination)
            restored.append(relative_path)
        finally:
            temporary_path.unlink(missing_ok=True)

    print_json({
        "restored": restored,
        "rejected": rejected,
        "message": "Only source files matching the committed manifest were restored. Review the resulting repository diff before deployment.",
    })
    return 0 if not rejected else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VerifyPulse fail-closed integrity and recovery utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="Show or explicitly write a new baseline manifest")
    generate.add_argument("--write", action="store_true", help="Write the manifest after review")
    generate.set_defaults(func=command_generate)

    verify = subparsers.add_parser("verify", help="Check working files against the committed manifest")
    verify.set_defaults(func=command_verify)

    plan = subparsers.add_parser("plan", help="Produce a no-change recovery plan for any integrity issues")
    plan.set_defaults(func=command_plan)

    restore = subparsers.add_parser("restore", help="Restore only hash-verified files from a trusted local source")
    restore.add_argument("--source-root", required=True, help="Local trusted repository copy that matches the manifest")
    restore.add_argument("--apply", action="store_true", help="Required acknowledgement before any write occurs")
    restore.set_defaults(func=command_restore)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print_json({"ok": False, "error": str(error)})
        return 2


if __name__ == "__main__":
    sys.exit(main())
