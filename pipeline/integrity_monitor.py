import os
import hashlib
import json
from datetime import datetime

# Configuration
CRITICAL_FILES_MANIFEST = os.path.join(os.path.dirname(__file__), 'critical_files_manifest.json')
INTEGRITY_LOG = os.path.join(os.path.dirname(__file__), 'integrity_log.jsonl')

# List of critical files to monitor (relative to project root)
CRITICAL_FILES = [
    'api/verify.js',
    'api/ghost_agent.js',
    'api/db_helper.js',
    'api/brand_protection_api.js',
    'api/insurance_partnership_api.js',
    'pipeline/scam_hunter.py',
    'pipeline/brand_protection.py',
    'pipeline/threat_intelligence_report.py',
    'pipeline/pulse_agent_war_games.py',
    'pipeline/integrity_monitor.py' # Monitor itself as well
]

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def calculate_file_hash(filepath):
    """Calculates the SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def generate_manifest():
    """Generates a manifest of critical files with their hashes."""
    manifest = {}
    for rel_path in CRITICAL_FILES:
        full_path = os.path.join(PROJECT_ROOT, rel_path)
        if os.path.exists(full_path):
            manifest[rel_path] = calculate_file_hash(full_path)
        else:
            print(f"Warning: Critical file not found during manifest generation: {rel_path}")
    
    with open(CRITICAL_FILES_MANIFEST, 'w') as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest generated at {CRITICAL_FILES_MANIFEST}")

def check_integrity():
    """Checks the integrity of critical files against the manifest."""
    if not os.path.exists(CRITICAL_FILES_MANIFEST):
        print("Error: Critical files manifest not found. Generating new one.")
        generate_manifest()
        return

    with open(CRITICAL_FILES_MANIFEST, 'r') as f:
        manifest = json.load(f)

    issues_found = False
    log_entries = []

    for rel_path in CRITICAL_FILES:
        full_path = os.path.join(PROJECT_ROOT, rel_path)
        status = "OK"
        details = ""

        if not os.path.exists(full_path):
            status = "MISSING"
            details = "File is missing."
            issues_found = True
        elif rel_path not in manifest:
            status = "NEW_UNTRACKED"
            details = "File exists but is not in manifest. Consider adding."
            issues_found = True
        else:
            current_hash = calculate_file_hash(full_path)
            if current_hash != manifest[rel_path]:
                status = "MODIFIED"
                details = f"File hash mismatch. Expected: {manifest[rel_path]}, Found: {current_hash}"
                issues_found = True
        
        if status != "OK":
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "file": rel_path,
                "status": status,
                "details": details
            }
            log_entries.append(log_entry)
            print(f"Integrity Issue: {rel_path} - {status} ({details})")
        else:
            print(f"Integrity Check: {rel_path} - {status}")

    if log_entries:
        with open(INTEGRITY_LOG, 'a') as f:
            for entry in log_entries:
                f.write(json.dumps(entry) + '\n')
        print(f"Integrity issues logged to {INTEGRITY_LOG}")
    
    if not issues_found:
        print("✅ All critical files are intact and unmodified.")
    else:
        print("⚠️ Integrity check completed with issues.")

def self_heal():
    """Attempts to self-heal missing or modified files based on a backup/template."""
    print("\n--- Attempting Self-Healing ---")
    # This is a placeholder. In a real system, you would have a secure backup
    # or a way to fetch original versions of files.
    # For now, we'll just report what *would* be healed.

    if not os.path.exists(CRITICAL_FILES_MANIFEST):
        print("Cannot self-heal: Manifest not found. Please generate manifest first.")
        return

    with open(CRITICAL_FILES_MANIFEST, 'r') as f:
        manifest = json.load(f)

    healed_count = 0
    for rel_path in CRITICAL_FILES:
        full_path = os.path.join(PROJECT_ROOT, rel_path)
        
        if not os.path.exists(full_path) or (rel_path in manifest and calculate_file_hash(full_path) != manifest[rel_path]):
            print(f"Simulating heal for: {rel_path} (Missing or Modified)")
            # In a real scenario, you would copy from a secure backup:
            # shutil.copy(os.path.join(BACKUP_DIR, rel_path), full_path)
            # For this simulation, we'll just log it.
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "file": rel_path,
                "action": "SELF_HEAL_ATTEMPTED",
                "details": "File was missing or modified, self-healing simulated."
            }
            with open(INTEGRITY_LOG, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            healed_count += 1

    if healed_count > 0:
        print(f"Simulated self-healing for {healed_count} files. Please manually verify and re-generate manifest.")
    else:
        print("No critical files required self-healing.")


if __name__ == '__main__':
    # Ensure the pipeline directory exists for logs and manifest
    os.makedirs(os.path.dirname(CRITICAL_FILES_MANIFEST), exist_ok=True)

    print("Choose an action:")
    print("1. Generate Manifest (Run this first or after major updates)")
    print("2. Check Integrity")
    print("3. Attempt Self-Heal (Simulated)")
    
    choice = input("Enter choice (1/2/3): ")

    if choice == '1':
        generate_manifest()
    elif choice == '2':
        check_integrity()
    elif choice == '3':
        self_heal()
    else:
        print("Invalid choice.")
