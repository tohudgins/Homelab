#!/usr/bin/env bash
# Retention for Wazuh's full-event archives + alerts logs.
#
# WHY THIS EXISTS: Wazuh already rotates these on its own (a new file per day,
# auto-gzipped once the day closes — confirmed live: /var/ossec/logs/archives/2026/Sep
# has both live .json and already-compressed .json.gz files). What it does NOT do is
# ever delete old ones — logall_json (enabled in tasks/main.yml for threat-hunting
# telemetry) means every day adds another file, forever. On a homelab-sized disk
# (32G free observed 2026-09-26) this isn't an emergency, but it's a real, predictable
# problem on any long enough timeline, which is exactly what the siem role's own code
# comment predicted ("archives grow fast, so a production deployment pairs this with
# rotation/retention").
#
# Deletes archive/alert files (raw or .gz, plus their .sum sidecars) whose mtime is
# older than RETENTION_DAYS, then prunes any year/month directories that are left
# empty. Logs a one-line summary per run so the cleanup is auditable, not silent.
#
# Usage: wazuh-log-retention.sh [--dry-run]
set -euo pipefail

RETENTION_DAYS="${WAZUH_LOG_RETENTION_DAYS:-90}"
LOG_DIRS=(/var/ossec/logs/archives /var/ossec/logs/alerts)
RUN_LOG=/var/ossec/logs/retention.log
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

total_count=0
total_bytes=0

for dir in "${LOG_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    # Only the dated per-day files under year/month subdirs are candidates for
    # deletion — never the top-level "live" archives.json/alerts.json symlink-like
    # current file, which mtime naturally excludes anyway since it's written to
    # continuously and can never be older than RETENTION_DAYS.
    mapfile -d '' -t matches < <(find "$dir" -mindepth 3 -maxdepth 3 -type f \
        \( -name '*.log' -o -name '*.json' -o -name '*.log.gz' -o -name '*.json.gz' \
           -o -name '*.log.sum' -o -name '*.json.sum' \) \
        -mtime "+${RETENTION_DAYS}" -print0)

    for f in "${matches[@]}"; do
        sz=$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || echo 0)
        total_bytes=$((total_bytes + sz))
        total_count=$((total_count + 1))
        if [[ "$DRY_RUN" -eq 1 ]]; then
            echo "[dry-run] would delete: $f (${sz} bytes)"
        else
            rm -f -- "$f"
        fi
    done
done

if [[ "$DRY_RUN" -eq 0 ]]; then
    # Clean up any year/month directories that are now empty.
    for dir in "${LOG_DIRS[@]}"; do
        [[ -d "$dir" ]] || continue
        find "$dir" -mindepth 2 -maxdepth 2 -type d -empty -delete 2>/dev/null || true
    done
    printf '%s retention_days=%s deleted_files=%s freed_bytes=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$RETENTION_DAYS" "$total_count" "$total_bytes" \
        >> "$RUN_LOG"
else
    printf '[dry-run] retention_days=%s would_delete_files=%s would_free_bytes=%s\n' \
        "$RETENTION_DAYS" "$total_count" "$total_bytes"
fi
