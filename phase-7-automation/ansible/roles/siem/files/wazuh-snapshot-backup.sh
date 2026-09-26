#!/usr/bin/env bash
# Real point-in-time backup of the Wazuh indexer's DATA (alerts, statistics,
# monitoring, vulnerability/inventory indices) via OpenSearch's native snapshot
# API — not just a config tar. Config (rules/decoders/ossec.conf) is already
# reproducible from this repo via Ansible; the alert HISTORY is not, and
# VM-snapshot-level DR (a VMware snapshot of the whole disk) is the only thing
# that previously protected it, which is coarse (whole-VM, not queryable/
# restorable per-index) and easy to forget to take before risky changes.
#
# Uses the `snapshotrestore` indexer user Wazuh's own installer provisions
# specifically for this (see wazuh-passwords.txt) rather than `admin` —
# least-privilege: this account can only do snapshot/restore operations, not
# read or modify data, so a compromised backup cron job can't exfiltrate or
# tamper with detection history.
#
# Usage: WAZUH_SNAPSHOTRESTORE_PASSWORD=... wazuh-snapshot-backup.sh
set -euo pipefail

BASE_URL="https://127.0.0.1:9200"
REPO="${WAZUH_SNAPSHOT_REPO:-lab_backup}"
RETENTION_DAYS="${WAZUH_SNAPSHOT_RETENTION_DAYS:-30}"
PASS="${WAZUH_SNAPSHOTRESTORE_PASSWORD:?WAZUH_SNAPSHOTRESTORE_PASSWORD must be set}"
LOG=/var/log/wazuh-snapshot-backup.log
SNAP="lab-$(date -u +%Y%m%d-%H%M%S)"
AUTH=(-u "snapshotrestore:${PASS}")

result=$(curl -sk "${AUTH[@]}" -X PUT \
    "${BASE_URL}/_snapshot/${REPO}/${SNAP}?wait_for_completion=true" \
    -H 'Content-Type: application/json' \
    -d '{"indices":"wazuh-alerts-*,wazuh-statistics-*,wazuh-monitoring-*,wazuh-states-*","ignore_unavailable":true,"include_global_state":false}')

state=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('snapshot',{}).get('state','UNKNOWN'))" 2>/dev/null || echo "PARSE_ERROR")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) snapshot=${SNAP} state=${state}" >> "$LOG"

if [[ "$state" != "SUCCESS" ]]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) WARNING: snapshot ${SNAP} did not report SUCCESS: $result" >> "$LOG"
fi

# Retention: delete snapshots older than RETENTION_DAYS, by the date encoded in
# the snapshot's own name (lab-YYYYMMDD-HHMMSS) rather than trusting a
# separately-tracked timestamp — the name IS the record.
cutoff=$(date -u -d "-${RETENTION_DAYS} days" +%Y%m%d)
old_snapshots=$(curl -sk "${AUTH[@]}" "${BASE_URL}/_snapshot/${REPO}/_all" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for s in data.get('snapshots', []):
    name = s.get('snapshot', '')
    parts = name.split('-')
    if len(parts) >= 2 and parts[0] == 'lab' and parts[1] < '${cutoff}':
        print(name)
")

for s in $old_snapshots; do
    curl -sk "${AUTH[@]}" -X DELETE "${BASE_URL}/_snapshot/${REPO}/${s}" -o /dev/null
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) deleted old snapshot=${s}" >> "$LOG"
done
