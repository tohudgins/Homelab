#!/usr/bin/env bash
# "Who watches the watchmen?" — nothing in this lab previously monitored the
# monitoring stack's own availability (Wazuh's <agents_disconnection_time>
# only tracks AGENTS dropping out, not the manager itself going down). If
# siem-01 dies, Wazuh obviously can't alert on its own outage — that check
# has to run from somewhere else. rtr-01 is the only host that's always up
# in every run profile (it's the gateway everything else depends on), so
# it's the only honest place for this to live.
#
# Checks TCP reachability of siem-01's agent-data port (1514) — the actual
# port every other host's Wazuh agent depends on, not just a ping. State is
# tracked in a file so this only logs on a genuine UP<->DOWN TRANSITION, not
# every 5-minute tick — the same coalesce-don't-repeat principle as any
# alerting pipeline (a check that logs "still down" every 5 minutes for a
# multi-hour outage is noise, not signal).
#
# Usage: monitor-siem-availability.sh
set -euo pipefail

SIEM_HOST="${SIEM_HOST:-10.10.30.10}"
SIEM_PORT="${SIEM_PORT:-1514}"
STATE_FILE=/var/log/siem-monitor-state
LOG_FILE=/var/log/siem-monitor.log

if timeout 5 bash -c "exec 3<>/dev/tcp/${SIEM_HOST}/${SIEM_PORT}" 2>/dev/null; then
    current=UP
else
    current=DOWN
fi

previous=""
[[ -f "$STATE_FILE" ]] && previous=$(cat "$STATE_FILE")

if [[ "$current" != "$previous" ]]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) siem-01 (${SIEM_HOST}:${SIEM_PORT}) transitioned ${previous:-UNKNOWN} -> ${current}" >> "$LOG_FILE"
fi

echo "$current" > "$STATE_FILE"
