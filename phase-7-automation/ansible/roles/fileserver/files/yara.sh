#!/usr/bin/env bash
# ===========================================================================
# yara.sh — Wazuh active-response: scan a FIM-changed file with YARA (fs-01).
#
# Triggered by the manager when a file is added/modified in the monitored share
# (rule 100450). Wazuh runs this on the agent, passing the triggering alert as
# JSON on stdin (AR protocol v4). We pull the changed file's path out of
# .parameters.alert.syscheck.path, scan it against the deployed ruleset, and on a
# match write a `wazuh-yara:` line to active-responses.log — which the manager
# ingests and rule 100460/100461 turn into a malware alert (T1204 / Impact).
#
# The detection is the scan RESULT, not the file write: FIM says "a file changed",
# YARA says "and it matches known-malicious signatures". Deployed to
# /var/ossec/active-response/bin/yara by the fileserver role.
# ===========================================================================
set -u

LOG_FILE="/var/ossec/logs/active-responses.log"
YARA_BIN="${YARA_BIN:-/usr/bin/yara}"
YARA_RULES="${YARA_RULES:-/var/ossec/ruleset/yara/rules/malware.yar}"

# AR protocol v4: a single JSON object on stdin.
read -r INPUT_JSON

# Prefer jq (installed by the role); fall back to a tolerant grep/sed extraction
# so a missing jq degrades to "still works" rather than "silently scans nothing".
if command -v jq >/dev/null 2>&1; then
  FILENAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path // empty')
  COMMAND=$(echo "$INPUT_JSON" | jq -r '.command // empty')
else
  FILENAME=$(echo "$INPUT_JSON" | sed -n 's/.*"path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  COMMAND=$(echo "$INPUT_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
fi

# Wazuh sends "add" to run the AR and "delete" to tear it down; only scan on add.
[ "$COMMAND" = "delete" ] && exit 0
[ -z "${FILENAME:-}" ] && exit 0
[ -r "$FILENAME" ] || exit 0
[ -x "$YARA_BIN" ] || { echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-yara: ERROR - yara not found at $YARA_BIN" >> "$LOG_FILE"; exit 1; }
[ -r "$YARA_RULES" ] || { echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-yara: ERROR - ruleset not found at $YARA_RULES" >> "$LOG_FILE"; exit 1; }

# Scan. `-w` silences warnings, `-f` fast mode; one line per matching rule.
YARA_OUTPUT=$("$YARA_BIN" -w -f -r "$YARA_RULES" "$FILENAME" 2>/dev/null)

if [ -n "$YARA_OUTPUT" ]; then
  while read -r LINE; do
    # yara prints: "<rule_name> <scanned_path>"
    RULE_NAME=$(echo "$LINE" | awk '{print $1}')
    echo "$(date '+%Y/%m/%d %H:%M:%S') wazuh-yara: INFO - Scan result: $RULE_NAME $FILENAME" >> "$LOG_FILE"
  done <<< "$YARA_OUTPUT"
fi

exit 0
