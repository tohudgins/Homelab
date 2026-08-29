#!/usr/bin/env bash
# Credentialed (authenticated) Greenbone scan of dc-01 — the deepening the
# active-vs-passive writeup only hypothesised. Run with sudo on scan-01.
set -euo pipefail
PROJECT="greenbone-community-edition"; DEPLOY_DIR="/opt/greenbone"
GMP_USER="admin"; GMP_PASS="GreenboneAdmin2026!"
# Dedicated least-privilege scan service account on dc-01 (NOT a human login) —
# created by the `windows`/host setup, documented in the vault Virtual Machines note.
CRED_NAME="dc-01 ssh (gvm-scan)"; CRED_LOGIN="gvm-scan"; CRED_PASS="GvmScan2026x"
TARGET_NAME="dc-01 credentialed"; TARGET_HOSTS="10.10.10.10"
TASK_NAME="dc-01 credentialed full-and-fast"
CONFIG_ID="daba56c8-73ec-11df-a475-002264764cea"       # Full and fast
SCANNER_ID="08b69003-5fc2-4037-a479-93b440211c73"      # OpenVAS Default
PORT_LIST_ID="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"    # All IANA assigned TCP
ALIVE_TEST="Consider Alive"
cd "$DEPLOY_DIR"

gmp() { docker compose -p "$PROJECT" run --rm --no-deps -T gvm-tools \
  gvm-cli --gmp-username "$GMP_USER" --gmp-password "$GMP_PASS" \
  socket --socketpath /run/gvmd/gvmd.sock --xml "$1" 2>/dev/null; }
pick_id() { python3 -c '
import sys, xml.etree.ElementTree as ET
elem, want = sys.argv[1], sys.argv[2]
try: root = ET.fromstring(sys.stdin.read())
except ET.ParseError: sys.exit(0)
for e in root.iter(elem):
    if (e.findtext("name") or "") == want: print(e.get("id") or ""); break
' "$1" "$2"; }
attr_id() { python3 -c "import sys,xml.etree.ElementTree as ET;print(ET.fromstring(sys.stdin.read()).get('id') or '')"; }

if [ "${1:-}" = "status" ]; then
  gmp '<get_tasks/>' | python3 -c '
import sys, xml.etree.ElementTree as ET
r = ET.fromstring(sys.stdin.read())
for t in r.iter("task"):
    print("  %-34s %-12s %s%%" % ((t.findtext("name") or ""),(t.findtext("status") or ""),(t.findtext("progress") or "")))'
  exit 0
fi

echo "== credential =="
CRED_ID="$(gmp '<get_credentials/>' | pick_id credential "$CRED_NAME" || true)"
if [ -z "$CRED_ID" ]; then
  CRED_ID="$(gmp "<create_credential><name>${CRED_NAME}</name><type>up</type><login>${CRED_LOGIN}</login><password>${CRED_PASS}</password></create_credential>" | attr_id || true)"
  echo "  created credential = $CRED_ID"
else echo "  reusing credential = $CRED_ID"; fi
[ -n "$CRED_ID" ] || { echo "!! no credential"; exit 1; }

echo "== credentialed target =="
TARGET_ID="$(gmp '<get_targets/>' | pick_id target "$TARGET_NAME" || true)"
if [ -z "$TARGET_ID" ]; then
  TARGET_ID="$(gmp "<create_target><name>${TARGET_NAME}</name><hosts>${TARGET_HOSTS}</hosts><port_list id=\"${PORT_LIST_ID}\"/><alive_tests>${ALIVE_TEST}</alive_tests><ssh_credential id=\"${CRED_ID}\"><port>22</port></ssh_credential></create_target>" | attr_id || true)"
  echo "  created target = $TARGET_ID"
else echo "  reusing target = $TARGET_ID"; fi
[ -n "$TARGET_ID" ] || { echo "!! no target"; exit 1; }

echo "== task =="
TASK_ID="$(gmp '<get_tasks/>' | pick_id task "$TASK_NAME" || true)"
if [ -z "$TASK_ID" ]; then
  TASK_ID="$(gmp "<create_task><name>${TASK_NAME}</name><config id=\"${CONFIG_ID}\"/><target id=\"${TARGET_ID}\"/><scanner id=\"${SCANNER_ID}\"/></create_task>" | attr_id || true)"
  echo "  created task = $TASK_ID"
else echo "  reusing task = $TASK_ID"; fi
[ -n "$TASK_ID" ] || { echo "!! no task"; exit 1; }

echo "== start =="
gmp "<start_task task_id=\"${TASK_ID}\"/>" | grep -o 'status="[0-9]*"[^>]*' | head -1 || true
echo "TASK_ID=$TASK_ID"
