#!/usr/bin/env bash
# ===========================================================================
# run-attack.sh — credential + sync wrapper for the two scripts that need
# ADMIN_USER/ADMIN_PW (ws-01's local-admin Windows creds):
#
#   ./run-attack.sh capstone [run-scenario.sh args, e.g. --verify]
#       Rsyncs the current phase-5-offense/apt-scenario/ up to atk-01
#       (~/capstone/apt-scenario/), then runs run-scenario.sh there with
#       ADMIN_USER/ADMIN_PW/SPRAY_PW forwarded — so an edit to the script
#       doesn't need a manual re-copy, and creds never get typed by hand.
#
#   ./run-attack.sh ad-validate [ad-validate.py args]
#       Runs phase-5-offense/purple-team/ad-validate.py in place (it SSHes
#       out to atk-01/dc-01/fs-01/ws-01/siem-01 itself per-command — nothing
#       to sync), with the same creds exported into this shell first.
#
# Both read ADMIN_USER/ADMIN_PW from scripts/.lab-secrets (git-ignored) the
# same way lab.sh already does for WS01_VMENC_PASS — see that file's own
# comment. Falls back to whatever's already in your environment if
# .lab-secrets doesn't set them, so an explicit
# `ADMIN_USER=x ADMIN_PW=y ./run-attack.sh ...` still works.
# ===========================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
[ -f "$HERE/.lab-secrets" ] && . "$HERE/.lab-secrets"

REPO="$(cd "$HERE/.." && pwd)"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_PW="${ADMIN_PW:-}"
SPRAY_PW="${SPRAY_PW:-Summer2026}"

[ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PW" ] \
  || echo "! ADMIN_USER/ADMIN_PW not set (scripts/.lab-secrets or the environment) — WMI/WinRM/PsExec steps will skip cleanly, everything else still runs" >&2

usage() { echo "usage: $0 capstone [run-scenario.sh args] | ad-validate [ad-validate.py args]"; exit 2; }

mode="${1:-}"; [ -n "$mode" ] || usage; shift || true

case "$mode" in
  capstone)
    echo "Syncing phase-5-offense/apt-scenario/ to atk-01:~/capstone/apt-scenario/ ..."
    rsync -az --delete "$REPO/phase-5-offense/apt-scenario/" atk-01:~/capstone/apt-scenario/
    ssh atk-01 "cd ~/capstone/apt-scenario && SPRAY_PW='$SPRAY_PW' ADMIN_USER='$ADMIN_USER' ADMIN_PW='$ADMIN_PW' ./run-scenario.sh $*"
    ;;
  ad-validate)
    exec env ADMIN_USER="$ADMIN_USER" ADMIN_PW="$ADMIN_PW" \
      "$REPO/phase-5-offense/purple-team/ad-validate.py" "$@"
    ;;
  *) usage ;;
esac
