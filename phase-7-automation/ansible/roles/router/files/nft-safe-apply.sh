#!/usr/bin/env bash
# ===========================================================================
# nft-safe-apply.sh — commit-confirm safety net for hand-testing nftables
# changes on rtr-01, BEFORE committing them to the router role.
#
# rtr-01 is simultaneously the firewall and the only SSH jump host into every
# internal segment (docs/00-ip-plan.md) — a bad ruleset locks you out of the
# whole network with no documented way back in except the VMware Fusion
# console (see docs/RUNBOOK.md's OOB recovery note). This is the same
# commit-confirm pattern production network gear (Junos/IOS-XR's `commit
# confirmed`) builds in natively: apply the change, auto-revert to the
# pre-apply ruleset unless a human confirms within N minutes.
#
# Deliberately NOT wired into the Ansible converge path: `make converge` is
# meant to run unattended and idempotently (docs/RUNBOOK.md), and a mandatory
# confirm-or-revert would make every automated converge revert itself, since
# nothing is there to confirm it. This is a manual tool for the moment real
# lockouts actually happen — iterating on a rule live, before it's proven
# safe enough to commit to nftables.conf.
#
# No `at`/atd dependency (not installed by default, and adding a package just
# for this is unnecessary) — `systemd-run --on-active` schedules the one-shot
# revert natively; Debian 13 already ships systemd.
#
# Your new-ruleset file should start with `flush ruleset` (same as
# nftables.conf itself) — a full declarative replace, not an additive one.
# The LKG snapshot this script captures internally does this for you (a bare
# `nft list ruleset` dump has no flush statement; reapplying it via `nft -f`
# onto an already-populated ruleset was confirmed live to APPEND a duplicate
# copy of every rule rather than replace them — caught by an actual
# apply/wait/auto-revert/diff test cycle, not assumed).
#
# Usage (run from a session you're prepared to lose — that's the whole point):
#   sudo nft-safe-apply.sh <new-ruleset-file> [timeout-minutes, default 5]
#   sudo nft-safe-apply.sh confirm            # cancel the pending auto-revert
#   sudo nft-safe-apply.sh --revert           # internal — invoked by the timer
# ===========================================================================
set -euo pipefail

STATE_DIR=/root/nft-safe-apply
LKG_FILE="$STATE_DIR/pending-revert.conf"
UNIT=nft-safe-apply-revert

mkdir -p "$STATE_DIR"

case "${1:-}" in
  confirm)
    systemctl stop "${UNIT}.timer" 2>/dev/null || true
    systemctl reset-failed "${UNIT}" 2>/dev/null || true
    rm -f "$LKG_FILE"
    logger -t nft-safe-apply "confirmed by operator, auto-revert cancelled"
    echo "Confirmed — scheduled auto-revert cancelled. Ruleset stays as applied."
    ;;

  --revert)
    if [ -f "$LKG_FILE" ]; then
      nft -f "$LKG_FILE"
      logger -t nft-safe-apply "AUTO-REVERTED: not confirmed within the timeout — restored the pre-apply ruleset"
      rm -f "$LKG_FILE"
    fi
    ;;

  ""|-h|--help)
    echo "usage: nft-safe-apply.sh <new-ruleset-file> [timeout-minutes] | confirm" >&2
    exit 2
    ;;

  *)
    NEW_FILE="$1"
    TIMEOUT="${2:-5}"
    [ -f "$NEW_FILE" ] || { echo "no such file: $NEW_FILE" >&2; exit 1; }

    # Only capture a fresh last-known-good if nothing is already pending —
    # re-running this to try a SECOND change before confirming the first must
    # keep reverting all the way back to the original state, not just to the
    # unconfirmed intermediate one. `flush ruleset` prefix is required: a
    # bare `nft list ruleset` dump has none, and reapplying it via `nft -f`
    # onto a live ruleset APPENDS a duplicate of every rule instead of
    # replacing them (confirmed live — see the header note).
    if [ ! -f "$LKG_FILE" ]; then
      { echo "flush ruleset"; nft list ruleset; } > "$LKG_FILE"
    fi

    # Same single-transaction apply the router role's own handler uses
    # (nft -f begins with `flush ruleset`, so there's never a window with the
    # firewall down) — this tool tests the exact command a real converge runs.
    nft -f "$NEW_FILE"

    # (Re)schedule the auto-revert. --on-active is relative to "now", so this
    # always means "N minutes from this apply," not a wall-clock time — and
    # re-running against a second change correctly resets the countdown.
    systemctl stop "${UNIT}.timer" 2>/dev/null || true
    systemctl reset-failed "${UNIT}" 2>/dev/null || true
    systemd-run --unit="$UNIT" --on-active="${TIMEOUT}min" \
      /usr/local/sbin/nft-safe-apply.sh --revert

    logger -t nft-safe-apply "applied $NEW_FILE, auto-revert armed for ${TIMEOUT}min unless confirmed"
    echo "Applied $NEW_FILE. Auto-reverts to the pre-apply ruleset in ${TIMEOUT} minute(s)"
    echo "unless confirmed. From a session you know still works:"
    echo "  sudo nft-safe-apply.sh confirm"
    ;;
esac
