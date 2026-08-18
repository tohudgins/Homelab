#!/usr/bin/env bash
# ===========================================================================
# lab.sh — homelab control surface (VMware Fusion + Ansible)
#
# Start/stop/suspend the lab by named run profile, converge it with Ansible,
# snapshot/restore, and print status — so the lab is a platform you drive with
# one command, not a pile of VMs you start by hand.
#
#   ./lab.sh status
#   ./lab.sh up soc            # start a run profile's VMs (see profiles)
#   ./lab.sh suspend           # suspend everything running
#   ./lab.sh stop              # clean poweroff of everything running
#   ./lab.sh converge [play]   # ansible-playbook site.yml (or a named play)
#   ./lab.sh snapshot <name>   # snapshot every running VM
#   ./lab.sh restore <name>    # revert every VM that has that snapshot
#   ./lab.sh profiles          # list run profiles
#
# Written for stock macOS bash 3.2 (no associative arrays). Override VMROOT if
# your VMs live elsewhere. The encrypted ws-01 needs a passphrase for
# `vmrun start` — export WS01_VMENC_PASS or put it in scripts/.lab-secrets
# (git-ignored) as WS01_VMENC_PASS=...
# ===========================================================================
set -euo pipefail

VMROOT="${VMROOT:-$HOME/Virtual Machines.localized}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ANSIBLE_DIR="$HERE/../phase-7-automation/ansible"
[ -f "$HERE/.lab-secrets" ] && . "$HERE/.lab-secrets"

ALL_VMS="rtr-01 dc-01 ws-01 siem-01 fs-01 dmz-01 atk-01 scan-01"

vmx_path() {
  case "$1" in
    rtr-01)  echo "$VMROOT/Debian 13.x 64-bit Arm.vmwarevm/Debian 13.x 64-bit Arm.vmx" ;;
    *)       echo "$VMROOT/$1.vmwarevm/$1.vmx" ;;
  esac
}

# Encrypted VMs need -vp <pass> for `vmrun start`. Echo the passphrase (or empty).
enc_pass() {
  case "$1" in
    ws-01) echo "${WS01_VMENC_PASS:-}" ;;
    *)     echo "" ;;
  esac
}
is_encrypted() { case "$1" in ws-01) return 0 ;; *) return 1 ;; esac; }

# Run profiles — from the build plan's "never run everything" table.
profile_vms() {
  case "$1" in
    networking) echo "rtr-01" ;;
    ad)         echo "rtr-01 dc-01 ws-01" ;;
    soc)        echo "rtr-01 dc-01 ws-01 siem-01" ;;
    attack)     echo "rtr-01 dc-01 ws-01 siem-01 fs-01 atk-01" ;;
    vulnscan)   echo "rtr-01 dc-01 siem-01 scan-01" ;;
    services)   echo "rtr-01 dc-01 siem-01 fs-01 dmz-01" ;;
    *)          echo "" ;;
  esac
}
ALL_PROFILES="networking ad soc attack vulnscan services"

running() { vmrun list | grep -qF "$(vmx_path "$1")"; }

# Run a vmrun command for a VM, prepending -vp <pass> for encrypted VMs so
# suspend/stop work on them too (not just start).
vmrun_vm() {
  local vm="$1"; shift
  if is_encrypted "$vm" && [ -n "$(enc_pass "$vm")" ]; then
    vmrun -vp "$(enc_pass "$vm")" "$@"
  else
    vmrun "$@"
  fi
}

start_vm() {
  local vm="$1" vmx; vmx="$(vmx_path "$1")"
  [ -f "$vmx" ] || { echo "  ! $vm: no vmx (not built yet?)"; return 0; }
  running "$vm" && { echo "  = $vm already running"; return 0; }
  if is_encrypted "$vm"; then
    local p; p="$(enc_pass "$vm")"
    [ -n "$p" ] || { echo "  ! $vm encrypted but no passphrase (WS01_VMENC_PASS / scripts/.lab-secrets) — skipped"; return 0; }
    vmrun -vp "$p" start "$vmx" nogui >/dev/null && echo "  ^ $vm started (encrypted)"
  else
    vmrun start "$vmx" nogui >/dev/null && echo "  ^ $vm started"
  fi
}

cmd_up() {
  local profile="${1:-}"; [ -n "$profile" ] || { echo "usage: lab.sh up <profile>"; exit 2; }
  local vms; vms="$(profile_vms "$profile")"
  [ -n "$vms" ] || { echo "unknown profile '$profile' (try: lab.sh profiles)"; exit 2; }
  echo "Starting profile '$profile': $vms"
  for vm in $vms; do start_vm "$vm"; done
}

cmd_suspend() {
  for vm in $ALL_VMS; do
    running "$vm" || continue
    # soft needs VMware Tools; fall back to hard if Tools isn't responding.
    if vmrun_vm "$vm" suspend "$(vmx_path "$vm")" soft >/dev/null 2>&1 \
       || vmrun_vm "$vm" suspend "$(vmx_path "$vm")" hard >/dev/null 2>&1; then
      echo "  v $vm suspended"
    else echo "  ! $vm suspend failed"; fi
  done
  echo "done."
}

cmd_stop() {
  for vm in $ALL_VMS; do
    running "$vm" || continue
    if vmrun_vm "$vm" stop "$(vmx_path "$vm")" soft >/dev/null 2>&1; then echo "  . $vm powered off"
    elif vmrun_vm "$vm" stop "$(vmx_path "$vm")" hard >/dev/null 2>&1; then echo "  . $vm hard-stopped"
    else echo "  ! $vm stop failed"; fi
  done
  echo "done."
}

cmd_status() {
  printf "%-9s %s\n" "VM" "STATE"
  printf "%-9s %s\n" "--" "-----"
  for vm in $ALL_VMS; do
    if [ ! -f "$(vmx_path "$vm")" ]; then printf "%-9s %s\n" "$vm" "not built"
    elif running "$vm"; then printf "%-9s %s\n" "$vm" "running"
    else printf "%-9s %s\n" "$vm" "stopped/suspended"; fi
  done
}

cmd_converge() { ( cd "$ANSIBLE_DIR" && ansible-playbook "${1:-site.yml}" ); }

cmd_snapshot() {
  local name="${1:-}"; [ -n "$name" ] || { echo "usage: lab.sh snapshot <name>"; exit 2; }
  for vm in $ALL_VMS; do running "$vm" && vmrun snapshot "$(vmx_path "$vm")" "$name" >/dev/null 2>&1 && echo "  + $vm @ $name"; done
  echo "done."
}

cmd_restore() {
  local name="${1:-}"; [ -n "$name" ] || { echo "usage: lab.sh restore <name>"; exit 2; }
  for vm in $ALL_VMS; do
    local vmx; vmx="$(vmx_path "$vm")"
    [ -f "$vmx" ] && vmrun listSnapshots "$vmx" 2>/dev/null | grep -qxF "$name" \
      && vmrun revertToSnapshot "$vmx" "$name" >/dev/null 2>&1 && echo "  < $vm reverted to $name"
  done
  echo "done."
}

cmd_profiles() { for p in $ALL_PROFILES; do printf "  %-11s %s\n" "$p" "$(profile_vms "$p")"; done; }

case "${1:-}" in
  status)   cmd_status ;;
  up)       cmd_up "${2:-}" ;;
  suspend)  cmd_suspend ;;
  stop)     cmd_stop ;;
  converge) cmd_converge "${2:-site.yml}" ;;
  snapshot) cmd_snapshot "${2:-}" ;;
  restore)  cmd_restore "${2:-}" ;;
  profiles) cmd_profiles ;;
  *) echo "usage: lab.sh {status|up <profile>|suspend|stop|converge [play]|snapshot <name>|restore <name>|profiles}"; exit 2 ;;
esac
