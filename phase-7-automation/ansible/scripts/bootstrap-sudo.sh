#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# One-time bootstrap: grant the Ansible automation account passwordless sudo on
# an internal lab host, so every subsequent `ansible-playbook` run needs no
# become password.
#
# Why this exists (the chicken-and-egg): Ubuntu ships `Defaults use_pty` in
# sudoers, which routes sudo's password prompt into a PTY that Ansible's become
# machinery cannot read — every password-based become times out with
# "Timeout waiting for privilege escalation prompt." Rather than weaken use_pty,
# we authorize the automation account (already key-only over SSH) for NOPASSWD
# sudo. That's the standard Ansible control-account model. Human interactive
# sudo still prompts for a password; use_pty hardening is left intact.
#
# This is the single manual pre-step before Ansible can manage a host. It uses
# the account's existing sudo password ONCE, over the working SSH path, then
# never needs it again.
#
# Usage:  ./bootstrap-sudo.sh <ssh-alias-or-host>   # e.g. ./bootstrap-sudo.sh fs-01
# ---------------------------------------------------------------------------
set -euo pipefail

HOST="${1:?usage: bootstrap-sudo.sh <ssh-alias-or-host>}"
ACCT="${2:-tohudgins}"

read -r -s -p "sudo password for ${ACCT}@${HOST}: " PW
echo

ssh "$HOST" "echo '${PW}' | sudo -S sh -c '
  echo \"${ACCT} ALL=(ALL) NOPASSWD:ALL\" > /etc/sudoers.d/90-ansible-${ACCT} &&
  chmod 440 /etc/sudoers.d/90-ansible-${ACCT} &&
  visudo -cf /etc/sudoers.d/90-ansible-${ACCT}
'"

echo "done: ${ACCT}@${HOST} now has passwordless sudo (Ansible can manage it)"
