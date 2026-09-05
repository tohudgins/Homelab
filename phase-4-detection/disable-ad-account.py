#!/usr/bin/env python3
"""
Wazuh custom active-response: disable/re-enable a Samba AD account.

The stock `disable-account` active response only understands local system accounts
(usermod/passwd -l) -- it has no concept of a Samba AD domain account. This script
calls `samba-tool user disable`/`enable` instead, so it actually works against the
account the brute-force alert (rule 100041) is about.

Wazuh invokes this with one JSON line on stdin:
  {"command": "add"|"delete", "parameters": {"alert": {<the full alert>}, ...}, ...}
"add" = apply the response (disable), "delete" = revert it (re-enable), fired
automatically when the active-response <timeout> in ossec.conf expires.
"""
import sys
import json
import subprocess
import datetime

LOG = "/var/ossec/logs/active-responses.log"

# Never let an automated response lock out a built-in/privileged account -- an
# attacker who knows this rule exists could otherwise weaponize it into a DoS by
# deliberately failing Kerberos auth as a real admin account to get it locked.
PROTECTED_ACCOUNTS = {"administrator", "krbtgt", "guest"}

# Machine/computer accounts (sAMAccountName ends in '$') are ALSO never disabled.
# Disabling one breaks the domain member outright, and worse, creates a
# self-sustaining loop: a disabled machine account's own continued Kerberos auth
# (winbind, ticket renewal) keeps failing pre-auth, which looks like MORE brute
# force (rule 100041) and re-triggers this very response. Observed live 2026-09-05
# when fs-01's post-resume auth burst disabled FS-01$ and the member fell out of
# the domain until FS-01$ was re-enabled and this guard added. See
# [[Active Response Collateral Damage]].


def log(msg: str) -> None:
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open(LOG, "a") as f:
        f.write(f"{ts} disable-ad-account: {msg}\n")


def main() -> None:
    try:
        payload = json.loads(sys.stdin.readline())
    except Exception as e:
        log(f"failed to parse stdin as JSON: {e}")
        sys.exit(1)

    command = payload.get("command")
    alert = payload.get("parameters", {}).get("alert", {})
    account = alert.get("data", {}).get("Authentication", {}).get("becameAccount")

    if not account:
        log(f"no account found in alert data, aborting (command={command})")
        sys.exit(1)

    if account.lower() in PROTECTED_ACCOUNTS:
        log(f"refusing to act on protected account: {account} (command={command})")
        sys.exit(0)

    if account.endswith("$"):
        log(f"refusing to act on machine account: {account} (command={command})")
        sys.exit(0)

    if command == "add":
        result = subprocess.run(
            ["samba-tool", "user", "disable", account],
            capture_output=True, text=True,
        )
        log(f"disable {account}: rc={result.returncode} {result.stdout.strip()} {result.stderr.strip()}")
    elif command == "delete":
        result = subprocess.run(
            ["samba-tool", "user", "enable", account],
            capture_output=True, text=True,
        )
        log(f"enable {account}: rc={result.returncode} {result.stdout.strip()} {result.stderr.strip()}")
    else:
        log(f"unknown command '{command}', no action taken")


if __name__ == "__main__":
    main()
