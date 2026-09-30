#!/usr/bin/env bash
# ===========================================================================
# install-backup-schedule.sh — run scripts/pull-backups.sh on a macOS launchd timer.
#
#   scripts/install-backup-schedule.sh             install / refresh
#   scripts/install-backup-schedule.sh --uninstall remove the agent
#   (or `make backup-schedule` / `make backup-unschedule`)
#
# Why the timer is hourly but pulls at most daily: the lab VMs are mostly suspended,
# so a fixed daily slot would usually find nothing running. pull-backups.sh --scheduled
# pulls each host only when it is reachable AND has no successful pull in the last 20h,
# so the first hourly tick after a host comes up does the work and the rest are silent.
#
# Why it installs a COPY of the script under ~/.local/bin instead of pointing launchd at
# the repo: macOS TCC grants ~/Desktop access per executable, and /bin/bash (what launchd
# runs) has none, so a script living under ~/Desktop fails with "Operation not permitted"
# — while the same command works in a terminal, which is why that failure is invisible
# until the agent has silently never worked. pull-backups.sh needs nothing from the repo
# (only ssh/rsync and ~/.ssh/config), so a copy is self-sufficient. Re-run this script
# after editing pull-backups.sh to refresh the copy.
# ===========================================================================
set -euo pipefail

LABEL="com.tohud.homelab.backup-pull"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
BIN="$HOME/.local/bin/homelab-pull-backups"
LOG="$HOME/Library/Logs/homelab-backup-pull.log"
HERE="$(cd "$(dirname "$0")" && pwd)"
DOMAIN="gui/$(id -u)"

if [ "${1:-}" = "--uninstall" ]; then
  launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
  rm -f "$PLIST" "$BIN"
  echo "Removed $LABEL (backups in ~/Homelab-backups are untouched)."
  exit 0
fi

mkdir -p "$(dirname "$BIN")" "$(dirname "$PLIST")" "$(dirname "$LOG")"
install -m 0755 "$HERE/pull-backups.sh" "$BIN"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$BIN</string>
    <string>--scheduled</string>
  </array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
plutil -lint "$PLIST" >/dev/null

launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"
echo "Installed $LABEL (hourly tick; pulls each reachable host at most once per 20h)."
echo "  script: $BIN"
echo "  log:    $LOG"
echo "Check:   launchctl print $DOMAIN/$LABEL | grep -E 'state|last exit'"
