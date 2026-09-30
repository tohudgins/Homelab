#!/usr/bin/env bash
# ===========================================================================
# pull-backups.sh — ship siem-01/misp-01's own backups off the VM disk they
# live on, onto the control node (this Mac).
#
# Real gap this closes: the app-level backups this lab already has (Wazuh's
# OpenSearch snapshot repo, MISP's DB+state tar, IRIS's DB dump — see
# docs/backup-restore.md) all write to a directory on the SAME host, and same
# underlying VM disk, as the data they protect. That's a real backup against
# LOGICAL loss (a bad query, an accidental index delete, app-level corruption)
# — genuinely useful, and the code is careful about it (least-privilege
# snapshotrestore user, retention cleanup, failure logging). It does nothing
# against PHYSICAL loss: if that one disk dies, the live data and its backup
# die together.
#
# Pull-based, not push-based, and on purpose: the control node already has
# one-way SSH access to every VM (that's how Ansible/lab.sh work) — pulling
# from here needs no new inbound listener, no new firewall rule on rtr-01, and
# no new credential on the VMs. Pushing FROM the VMs TO the Mac would need all
# three. Same principle a real backup server uses (it reaches out to sources,
# sources don't need access back to it).
#
# Bounded, disk-conscious (checked live, not assumed, 2026-09-30):
#   - Wazuh snapshot repo: 299M today, OpenSearch snapshots are INCREMENTAL
#     (each one only stores new/changed segments), so mirroring the whole
#     repo with rsync --delete stays small and grows slowly — safe to mirror
#     in full.
#   - IRIS backups: 68K today (small SQL dumps) — safe to mirror in full.
#   - MISP backups: 1.3G for just TWO runs (each full DB dump + state tar is
#     ~650M, NOT incremental) — at the role's own 30-day retention default
#     this could reach ~20G mirrored in full, on a host already tight on
#     disk. Pulls only the LATEST pair instead of the whole retention window
#     — bounds MISP's footprint to ~650M regardless of source retention.
#
# Usage: scripts/pull-backups.sh   (or `make backup-pull`)
# Not scheduled automatically — this is a personal Mac, not a fleet backup
# server; run it after a backup cron fires, or add it to your own crontab if
# you want it automatic (see docs/RUNBOOK.md §4 for the one-line entry).
# ===========================================================================
set -euo pipefail

DEST_ROOT="${HOMELAB_BACKUP_DEST:-$HOME/Homelab-backups}"
RSYNC_SUDO=(--rsync-path="sudo rsync")   # remote paths are root-owned (cron runs as root)

# Full directory mirror, bounded by the source's own retention (Wazuh, IRIS —
# both small). Directories ONLY — rsync's trailing-slash source syntax means
# "sync the contents of this directory," which fails against a plain file
# ("change_dir ... failed: Not a directory") — use pull_file for those.
# No -v on rsync means it prints nothing on success, so check rsync's own
# exit code directly rather than piping through anything: earlier version
# piped through `grep -v '^$'` to strip blank lines, but grep-on-empty-input
# exits 1 ("no lines matched") even when rsync exits 0 — with `pipefail` that
# turned every silent-success run into a false "rsync reported an issue".
# Confirmed by running the exact rsync commands standalone: both exit 0.
pull() {
  local host="$1" remote_path="$2" local_name="$3"
  local dest="$DEST_ROOT/$host/$local_name"
  mkdir -p "$dest"
  echo "==> $host:$remote_path -> $dest (full mirror)"
  rsync -az --delete "${RSYNC_SUDO[@]}" -e ssh "${host}:${remote_path%/}/" "$dest/" \
    || echo "  ! rsync failed for $host:$remote_path (host down?)"
}

# Single remote file -> local directory.
pull_file() {
  local host="$1" remote_file="$2" local_name="$3"
  local dest="$DEST_ROOT/$host/$local_name"
  mkdir -p "$dest"
  echo "==> $host:$remote_file -> $dest/"
  ssh "$host" "sudo cat '$remote_file'" > "$dest/$(basename "$remote_file")" \
    || echo "  ! pull failed for $host:$remote_file (host down?)"
}

# Latest-file-matching-pattern only, deliberately NOT a full mirror (MISP —
# large, non-incremental dumps). Pulls the newest match, then prunes any OLDER
# local dump of the same kind — without that, every new daily dump would add
# another ~650M next to the previous one, and this would be exactly the
# unbounded copy the header says it isn't (an earlier version of this function
# only ever added files; a single test run can't show that). Written to a
# .partial name first so a failed/interrupted transfer never leaves a
# half-written file under the real name, and pruning happens only after a
# transfer that actually succeeded — a failed run keeps yesterday's good copy.
pull_latest() {
  local host="$1" remote_dir="$2" local_name="$3" pattern="$4"
  local dest="$DEST_ROOT/$host/$local_name"
  mkdir -p "$dest"
  local latest
  latest=$(ssh "$host" "sudo ls -t ${remote_dir}/${pattern} 2>/dev/null | head -1") || true
  if [ -z "$latest" ]; then
    echo "==> $host:$remote_dir/$pattern -> $dest (nothing found)"
    return 0
  fi
  local base; base=$(basename "$latest")
  echo "==> $host:$latest -> $dest/ (latest only, older local dumps pruned)"
  if ssh "$host" "sudo cat '$latest'" > "$dest/$base.partial"; then
    mv "$dest/$base.partial" "$dest/$base"
    find "$dest" -maxdepth 1 -type f -name "$pattern" ! -name "$base" -delete
  else
    rm -f "$dest/$base.partial"
    echo "  ! pull failed for $host:$latest (host down?) — keeping the previous local copy"
  fi
}

echo "Pulling backups into $DEST_ROOT"
echo

# siem-01 — Wazuh's OpenSearch snapshot repo (wazuh-snapshot-backup.sh's target,
# roles/siem/defaults/main.yml: wazuh_snapshot_repo_path) + its own run log.
# Mechanism verified live before wiring this up: a real manual snapshot+delete
# round-trip against the same credential/repo the cron uses succeeded cleanly
# (the stale "Unauthorized" lines in the run log are from 2026-09-26, almost
# certainly an indexer-restart timing window during that day's work, not a
# standing defect — the 4am cron simply hasn't run since, since the VM's
# suspended outside active sessions).
pull siem-01 /var/lib/wazuh-indexer-snapshots wazuh-snapshots
pull_file siem-01 /var/log/wazuh-snapshot-backup.log wazuh-snapshot-backup-log

# misp-01 — MISP and IRIS (roles/misp,iris/defaults/main.yml) both live on the
# same host (the `threat_intel` inventory group).
pull_latest misp-01 /opt/misp-docker/backups misp 'misp-db-*.sql.gz'
pull_latest misp-01 /opt/misp-docker/backups misp 'misp-state-*.tar.gz'
pull_file misp-01 /opt/misp-docker/backups/backup.log misp
pull misp-01 /opt/iris-web/backups iris

echo
echo "Done. Local footprint:"
du -sh "$DEST_ROOT"/*/* 2>/dev/null || echo "  (nothing pulled — are the source VMs up?)"
