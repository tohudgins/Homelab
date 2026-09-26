#!/usr/bin/env bash
# App-level backup for MISP: the MySQL database (events/attributes/feeds — the
# actual threat-intel data) plus the bind-mounted state the misp-docker
# containers can't function without (GPG keyring used to sign/encrypt exports,
# app config, and stored attachment files). VM-snapshot-level DR existed before
# this; it's coarse (whole-disk, not restorable per-service) and easy to skip
# before a risky change, which is the gap this closes.
#
# Usage: misp-backup.sh
set -euo pipefail

DEPLOY_DIR=/opt/misp-docker
BACKUP_DIR="${DEPLOY_DIR}/backups"
RETENTION_DAYS="${MISP_BACKUP_RETENTION_DAYS:-30}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG="${BACKUP_DIR}/backup.log"

mkdir -p "$BACKUP_DIR"

db_user=$(docker exec misp-docker-db-1 printenv MYSQL_USER)
db_pass=$(docker exec misp-docker-db-1 printenv MYSQL_PASSWORD)
db_name=$(docker exec misp-docker-db-1 printenv MYSQL_DATABASE)

docker exec misp-docker-db-1 mysqldump -u "$db_user" -p"$db_pass" "$db_name" \
    | gzip > "${BACKUP_DIR}/misp-db-${TS}.sql.gz"

# GPG keyring + app config + stored attachments — bind-mounted directly under
# the deploy dir (confirmed via `docker inspect`, not assumed). gpg-agent's own
# live Unix sockets under gnupg/ can't be archived (and shouldn't be — they're
# re-created on next use, not state); --warning=no-file-ignored silences tar's
# harmless note about skipping them instead of leaving stderr noise on every run.
tar --warning=no-file-ignored -czf "${BACKUP_DIR}/misp-state-${TS}.tar.gz" -C "$DEPLOY_DIR" gnupg configs files

db_bytes=$(stat -c%s "${BACKUP_DIR}/misp-db-${TS}.sql.gz")
state_bytes=$(stat -c%s "${BACKUP_DIR}/misp-state-${TS}.tar.gz")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) db=misp-db-${TS}.sql.gz(${db_bytes}b) state=misp-state-${TS}.tar.gz(${state_bytes}b)" >> "$LOG"

find "$BACKUP_DIR" -maxdepth 1 -type f \( -name 'misp-db-*.sql.gz' -o -name 'misp-state-*.tar.gz' \) \
    -mtime "+${RETENTION_DAYS}" -delete
