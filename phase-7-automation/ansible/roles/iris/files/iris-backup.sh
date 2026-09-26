#!/usr/bin/env bash
# App-level backup for DFIR-IRIS: the Postgres case database (cases, IOCs,
# notes, timelines — real analyst work product) plus the named Docker volumes
# holding case evidence/downloads and custom templates. Same rationale as the
# misp/wazuh backups: VM-snapshot DR is coarse and easy to skip; this is a
# real, per-service, restorable backup.
#
# Usage: iris-backup.sh
set -euo pipefail

DEPLOY_DIR=/opt/iris-web
BACKUP_DIR="${DEPLOY_DIR}/backups"
RETENTION_DAYS="${IRIS_BACKUP_RETENTION_DAYS:-30}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG="${BACKUP_DIR}/backup.log"

mkdir -p "$BACKUP_DIR"

pg_user=$(grep -m1 '^POSTGRES_USER=' "${DEPLOY_DIR}/.env" | cut -d= -f2-)
pg_pass=$(grep -m1 '^POSTGRES_PASSWORD=' "${DEPLOY_DIR}/.env" | cut -d= -f2-)
pg_db=$(grep -m1 '^POSTGRES_DB=' "${DEPLOY_DIR}/.env" | cut -d= -f2-)

docker exec -e PGPASSWORD="$pg_pass" iriswebapp_db pg_dump -U "$pg_user" -d "$pg_db" \
    | gzip > "${BACKUP_DIR}/iris-db-${TS}.sql.gz"

# Named Docker volumes (case evidence/downloads, custom templates) — tar
# straight from Docker's own volume storage on the host, no extra container
# needed. Volume names are prefixed with the compose project name
# (the deploy dir's basename, "iris-web").
for vol in iris-web_iris-downloads iris-web_server_data iris-web_user_templates; do
    src="/var/lib/docker/volumes/${vol}/_data"
    [[ -d "$src" ]] || continue
    tar czf "${BACKUP_DIR}/${vol}-${TS}.tar.gz" -C "$src" . 2>/dev/null || true
done

db_bytes=$(stat -c%s "${BACKUP_DIR}/iris-db-${TS}.sql.gz")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) db=iris-db-${TS}.sql.gz(${db_bytes}b) volumes=$(ls "${BACKUP_DIR}"/*-"${TS}".tar.gz 2>/dev/null | wc -l)" >> "$LOG"

find "$BACKUP_DIR" -maxdepth 1 -type f \( -name 'iris-db-*.sql.gz' -o -name 'iris-web_*-*.tar.gz' \) \
    -mtime "+${RETENTION_DAYS}" -delete
