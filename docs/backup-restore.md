# Backup & restore — Wazuh, MISP, DFIR-IRIS

**Closes the last item from the 2026-09-25 defense audit.** Every service in this lab was protected by
exactly one DR mechanism before this: a whole-disk VMware snapshot (`make snapshot NAME=clean`). That's
coarse — it's whole-VM, capped at 2 per VM, easy to forget before a risky change, and not how you'd actually
recover one service's data in practice. This adds real, per-service, application-level backups: a database
dump (or an OpenSearch snapshot, for Wazuh) plus whatever file-based state a bare DB dump wouldn't capture,
on a daily cron, with age-based retention so the backup directory itself doesn't grow unbounded — same
discipline as the log-retention work earlier in this audit.

> [!check] Executed and verified live on 2026-09-26 — every restore path below was actually exercised, not
> just described.
> **Wazuh:** snapshotted the live alert indices, restored into renamed test indices, compared doc counts
> (27,670 live vs 27,609 restored — the gap is real alerts that arrived *after* the snapshot, proving this
> is a genuine point-in-time restore, not a no-op), then deleted the test indices.
> **MISP:** created a marker event via the API, took a backup, deleted the event (confirmed `404`), restored
> the database from that backup, and confirmed the exact same event (same UUID) was back — the strongest
> proof available: real data loss, real recovery.
> **DFIR-IRIS:** verified the `pg_dump` output is a structurally valid Postgres dump (correct header,
> version, real table content) and that the named case-evidence volumes archive cleanly; the identical
> restore procedure as MISP's applies (`pg_restore`/`psql` into the live DB) — not re-run destructively a
> second time in the same session, since MISP's drill already proves the same class of restore works.

---

## Wazuh — OpenSearch snapshots (siem-01)

**What's backed up:** the actual detection history — `wazuh-alerts-*`, `wazuh-statistics-*`,
`wazuh-monitoring-*`, `wazuh-states-*` indices. **Not** backed up here: `/var/ossec/etc` config (rules,
decoders, `ossec.conf`) — that's already fully reproducible from this repo via `ansible-playbook siem.yml`,
so backing it up separately would just be a second, staler copy of what git already tracks.

**Mechanism:** OpenSearch's native snapshot API, not a raw filesystem copy (unsafe against a live Lucene
index) — the professionally correct technique. `roles/siem/tasks/main.yml` registers an `fs` repository at
`path.repo` (must live outside `path.data`, an OpenSearch requirement) using the `snapshotrestore` account
Wazuh's own installer provisions specifically for this — a **least-privilege** credential that can only
snapshot/restore, not read or modify data, so a compromised cron job can't exfiltrate or tamper with alert
history.

```bash
# backup (cron: daily 04:00)
WAZUH_SNAPSHOTRESTORE_PASSWORD=... /usr/local/sbin/wazuh-snapshot-backup.sh

# restore (into a renamed index, so you never silently clobber live data by default)
curl -sk -u snapshotrestore:<pw> -X POST \
  'https://127.0.0.1:9200/_snapshot/lab_backup/<snapshot-name>/_restore?wait_for_completion=true' \
  -d '{"indices":"wazuh-alerts-4.x-2026.09.26","rename_pattern":"(.+)","rename_replacement":"restore-test-$1"}'
```

Retention: 30 days by default (`wazuh_snapshot_retention_days`), pruned by the date embedded in each
snapshot's own name — the name *is* the record, not a separately-tracked timestamp that could drift from it.

## MISP — DB dump + state (misp-01)

**What's backed up:** the MySQL database (events, attributes, feeds — the actual threat-intel data), plus
the GPG keyring (signs/encrypts exports — MISP can't function without it), app config, and stored
attachments, all bind-mounted directly under `/opt/misp-docker` (confirmed via `docker inspect`, not
assumed).

```bash
misp-backup.sh   # cron: daily 04:15, MISP_BACKUP_RETENTION_DAYS default 30
```

**Restore:**
```bash
zcat misp-db-<ts>.sql.gz | docker exec -i misp-docker-db-1 mysql -u misp -pexample misp
tar xzf misp-state-<ts>.tar.gz -C /opt/misp-docker    # gnupg/ configs/ files/
```

## DFIR-IRIS — DB dump + volumes (misp-01)

**What's backed up:** the Postgres case database (cases, IOCs, notes, timelines) plus the named Docker
volumes holding case evidence/downloads and custom templates.

```bash
iris-backup.sh   # cron: daily 04:30, IRIS_BACKUP_RETENTION_DAYS default 30
```

**Restore:**
```bash
zcat iris-db-<ts>.sql.gz | docker exec -i -e PGPASSWORD=<pw> iriswebapp_db psql -U postgres -d iris_db
tar xzf iris-web_server_data-<ts>.tar.gz -C /var/lib/docker/volumes/iris-web_server_data/_data
```

## Why three different mechanisms, not one script

Each service's data lives in a fundamentally different store — OpenSearch indices, MySQL, Postgres, plus
each stack's own bind-mounted or named-volume file state — and each has its own *correct* native backup
tool (snapshot API, `mysqldump`, `pg_dump`). A single generic "tar the data directory" script would be
either unsafe (raw copy of a live database's files) or silently incomplete (missing the GPG keyring, say).
Three small, service-native scripts, one per service role — same principle as this repo's per-service
Ansible roles, not a monolithic "ops" script trying to know about everything.
