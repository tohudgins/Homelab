# Phase 2 — Known Weaknesses Register

Deliberately introduced AD misconfigurations, kept for Phase 4/5 to detect and (eventually) attack against.
Each one is a real, common pattern found in production Active Directory environments — not a contrived
lab-only setup. Written retroactively on 2026-08-15 once Phase 4 needed a concrete Kerberoasting target;
the intent was always in the Phase 2 plan, this is where it actually gets built and documented.

| # | Weakness | Account(s) | Real-world pattern it mirrors | Attacked/detected in |
|---|---|---|---|---|
| 1 | Kerberoastable service accounts with weak, dictionary-guessable passwords | `svc-sql`, `svc-backup`, `svc-web` | Legacy service accounts set up years ago, never rotated, named/passworded by whoever provisioned them at the time | [Phase 4 — T1558.003](../phase-4-detection/detection-catalog.md#3-t1558003-kerberoasting) |
| 2 | Cleartext service-account credential in a world-readable share, chained into Tier-0 privilege (Backup Operators + DCSync ACE) | `svc-backup` | Ops leaves a plaintext credential in a scheduled-task script on a shared drive, and the account it authenticates as was over-scoped "just in case" it ever needed backup access | [Phase 5 — fs-01 credential theft → DCSync](../phase-5-offense/attack-detect-writeups/01-fs01-credential-theft-to-dcsync.md) |

## 1. Kerberoastable service accounts

**What was built:** three domain user accounts, each with a Service Principal Name (SPN) registered and
a weak password:

| Account | SPN | Password | Weakness pattern |
|---|---|---|---|
| `svc-sql` | `MSSQLSvc/dc-01.lab.internal:1433` | `Summer2026` | season + year — one of the most common human password patterns, in most cracking wordlists directly |
| `svc-backup` | `HOST/backup-svc.lab.internal` | `Backup2026` | account purpose + year, no complexity beyond the minimum |
| `svc-web` | `HTTP/webapp.lab.internal` | `WebApp2026` | same pattern — role name + year |

Any SPN registered on a user account (rather than a computer account) makes that account's Kerberos
ticket-granting-service (TGS) requestable by *any* authenticated domain user, with no special privilege
needed — that's what makes Kerberoasting a low-bar-to-entry technique. The registered SPN is what makes
an account a *target*; the weak password is what makes cracking the resulting ticket actually pay off.
Both conditions had to be true for this to be a real, demonstrable weakness.

Also created `jdoe`, an ordinary unprivileged domain user, specifically to prove the "no special privilege
needed" part — the attack simulation in Phase 4 authenticates as `jdoe`, not `Administrator`.

**Why this is realistic, not contrived:** service accounts accumulate in real AD environments as
applications get provisioned over years — a SQL Server install, a backup agent, an IIS app pool identity
— each needing a domain account to run as, each usually set up once and left alone. Weak/legacy passwords
on exactly these accounts (rather than on human user accounts, which usually have some rotation policy)
is one of the most consistently-cited real findings in AD penetration tests and Purple Team engagements.

**How to reproduce / extend:**
```
samba-tool user create svc-sql "Summer2026" --description="..."
samba-tool spn add MSSQLSvc/dc-01.lab.internal:1433 svc-sql
```

**Remediation (not applied — these stay in place intentionally as detection/attack targets):** in a real
environment, this class of weakness is fixed by: rotating service account passwords to long random values
(ideally via a managed service account / gMSA-equivalent, which Samba AD DC as of this build doesn't
support the same way Windows Server does — a real limitation worth noting, not glossed over), or moving
the SPN to a machine account instead of a user account where the TGS is encrypted with a machine-strength
key rather than a human-settable password.

**Detected in Phase 4:** see
[T1558.003 — Kerberoasting](../phase-4-detection/detection-catalog.md#3-t1558003-kerberoasting) for the
full attack simulation, the Samba audit-logging setup needed to see it at all (off by default), the
custom Wazuh rules, and a confirmed real evasion (a single targeted ticket request produces no alert).

## 2. svc-backup — cleartext credential leak + Backup Operators/DCSync over-privilege

**What was built:** two coupled misconfigurations on the same account, chained into a low-privilege →
Tier-0 path:

1. `phase-7-automation/ansible/roles/fileserver/files/map-backup-share.ps1`, a scheduled-task helper
   staged on fs-01's world-readable `[public]` share, hardcodes `svc-backup`'s password in cleartext
   (`$pass = "Backup2026" | ConvertTo-SecureString -AsPlainText -Force`) behind a
   `# TODO: move this credential into the vault (JIRA-4471)` comment referencing a ticket that was never
   actually opened — the classic "we'll fix it later" artifact.
2. `svc-backup` itself is over-privileged: member of the built-in **Backup Operators** group and granted
   `DS-Replication-Get-Changes` / `DS-Replication-Get-Changes-All` directly on the domain naming context —
   i.e. DCSync rights (`phase-7-automation/ansible/roles/dc/defaults/main.yml`: `dc_backup_operators_members`,
   `dc_dcsync_guids`).

Any authenticated domain user (`jdoe`, no special privilege) who reads the share harvests a real, working
credential for an account that can dump every password hash in the domain via replication — a full
low-priv-to-Domain-Admin path with no exploit involved, just two ordinary-looking misconfigurations that
compound.

**Why this is realistic, not contrived:** cleartext credentials in scheduled-task scripts on shared drives
are one of the single most common findings in real credential-access engagements — usually left by
whoever wrote the automation and never rotated because "it's just for backups." Backup Operators is
routinely over-granted because it *sounds* like a low-risk, backup-only right; in reality it (and the
DCSync ACE this account also holds) is Tier-0 in BloodHound terms. The fake JIRA reference is itself a
realistic artifact — a remediation that was logged and then never followed up.

**How to reproduce / extend:**
```
smbclient //10.10.10.20/public -U 'lab.internal\jdoe%P@ssw0rd2026!' -c 'get map-backup-share.ps1'
grep -i pass map-backup-share.ps1        # yields svc-backup / Backup2026 in cleartext
secretsdump.py lab.internal/svc-backup:Backup2026@dc-01.lab.internal -just-dc-ntlm
```

**Remediation (not applied — stays in place intentionally as a detection/attack target):** in a real
environment this is fixed by never storing a scheduled-task credential in cleartext (gMSA, a credential
vault, or at minimum DPAPI scoped to the running principal), and by scoping Backup Operators / replication
rights to a dedicated, non-interactive backup principal that is never also a Kerberoastable, share-readable
target — the two misconfigurations should never live on the same account.

**Detected in Phase 4/5:** see
[Phase 5 — fs-01 credential theft → Backup Operators → DCSync](../phase-5-offense/attack-detect-writeups/01-fs01-credential-theft-to-dcsync.md)
for the full attack chain (executed from `atk-01` as `jdoe`), and the detection catalog's T1552.001 entry
(rule 100090, share-read via Samba `full_audit`) + T1003.003/T1003.006 entry (rule 100080, DCSync/NTDS
replication) for the detection side.

## Related

- [`docs/design-decisions.md`](../docs/design-decisions.md) — why dc-01 runs Samba AD DC
- [`phase-4-detection/detection-catalog.md`](../phase-4-detection/detection-catalog.md) — the detection side of this register
