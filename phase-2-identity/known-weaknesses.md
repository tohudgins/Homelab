# Phase 2 — Known Weaknesses Register

Deliberately introduced AD misconfigurations, kept for Phase 4/5 to detect and (eventually) attack against.
Each one is a real, common pattern found in production Active Directory environments — not a contrived
lab-only setup. Written retroactively on 2026-08-15 once Phase 4 needed a concrete Kerberoasting target;
the intent was always in the Phase 2 plan, this is where it actually gets built and documented.

| # | Weakness | Account(s) | Real-world pattern it mirrors | Attacked/detected in |
|---|---|---|---|---|
| 1 | Kerberoastable service accounts with weak, dictionary-guessable passwords | `svc-sql`, `svc-backup`, `svc-web` | Legacy service accounts set up years ago, never rotated, named/passworded by whoever provisioned them at the time | [Phase 4 — T1558.003](../phase-4-detection/detection-catalog.md#3-t1558003--kerberoasting) |

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
[T1558.003 — Kerberoasting](../phase-4-detection/detection-catalog.md#3-t1558003--kerberoasting) for the
full attack simulation, the Samba audit-logging setup needed to see it at all (off by default), the
custom Wazuh rules, and a confirmed real evasion (a single targeted ticket request produces no alert).

## Related

- [`docs/design-decisions.md`](../docs/design-decisions.md) — why dc-01 runs Samba AD DC
- [`phase-4-detection/detection-catalog.md`](../phase-4-detection/detection-catalog.md) — the detection side of this register
