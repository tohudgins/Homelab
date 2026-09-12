# BloodHound CE — AD attack-path mapping

**Phase 5 — Offense in context.** Host-side [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound)
(Docker, `docker-compose.yml` in this directory — the official upstream compose file, unmodified) graphs the
domain's attack paths from data collected by `bloodhound-ce-python` on `atk-01`. This is what surfaces the
low-priv → Tier-0 path the rest of Phase 5 executes: `svc-backup` → **Backup Operators** membership +
**DCSync** rights on the domain NC (see [`../attack-detect-writeups/01-fs01-credential-theft-to-dcsync.md`](../attack-detect-writeups/01-fs01-credential-theft-to-dcsync.md)).

## Run it

```bash
# host (this Mac): bring up the graph UI
cd phase-5-offense/bloodhound-ce && docker compose up -d   # UI at http://localhost:8080

# atk-01: collect
ssh atk-01 '~/.local/bin/bloodhound-ce-python -c All -u jdoe -p "<jdoe password>" \
  -d lab.internal -dc dc-01.lab.internal -ns 10.10.10.10 --auth-method ntlm --zip'
# pull the zip back and drag-and-drop it onto the BloodHound CE UI (Administration -> File Ingest)
```

`jdoe` (the ordinary unprivileged domain user used throughout Phase 4/5 —
[`../../phase-2-identity/known-weaknesses.md`](../../phase-2-identity/known-weaknesses.md)) is enough: BloodHound
collection needs only an authenticated domain logon, not any special privilege — the same "no special access
required" property that makes Kerberoasting and this graph both real, low-bar-to-entry findings.

## `--auth-method ntlm` is the fix, not a relax/re-harden dance (corrected 2026-09-11/12)

An earlier session found that binding `bloodhound-ce-python` against this Samba DC required temporarily
relaxing `ldap server require strong auth` (`no`, i.e. permit unsigned/unencrypted LDAP) on dc-01, then
restoring it after collection — a "relax → collect → re-harden" cycle repeated on every re-collection, and
recorded as such in the operator notes. **Re-tested this from scratch and it's no longer true** (either the
tool was upgraded since, or the original attempt never tried what's below):

- With `dc-01`'s `smb.conf` untouched — strong auth at its Samba **default (enforced)**, confirmed by a raw
  `ldapsearch -x` SIMPLE bind being correctly rejected (`ldap_bind: Strong(er) authentication required (8)`,
  `BindSimple: Transport encryption required`) — `bloodhound-ce-python -c All --auth-method ntlm` still
  completed a **full** collection: 1 domain, 3 computers, 12 users, 42 groups, 2 GPOs, 1 OU, 36 containers,
  with real ACL data (`Aces`) on every object.
- Why: the tool logs `WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to
  connect over LDAPS instead...` and does exactly that — LDAPS (port 636, TLS) satisfies "requires
  confidentiality" on its own, so the plain-port SIMPLE-bind path the strong-auth setting blocks was never
  needed once the collector properly falls back to it.
- **Confirmed the specific attack path survived the switch**: the collected domain object's ACEs include
  `GetChanges`/`GetChangesAll` granted to SID `...-1106` (`svc-backup`), and the `Backup Operators` group's
  members include the same SID — both halves of the BloodHound path this lab is built to demonstrate.
- Session enumeration (`Access denied while enumerating Sessions on dc-01.lab.internal, likely a patched OS`)
  is unrelated — a normal, expected miss on a hardened DC, not an LDAP auth issue.

**Practical effect:** don't touch `smb.conf` for a re-collection. Just run the command above with
`--auth-method ntlm`. The operator note that said otherwise has been corrected.

## Access

`http://localhost:8080` (host-side, not through any lab VM) — admin login forces a password reset on first
use; current credentials are in the vault's `Virtual Machines` note (not committed here).

## Related

[`../attack-detect-writeups/01-fs01-credential-theft-to-dcsync.md`](../attack-detect-writeups/01-fs01-credential-theft-to-dcsync.md) —
the attack this graph maps, executed end-to-end and detected. [`../../phase-2-identity/known-weaknesses.md`](../../phase-2-identity/known-weaknesses.md) —
the deliberate misconfigurations BloodHound surfaces.
