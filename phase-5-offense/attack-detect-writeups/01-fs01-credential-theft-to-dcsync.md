# Attack / Detect: fs-01 credential theft → Backup Operators → DCSync

**Phase 5 — Offense in context.** A paired attacker-console / defender-alert walkthrough of one attack
path that BloodHound surfaces in this lab, executed from `atk-01` (Kali, REDTEAM segment) and hunted in
Wazuh on `siem-01`. It also documents — honestly — where the standard Linux offensive tooling does and
does not work against a **Samba** AD DC, because that boundary is the single most important thing this
exercise taught.

Domain: `lab.internal` · DC: `dc-01` (Samba AD DC 4.23.6) · Attacker: `atk-01` (`10.10.40.119`) ·
Low-priv foothold user: `jdoe` (Domain User).

---

## 1. The path BloodHound found

Collection was run with `bloodhound-ce-python` from `atk-01` and analysed in host-side BloodHound CE.
Two deliberately-planted weaknesses chain into a low-privilege → Tier-0 path:

```
jdoe (Domain User)
   │  reads \\fs-01\public\map-backup-share.ps1   (T1552.001 — cleartext cred in a readable share)
   ▼
svc-backup / Backup2026
   ├─ MemberOf → Backup Operators            (Tier Zero in BloodHound)
   └─ DS-Replication-Get-Changes[-All] on the domain NC → DCSync   (T1003.006)
```

BloodHound renders `svc-backup → Backup Operators` and `svc-backup → DCSync → lab.internal` as the
graphed "here is the path from a low-priv user to domain compromise" opening image.

---

## 2. Attack — executed from atk-01

### 2a. Credential access — read the weak share (T1552.001) ✅ works

```
$ smbclient //10.10.10.20/public -U 'lab.internal\jdoe%P@ssw0rd2026!' -c 'get map-backup-share.ps1'
$ grep -i pass map-backup-share.ps1
$user = "LAB\svc-backup"
$pass = "Backup2026" | ConvertTo-SecureString -AsPlainText -Force
```

Any Domain User can read the share, harvesting a real service-account credential — no exploit, minimal
noise. `nxc smb 10.10.10.10 -u svc-backup -p Backup2026` confirms the harvested credential is valid.

### 2b. Kerberoasting (T1558.003) ⚠️ partial on Samba

`impacket-GetUserSPNs` enumerates the SPN accounts correctly (and shows `svc-backup`'s
`MemberOf: CN=Backup Operators`), but the actual TGS request fails:

```
[-] Principal: lab.internal\svc-backup - Kerberos SessionError: KRB_AP_ERR_INAPP_CKSUM
```

The roast cannot complete because of an impacket ↔ Samba Kerberos bug (see §4). The DC still **receives**
the three TGS-REQs, which is all the detection needs.

### 2c. DCSync (T1003.006) ⚠️ request lands, impacket can't parse the reply

```
$ secretsdump.py lab.internal/svc-backup:Backup2026@dc-01.lab.internal -just-dc-ntlm
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[-] DRSR SessionError: code: 0x0 - ERROR_SUCCESS
```

Identical failure on impacket 0.14-dev **and** stable 0.12.0. dc-01's Samba log pins the cause:
`dcesrv_drsuapi_DsGetNCChanges: Failed to decode remote prefixMap: WERR_INVALID_PARAMETER` — impacket
sends a `prefixMap` Samba rejects. The malicious replication request still reaches the DC's replication
interface, which is the detectable event.

---

## 3. Detect — hunted in Wazuh

| Attacker action | Wazuh rule | Level | ATT&CK | Fires? |
|---|---|---|---|---|
| Read the bait credential file on fs-01 | **100090** | 12 | T1552.001 | ✅ |
| Kerberoast (3 TGS-REQs in <60s) | 100031 (Phase 4) | 12 | T1558.003 | ✅ |
| DCSync (`DsGetNCChanges` from a non-DC) | **100080** | 12 | T1003.006 | ✅ |

### 3a. Credential theft — rule 100090

FIM (syscheck) catches file **changes**, never **reads**, so reading the planted credential produced no
alert. The fix is share-access auditing: Samba `full_audit` VFS on the `[public]` share logs every
`openat` to `smbd_audit` (journald), which a custom decoder parses into `smb_user` / `srcip` / `smb_path`.

**Telemetry:** `LAB\jdoe|10.10.40.119|atk-01|public|openat|ok|r|/srv/samba/public/map-backup-share.ps1`

**Defender view:**
> **L12 — Credential theft — planted svc-backup credential file read on the fs-01 weak share by `LAB\jdoe` from `10.10.40.119`.** (T1552.001)

### 3b. DCSync — rule 100080

In a **single-DC** domain there is no legitimate DC-to-DC replication, so any `DsGetNCChanges` request is
unambiguously an attack. The rule matches Samba's replication-handler log line forwarded via journald.

**Defender view:**
> **L12 — DCSync suspected — AD replication (DsGetNCChanges) invoked on the DC; no legitimate DC-to-DC replication exists in this single-DC domain.** (T1003.006)

*Note:* this fires on impacket's (failing) request. To also catch a **successful** DCSync from a
non-buggy client, raise `log level drsuapi:5` in `smb.conf` so every `DsGetNCChanges` is logged, then key
on the same handler string. In a multi-DC domain the rule must additionally exclude requests whose source
is a real DC (by IP / machine account).

---

## 4. The Samba-vs-Windows-Server boundary (honest findings)

The DC is **Samba** because there is no ARM64 Windows Server ISO for Apple Silicon (see
`docs/design-decisions.md`). Attacking it from Linux `impacket` tooling hits genuine, **version-independent**
interop bugs — not the lab's misconfiguration:

- **Kerberos** — every Kerberos operation (LDAP GSS bind, Kerberoast, Kerberos DCSync) fails with
  `KRB_AP_ERR_INAPP_CKSUM`.
- **DRSUAPI / DCSync** — fails with `Failed to decode remote prefixMap` (impacket's prefixMap encoding).
- **NTLM LDAP bind** — ldap3's NTLMSSP bind is terminated by Samba; BloodHound collection only works via a
  **SIMPLE bind with the UPN** (`jdoe@lab.internal`), which needs strong-auth relaxed or LDAPS.
- **SharpHound** (the Windows-native alternative) ships **x86-only** and cannot load its native
  `SharpHoundRPC` assembly under ARM64 emulation — a dead end on this hardware.

**What this means, and why it's fine for a detection lab:** a *flawless offensive dump* would need a real
Windows Server DC. But detection does not depend on the exploit succeeding — every attack still generates
the telemetry the DC would produce, and all three techniques above are detected. The Windows-specific
*execution* primitives (e.g. Backup Operators → `NTDS.dit` over SMB) simply don't map to Samba, which is
itself a useful thing to understand and document rather than paper over.

---

## Reproduce

- Rules: `phase-4-detection/local_rules.xml` (100080, 100090) + `phase-4-detection/local_decoder.xml`
  (`samba-full-audit`, child of the stock `smbd` decoder).
- fs-01 `[public]` share carries `vfs objects = full_audit` (`full_audit:success = openat`, facility
  `local7`).
- The deliberate misconfigs (svc-backup in Backup Operators + DCSync ACEs) and their revert commands are
  in the private VM inventory note.
