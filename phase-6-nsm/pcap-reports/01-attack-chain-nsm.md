# NSM analysis: the Phase-5 attack chain, seen three ways

**Phase 6 — Network Security Monitoring.** The same attack chain from Phase 5, replayed from `atk-01`
(`10.10.40.119`, REDTEAM) against the CORP AD servers, and observed *on the wire* by two complementary
engines running inline on the router, then correlated against the host-based Wazuh detections.

**Sensors** (both on rtr-01, watching `enp26s0` = the CORP segment where dc-01/fs-01 live; inter-segment
traffic is routed through rtr-01, so the attacker's packets appear here):

- **Suricata 7.0.10** — inline, ET Open ruleset (signature IDS: "is this a *known-bad* pattern?")
- **Zeek** — standalone (protocol-aware NSM: "what *happened*, connection by connection?")
- Full PCAP: [`../captures/phase5-attacks.pcap`](../captures/phase5-attacks.pcap) (185 packets)

The point of Phase 6 is that these answer different questions, and the gaps in one are covered by another
— including the host sensor from Phase 4/5.

> [!check] Re-verified live on 2026-08-24.
> The full chain was re-run from `atk-01` and both sensors reproduced every artifact below from fresh
> traffic: Suricata fired `SURICATA Kerberos 5 weak encryption parameters` (×10), `ET HUNTING Possible
> Powershell .ps1 Script Use Over SMB` (×8), and `ET INFO SMB2 … Powershell .ps1 File` (×4), with **no
> DCSync signature** (only `ET EXPLOIT Possible GoldenPac` ×5 on the Kerberos leg); Zeek logged
> `smb_files` → `map-backup-share.ps1`, `kerberos` → 3× failed `TGS jdoe→krbtgt`, `ntlm` → `jdoe`/`svc-backup`,
> and — the headline — `dce_rpc` → **`drsuapi DRSGetNCChanges` by name** (alongside DRSBind/DRSCrackNames).
> A second report on a different traffic class (network recon) is in [`02-recon-scanning-nsm.md`](02-recon-scanning-nsm.md).

---

## Correlation matrix — one attack, four vantage points

| Technique | Suricata (signature) | Zeek (protocol log) | Wazuh (host) |
|---|---|---|---|
| **T1552.001** credential theft — read `map-backup-share.ps1` on fs-01 | `ET HUNTING Possible Powershell .ps1 Script Use Over SMB`; `ET INFO SMB2 NT Create AndX Request For a Powershell .ps1 File` | `smb_files.log`: `SMB::FILE_OPEN map-backup-share.ps1` | rule **100090** |
| **T1558.003** Kerberoasting | `SURICATA Kerberos 5 weak encryption parameters` | `kerberos.log`: `TGS … success=F KRB_AP_ERR_INAPP_CKSUM` | rule **100031** |
| **T1003.006** DCSync | *(no signature for the DRSUAPI payload)* → only `ET EXPLOIT Possible GoldenPac` on the Kerberos leg | `dce_rpc.log`: `drsuapi DRSBind → DRSGetNCChanges` | rule **100080** |

The single most important row is the last one — see §4.

---

## 1. Credential theft over SMB (T1552.001)

**Wire (Zeek `smb_files.log`):**
```
1786936984.459596  10.10.40.119 → 10.10.10.20  SMB::FILE_OPEN  map-backup-share.ps1
```
Zeek names the exact file opened. Paired with `conn.log`
(`10.10.40.119 → 10.10.10.20:445  tcp  gssapi,smb,ntlm`) and `ntlm.log`, which exposes the authenticating
identity in cleartext: `jdoe / ATK-01 / LAB.INTERNAL`.

**Suricata:** the ET ruleset fires on the *behaviour* — a `.ps1` file being pulled over SMB2 — with both an
INFO (`SMB2 NT Create AndX Request For a Powershell .ps1 File`) and a HUNTING
(`Possible Powershell .ps1 Script Use Over SMB`) alert. This is exactly the kind of "script/tool pulled
from a share" pattern the ET ruleset is tuned for, and it independently corroborates Wazuh rule 100090.

## 2. Kerberoasting (T1558.003)

**Wire (Zeek `kerberos.log`):**
```
1786936986.663973  10.10.40.119 → 10.10.10.10  TGS  jdoe/LAB.INTERNAL  krbtgt/LAB.INTERNAL  F  KRB_AP_ERR_INAPP_CKSUM
```
Zeek logs the TGS-REQ *and the exact Kerberos error* — the impacket↔Samba `INAPP_CKSUM` bug (documented in
Phase 5) is visible right here at the network layer, from a completely independent sensor. A burst of TGS
requests in a fraction of a second, all failing identically, is itself the Kerberoasting signal.

**Suricata:** `SURICATA Kerberos 5 weak encryption parameters` — the Kerberos parser flags the weak
(RC4-family) encryption the roasting request negotiates, which is the classic Kerberoast network tell.

## 3. DCSync (T1003.006)

**Wire (Zeek `dce_rpc.log`):**
```
1786936988.913030  10.10.40.119 → 10.10.10.10:49153  drsuapi  DRSBind
1786936988.916623  10.10.40.119 → 10.10.10.10:49153  drsuapi  DRSGetNCChanges   <-- the replication pull
1786936988.919189  10.10.40.119 → 10.10.10.10:49153  drsuapi  DRSGetNCChanges
```
`ntlm.log` ties the operation to the account: `svc-backup / lab.internal`. A **`DRSGetNCChanges` from a
host on the REDTEAM segment** — a machine that is not a Domain Controller — is an unambiguous DCSync
indicator on the wire.

---

## 4. The key NSM lesson: signatures vs. protocol logs vs. encryption

**DCSync has no Suricata signature here.** The DRSUAPI request rides inside an RPC bind whose payload is
encrypted, so a signature IDS has nothing byte-pattern-matchable to fire on — the only Suricata alert on
that leg was a loosely-related `Possible GoldenPac` on the Kerberos authentication, not the replication
itself. **Zeek catches it anyway**, because it parses the DCE/RPC layer and logs the *operation name*
(`DRSGetNCChanges`) rather than trying to match payload bytes. This is the whole argument for running a
protocol-aware NSM sensor alongside a signature IDS: signatures catch known-bad content; Zeek catches
known-bad *behaviour* even when the content is opaque.

**What encryption hides, and what it doesn't.** None of these attacks used TLS (no `tls.log` was produced),
but parts of the traffic are already encrypted at the application layer — the DRSUAPI payload, Kerberos
pre-auth, SMB session data. Crucially, **the metadata survives encryption**: *who* authenticated (NTLMv1/2
leaks the username outright), *which* endpoint/operation was invoked, *which* file was opened, *how much*
data moved, and *when*. Had the attacker wrapped LDAP in TLS (LDAPS) to evade content inspection, Zeek
would still record the connection, the JA3/JA3S, the volumes and the timing — enough to detect the
behaviour without ever seeing the plaintext. The honest limit: if the *content* is what you need (e.g. the
specific LDAP filter, or the secrets DCSync pulled), encryption denies it to the network sensor, and you
fall back to the host (Wazuh) or the DC's own logs. That host+network layering is exactly why all three
techniques are caught here regardless of which single sensor is blinded.

---

## Reproduce

1. Zeek: standalone on `enp26s0` (`/opt/zeek/etc/node.cfg`), `zeekctl deploy`. Logs in
   `/opt/zeek/logs/current/`.
2. Suricata: already inline on `enp26s0` with ET Open; alerts in `/var/log/suricata/eve.json`.
3. `tcpdump -i enp26s0 -w capture.pcap host 10.10.40.119`, then replay the three attacks from atk-01
   (see `phase-5-offense/attack-detect-writeups/`), stop the capture.
4. Correlate: `zeek-cut` the protocol logs, filter eve.json for `alert` events, open the PCAP in Wireshark.
