# Analyst triage playbooks

`docs/RUNBOOK.md` covers operating the lab (start/stop, run a simulation). `soc-ops-iris.md` covers the
*automated* half of incident response — Wazuh detects, `integratord` escalates or merges into an IRIS case,
zero manual steps. Neither answers the question an analyst actually has to answer once a case lands in front
of them: **is this real, and what do I do about it?** This is that document — for a representative set of
alerts spanning the tactics this lab covers, not an exhaustive one-per-rule-ID list (that would be a
reference table, not a playbook; `phase-4-detection/attack-coverage/technique-index.md` is already that
table). Pick the playbook whose alert matches what's in front of you; the shape generalizes to the ~40 rules
not covered explicitly below.

## How to use this

1. **Open the IRIS case** (or the raw Wazuh alert if `integratord` hasn't escalated it yet — level ≥10
   fires an alert, but only some rules are wired to auto-escalate; see `soc-ops-iris.md` §7's "honest scope
   boundary"). The case already carries the asset, the raw alert JSON, and — if a containment action already
   fired — a merged completion event.
2. **Ask the same three questions every time, before anything technique-specific:** Is this a scheduled
   maintenance window or a known test run (check `To Do.md`-adjacent context / ask whoever's running the
   lab)? Does the source account/IP belong to a real operator, or is it one of the deliberately-planted weak
   accounts (`phase-2-identity/known-weaknesses.md`) or the honeytoken (`svc-sqladmin`, which has *zero*
   legitimate use by definition)? Has this exact alert type fired repeatedly in a short window (a burst is a
   different story than a singleton)?
3. **Then go to the specific playbook below.**

---

## 1. Kerberoasting — rule 100031 (T1558.003)

**What it means:** an account requested Kerberos service tickets (TGS) for 3+ SPNs within 60 seconds — the
signature of an offline-cracking attempt (Rubeus/`impacket-GetUserSPNs`/`kvno`), not normal service use (a
real client only ever needs a TGS for the *one* service it's about to talk to).

**Triage:**
- `samba-tool spn list <requesting-account>` on `dc-01` — did this account have any legitimate reason to
  touch multiple SPNs (an app server, a monitoring tool)? Almost never for a human user account.
- Check which SPNs were requested (`data.timestamp`-adjacent Samba audit lines in `log.samba`) — targeting
  every Kerberoastable service account (`svc-sql`/`svc-backup`/`svc-web`) in one run is the strongest true-
  positive signal; one SPN in isolation is weaker.
- Cross-reference the source IP against `phase-2-identity/known-weaknesses.md` — is the requesting account
  one of the intentionally-weak targets being tested, or a real credential that's been compromised?

**Escalation:** true positive if the requesting account has no service-account justification for multiple
SPN lookups in a burst. This is Credential Access with a likely-successful outcome already baked in (the
weak service-account passwords crack in seconds against a wordlist) — treat as "assume compromised" for
`svc-sql`/`svc-backup`/`svc-web`, not "investigate further."

**Containment:** no automated response wired (see `detection-catalog.md` §3 — deliberately, ticket requests
themselves aren't damage). Manual: rotate the targeted service account's password immediately
(`samba-tool user setpassword <account>`), audit what that account has access to.

**Related:** `01-fs01-credential-theft-to-dcsync.md` §2b, `phase-2-identity/known-weaknesses.md`

---

## 2. DCSync / NTDS dump — rule 100080 (T1003.006 / T1003.003)

**What it means:** a `DsGetNCChanges` replication request hit the DC from a non-DC source. In this
single-DC domain there is **no legitimate reason for this to ever fire** — it's binary, not probabilistic.
Whether the request was scoped to one account (classic DCSync) or unscoped (a full NTDS-equivalent dump)
doesn't change the verdict, just the blast radius.

**Triage:** there isn't really any — this is a "does the source have DCSync-equivalent rights at all"
check, not a "was this authorized" check. `samba-tool dsacl get --objectdn "DC=lab,DC=internal"` shows who
holds replication rights (should be exactly `svc-backup`, the one deliberately over-privileged account, plus
built-in DC accounts). If the source is anyone else, that's a privilege-escalation finding on top of the
credential-theft one.

**Escalation:** always escalate. This is the single highest-confidence, highest-severity alert in the whole
catalog (level 12, and per `soc-ops-iris.md` deliberately not throttled).

**Containment:** no automated response (see `01-fs01-credential-theft-to-dcsync.md` §3b — auto-reverting a
replication grant is riskier than the alert itself in a real domain). Manual: disable the source account
immediately (`samba-tool user disable <account>`), force-rotate **every** credential in the domain if the
dump plausibly succeeded (unscoped request = assume total compromise), review the DCSync ACE grant itself —
if it's `svc-backup` per the lab's own known weaknesses, this may be the deliberate scenario running as
intended; if it's anyone else, someone escalated privilege first and that path needs its own investigation.

**Related:** `01-fs01-credential-theft-to-dcsync.md` §3b (now covers both T1003.006 and T1003.003)

---

## 3. Password spray / Kerberos brute force — rules 100401 / 100041 (T1110.003 / T1110.001)

**What it means:** either one password tried against many accounts (spray, rule 100401) or many passwords
tried against one account (brute force, rule 100041) within a correlation window.

**Triage:**
- Check `wbinfo`/`samba-tool user list` for whether any of the targeted accounts show a recent successful
  logon immediately after the burst — a spray "succeeding" looks like a burst of failures followed by one
  success from the same source.
- If `disable-ad-account` already fired (rule 100041's active response — check the IRIS case for a merged
  100530 completion event), the account is already contained; triage becomes "was the disable correct" not
  "should I act."

**Escalation:** a single low-volume burst from an internal IP during a known test window is likely the lab's
own validation harness (`ad-validate.py`) — check the source IP against `atk-01`'s known address first.
Anything sustained, from an unexpected source, or that correlates with a subsequent successful logon is a
real incident.

**Containment:** rule 100041 already auto-disables the targeted AD account (`disable-ad-account.py`,
hard-excludes `administrator`/`krbtgt`/`guest`) and auto-re-enables at a 600s timeout — verify the timeout
hasn't let a still-actively-targeted account back online. Password spray (100401) has no active response
wired (it targets many accounts, not one — there's no single account to disable); manual: identify and block
the source IP if external, force password resets for any account that shows a subsequent successful auth.

**Related:** `02-password-spray-smb.md`, `soc-ops-iris.md` §7 (the auto-merge behavior for this exact rule)

---

## 4. Security tooling disruption — rule 100060 / 100506 (T1562.001)

**What it means:** someone tried to stop/disable/mask the Wazuh agent, `auditd`, or `samba-ad-dc` (Linux),
or added a Defender exclusion (Windows). **This is the one alert type where you should assume you're
already partially blind on that host** — the whole point of the technique is denying you future visibility.

**Triage:** treat the alert itself as reduced-confidence going forward for *that specific host* — if the
Wazuh agent's disable succeeded even briefly, anything that happened on that host during the gap has no
telemetry. Check `wazuh-control status` / agent connection state directly on the host (don't trust the
manager's last-seen timestamp alone, since a disabled-then-silent agent looks identical to a healthy quiet
one from the manager's side). For the Windows Defender-exclusion variant, check what path was excluded —
that path is now a blind spot on that host for anything dropped there next.

**Escalation:** always escalate — per `detection-catalog.md` §7, this is "arguably the single highest-value
rule in this whole catalog" precisely because it questions whether anything else you're seeing (or *not*
seeing) from that host can be trusted.

**Containment:** re-enable the disabled service/tooling immediately
(`systemctl enable --now wazuh-agent`/`auditd`/`samba-ad-dc`, or `Remove-MpPreference -ExclusionPath`) —
but do this as evidence-preservation, not case closure: the fact that someone tried this at all means the
host needs a fuller compromise investigation, not just "tool restored, done."

**Related:** `detection-catalog.md` §7

---

## 5. SYSVOL / GPO integrity change — rule 100020 (T1484.001)

**What it means:** a write happened under `/var/lib/samba/sysvol` — a GPO or logon script. Blast radius is
domain-wide: every domain-joined host picks this up on its next policy refresh or logon, unlike every other
monitored path in this lab.

**Triage:** the alert carries pre/post MD5/SHA1/SHA256 (via `report_changes`) — diff the actual content
change before doing anything else. A single-character change to a comment is a different story than a new
executable reference in a logon script. Check who has legitimate GPO-edit rights and whether this matches a
known change window.

**Escalation:** always escalate for review even if it turns out benign — per the writeup, this rule is
deliberately "alert on any SYSVOL write, then let a human judge intent," not pre-filtered for maliciousness.

**Containment:** no active response wired on purpose (reverting a file automatically risks clobbering a
legitimate concurrent edit — see `09-sysvol-gpo-integrity-t1484.001.md` §6). Manual: if the change is
confirmed malicious, revert from the pre-change hash/backup and force a policy refresh
(`samba-tool gpo` tooling or direct file restore), then investigate how write access to SYSVOL was obtained
in the first place — that's a bigger problem than the file itself.

**Related:** `09-sysvol-gpo-integrity-t1484.001.md`

---

## 6. Registry Run Key persistence — rule 100070 (T1547.001)

**What it means:** a process wrote an autostart entry to `HKLM`/`HKCU\...\CurrentVersion\Run`. **This is the
noisiest alert in this list by design** — legitimate installers do this constantly, which is the accepted
tradeoff for catching the technique regardless of which tool wrote the key (see
`07-registry-run-keys-t1547.001.md` §3).

**Triage:** this is the one playbook where the *first* question is "what installed, and was that
installation expected?" `$(win.eventdata.image)` in the alert tells you the writing process;
`$(win.eventdata.targetObject)` tells you the exact key. A known software deployment happening at the same
time is the most common explanation — check that before treating this as an incident.

**Escalation:** escalate when the writing process is unexpected (not a known installer/deployment tool), the
target path/value name looks deliberately obfuscated, or it correlates with any other alert on the same host
in the same window — Run-key persistence is rarely step one of an intrusion, so a correlated hit is a much
stronger signal than an isolated one.

**Containment:** no active response (false-positive risk is too high for automated remediation — see the
writeup's own honest false-positive-risk section). Manual: remove the specific registry value after
confirming it's malicious, don't blanket-clear the Run key (breaks legitimate installed software).

**Related:** `07-registry-run-keys-t1547.001.md`

---

## 7. WMI / WinRM lateral movement — rules 100515/100527 / 100516 (T1047 / T1021.006)

**What it means:** `WmiPrvSE.exe` or `wsmprovhost.exe`/`WinRShost.exe` spawned a shell child — someone
executed a command on this host *remotely*, over WMI or WinRM/PS-Remoting.

**Triage:** check the source of the remote connection (Windows Security log 4624/4648-equivalent, or
correlate by timestamp with any credential-access alert shortly before — lateral movement almost always
follows a successful credential-theft step in this lab's own attack chains). Is the source a known admin
workstation, or unexpected?

**Escalation:** always escalate — a shell spawned by WMI/WinRM's own host process is definitionally remote
code execution, not a benign administrative action pattern this lab's rules would otherwise match. The only
question is whether it's an authorized admin action (jump host, remote management tooling) or an attacker.

**Containment:** no active response wired for either (killing an active WMI/WinRM session risks cutting off
legitimate remote administration mid-task — a judgment call, not an automated one). Manual: identify and
terminate the specific remote session if unauthorized, then work backward to how the credential used to
authenticate was obtained.

**Related:** `04-lateral-movement-wmi-winrm-psexec.md`

---

## 8. Sliver C2 beaconing — Suricata 9100001 (JA3) / 9100002 (interval pattern)

**What it means:** either a JA3 TLS fingerprint match for a known Sliver implant, or a connection-count
pattern (≥10 connections in 60s to the same destination) consistent with beaconing — this fires at the
*network* layer, independent of whatever the host-based agent does or doesn't see (the whole point: a
TLS-1.3 C2 channel is invisible to signature IDS and often to a default host agent too, see
`sliver-c2/README.md`).

**Triage:** `zeek-cut` the `conn.log` for the flagged host/destination pair — real cadence (every N seconds,
tight jitter) versus coincidental legitimate traffic that happened to cross the threshold (an app with
frequent polling). Check `full_command`'s `/proc/*/exe` walk (rule 100200) for the same host around the same
time — an in-memory or `/tmp`-resident binary correlating with the network pattern is close to confirmed.

**Escalation:** a JA3 hit (9100001) is high-confidence on its own — it's matching a specific implant
fingerprint, not a heuristic. A pure interval-pattern hit (9100002) with no JA3 match and no
suspicious-binary correlation is weaker and worth a second data point before escalating.

**Containment:** no active response wired (blocking C2 egress automatically on a network-layer heuristic
risks a false-positive outage of legitimate traffic). Manual: block the destination IP/domain at the
firewall, isolate the host from the network, then do full host forensics — network detection alone doesn't
tell you what the implant already did.

**Related:** `phase-5-offense/sliver-c2/README.md`, `phase-4-detection/threat-hunting/README.md` (the
beaconing hunt's composite scoring, for the cases that don't cleanly cross the real-time rule's threshold)

---

## 9. Ransomware canary tampering — rules 100430/100431 (T1486)

**What it means:** the deliberately-planted decoy file (`Q3-Financials-2026.csv`) was modified or deleted —
a canary has no legitimate reason to ever change, so unlike almost every other alert in this list, **there
is no false-positive case to reason about.**

**Triage:** none needed for the verdict — go straight to scope. Check whether *other* files in the same
share changed around the same time (`syscheck` on the rest of `[public]` and any other monitored shares) —
a single canary hit in isolation might be a curious/exploratory read; multiple files changing in the same
burst is active ransomware/mass-tamper behavior in progress, right now.

**Escalation:** always escalate immediately, treat as active incident by default given the technique this
canary exists to catch (encryption/destruction) is typically irreversible once it completes.

**Containment:** no active response (see `deception/README.md` §2 — auto-restoring a canary mid-attack
teaches the attacker their tooling is being watched, without stopping the actual damage elsewhere). Manual:
isolate the host/share from the network immediately, do not wait for confirmation — the cost of a false
alarm here is far lower than the cost of ransomware completing while triage happens.

**Related:** `phase-4-detection/deception/README.md` §2

---

## 10. SAM dump via RemoteRegistry — rules 100560/100561 (T1003.002)

**What it means:** the `RemoteRegistry` service was enabled and started on a Windows host it wasn't already
running on — the mechanism `impacket-secretsdump` (and legitimate remote-registry tools) use to read the
SAM/SECURITY hives.

**Triage:** `RemoteRegistry` is disabled by default and has essentially no routine reason to be toggled —
check whether any legitimate remote-administration tooling in this environment is documented as needing it
(none currently are). If not, there's no ambiguous case here either.

**Escalation:** escalate — this is a completed local-account-credential-theft action by the time the alert
fires (the hive read already happened), not an attempt in progress.

**Containment:** no active response wired. Manual: disable `RemoteRegistry` again if the attacker didn't
already restore it to disabled on exit (check current state — `secretsdump.py` normally does restore it,
which is itself worth noting: a "helpfully" cleaned-up state doesn't mean nothing happened), rotate every
local account password on the affected host, especially any shared local-admin credential.

**Related:** `08-sam-dump-credential-cracking-t1003.002.md`

---

## Related

`docs/RUNBOOK.md` (operating the lab) · `phase-4-detection/soc-ops-iris.md` (the automated case pipeline
these playbooks assume already ran) · `phase-4-detection/attack-coverage/technique-index.md` (every other
rule not covered above — the shape of triage generalizes: what does the alert mean, is there a legitimate
explanation, what's the blast radius, is there an existing active response to verify)
