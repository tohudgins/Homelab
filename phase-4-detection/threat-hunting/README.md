# Threat Hunting — hypothesis-driven hunts in the lab's own telemetry

**Phase 4 — detection engineering, the analyst half.** The rest of Phase 4 writes *rules*: encode a known
bad, alert when it recurs. Hunting is the opposite motion — assume a competent adversary is already inside
and has evaded the rules, form a hypothesis about a behaviour they can't avoid emitting, and go looking for
it in data that isn't alerting. The payoff is the **hunt → detection loop**: a hunt either *confirms* an
existing detection (good — the rule earns its keep and you know a human could find the same thing without
it), or it *surfaces a gap*, and that gap becomes a new rule. Both outcomes appear below, one per hunt, run
against telemetry this lab already generates — **Zeek** NSM on the wire and **Sysmon** endpoint events in
Wazuh.

> [!check] Executed and verified live on 2026-09-04.
> Hunt A ranked a live Sliver C2 beacon to the top of `conn.log` by timing alone (composite score 81 vs 44
> for the next caller) and **confirmed** the existing Suricata beacon rule (9100002, 72 alerts on the same
> traffic). Hunt B stack-counted 145 process events on `ws-01`, surfaced a one-off `bitsadmin.exe` in the
> long tail with **no existing detection**, and closed the loop: authored a Sigma rule (Wazuh 100511/100512,
> T1197), verified 18/18 in `sigma-selftest.py`, deployed it, and proved it fires end-to-end with
> `purple-team.py`. Every number below came out of the running lab.

---

## Methodology

Each hunt follows the same five beats — the structure a SOC hunt report is expected to have, so the process
is legible and repeatable, not a one-off clever query:

| Beat | Question |
|---|---|
| **Hypothesis** | What behaviour would an adversary emit that they *can't* easily suppress? |
| **Data source** | Which log already contains that behaviour — and is it actually being collected? |
| **Analysis** | A small, reviewable script that ranks the whole population by the hypothesised signal. |
| **Triage** | The ranking is not a verdict. Which of the top hits are benign, and *why*? |
| **Outcome** | Promote to a detection, tune an existing one, or dismiss — and record which. |

All three scripts (`hunt-beaconing.py`, `hunt-rare-process.py`, `hunt-kerberoast-baseline.py`) are
stdlib-only, read the telemetry over SSH (or a local copy / stdin), and **rank on behaviour alone** — they
never encode "this IP is bad." The verdict is the analyst's, made in the triage step. That separation is the
point: a hunt tool that already knows the answer isn't hunting.

---

## Hunt A — Beaconing on the wire (Zeek `conn.log`)

**Hypothesis.** A command-and-control implant calls home on a regular cadence. Encryption hides the *content*
of the channel — this lab already proved a TLS-1.3 Sliver beacon walks past a signature IDS
([`phase-5-offense/sliver-c2`](../../phase-5-offense/sliver-c2/README.md)) — but it cannot hide the *timing*.
Regular connections to one destination are a beacon's unavoidable tell.

**Data source.** Zeek `conn.log` from the inline NSM sensor on `rtr-01` (CORP interface). One row per
connection, with start time, 4-tuple, byte counts, and state. The logs are `root:zeek` mode 0640, so the
script fetches them as root (the `rtr-01-root` SSH alias) — reading them as an ordinary user returns nothing,
which is easy to misread as "Zeek isn't capturing."

**Analysis — `hunt-beaconing.py`.** Group every connection by `(source, dest, dest_port)`; for each pair
compute a **composite beacon score (0-100)**, the mean of three signals a real beacon shows and human/app
traffic does not:

1. **interval regularity** — `1 - CV` of the inter-arrival gaps (CV = stddev/mean). A metronome scores 1.
2. **request-size regularity** — `1 - CV` of `orig_bytes`. Identical check-ins score 1; a data-less
   SYN-only pattern scores 0 (it carries no C2 tasking signal).
3. **persistence** — connection count / 20, capped at 1. A beacon keeps calling.

To generate a live signal, a fresh Sliver HTTPS beacon (5 s interval, jitter 3) was landed on `fs-01` (CORP)
pointed at `atk-01` (REDTEAM:443), exactly as in the Sliver writeup. The ranked result:

```
== Beacon hunt :: 135 connections, 12 src/dst/port pairs, 3 with >=8 conns ==
   ranking by composite beacon score (interval + size regularity + persistence); flagged >= 60

    score conns  interval  iv_cv  req_sz  sz_cv   st  source        -> destination     seg
  ----------------------------------------------------------------------------------------
  !    81    70     6.3s   0.25   2577B   0.33   SF  10.10.10.20   -> 10.10.40.119    REDTEAM
       44     9    13.0s   0.13      0B      -   S0  10.10.10.20   -> 10.10.30.10     SOC/MGMT
       33    22    23.5s   1.83      0B      -  OTH  10.10.10.1    -> 10.10.10.20     CORP
```

The Sliver beacon (`10.10.10.20 → 10.10.40.119:443`) tops the ranking at **81**: 70 established connections
every ~6 s carrying consistent ~2.5 KB requests. The raw `conn.log` cadence is human-readable once ranked —
a burst of tasking, then a steady ~5–8 s metronome, each connection alive ~0.02 s:

```
1788574629.70  10.10.10.20 -> 10.10.40.119:443  SF  dur=0.016  orig_bytes=3228
1788574634.91  10.10.10.20 -> 10.10.40.119:443  SF  dur=0.016  orig_bytes=2425   (+5.2s)
1788574639.99  10.10.10.20 -> 10.10.40.119:443  SF  dur=0.017  orig_bytes=3182   (+5.1s)
1788574646.41  10.10.10.20 -> 10.10.40.119:443  SF  dur=0.016  orig_bytes=2398   (+6.4s)
```

**Triage — the finding that matters, and why a single metric is a trap.** Look at the `iv_cv` column. The
*most regular* caller in the whole capture is **not** the malware — it's `10.10.10.20 → 10.10.30.10:1514`
(CV 0.13), the **Wazuh agent's own keepalive to the SIEM**. Rank on interval CV alone and the benign
keepalive floats *above* the C2, because Sliver's `--jitter 3` deliberately raises the beacon's interval CV
(0.25) to blend in — **jitter is the evasion, aimed at exactly this hunt.** Two things recover the beacon:

- **The composite score**, not raw CV. The keepalive is data-less (`orig_bytes` 0, state `S0` — SYN-only
  connection attempts while the SIEM was still booting) and lower-volume, so its size and persistence signals
  are weak; it scores 44. The beacon carries real, semi-consistent payloads across 70 completed connections;
  it scores 81. Combining three signals beats any one.
- **Destination triage.** Both regular callers are surfaced by the tool; the analyst separates them by *where*
  they phone. `→ SOC:1514` is the Wazuh channel — expected infrastructure, dismissed. `→ REDTEAM:443` is a
  CORP host repeatedly contacting the attacker segment on 443 — treated as C2 until proven otherwise. The
  third caller (`10.10.10.1 → fs-01`, CV 1.83) is my own bursty SSH/scp admin traffic, correctly *not* a beacon.

**Outcome — confirms an existing detection.** The beacon the hunt found by timing is the same one the Suricata
NSM rules alert on. On the identical live traffic, **rule 9100002 (behavioural beaconing) fired 72 times** and
9100001 (Go-TLS JA3 implant fingerprint) 146 times. So the hunt *confirms* the signature — and, more useful,
proves a hunter would find this beacon **even with no signature at all**, purely from `conn.log` timing. No
new rule needed here; the value is the validated analytic and the documented jitter/keepalive trap.

---

## Hunt B — Rare processes on the endpoint (Sysmon EID 1 via Wazuh)

**Hypothesis.** On any endpoint the same handful of binaries run constantly (the shell, PowerShell, the
agent, housekeeping tasks) while an attacker's tooling — a LOLBin pressed into service, a one-off downloader —
runs *rarely*. So the **rarest** processes are, disproportionately, the ones worth looking at. "The
least-frequent occurrence is often the most interesting" is the oldest hunt there is (SANS stack counting).

**Data source — and a real prerequisite this hunt exposed first.** The obvious source is the SIEM. But Wazuh
only writes **rule-matched** events to `alerts.json`, and the stock Sysmon EID 1 rules only alert on
*already-suspicious* patterns (the base rule, 92000, requires a `cscript`/`wscript` parent). You cannot find a
rare-but-innocuous-*looking* process in a corpus that has already been filtered down to suspicious ones —
the hunt's own input was missing. **Fix:** enable full-event archiving on the manager
(`<logall_json>yes</logall_json>`), which streams every event to `/var/ossec/logs/archives/archives.json`.
Collecting the telemetry is step zero of hunting it — a finding in its own right, and now a durable capability
for future hunts.

**Analysis — `hunt-rare-process.py`.** Pull every Sysmon EID 1 (process-creation) event for one agent from
the archive; stack-count by image basename (rarest first) and by parent → child relationship, with a sample
command line per image for triage. A realistic corpus was generated on `ws-01` (common admin binaries run
many times) and a single **Atomic Red Team T1197-1** (`bitsadmin` download) fired once as the needle:

```
== Rare-process hunt :: agent=ws-01 :: 145 process-creation events, 21 distinct images ==
   long tail first — the rarest binaries are the most interesting

  count      %  image                  parent           sample command line
  ------------------------------------------------------------------------------------------------
      1   0.7%  bitsadmin.exe          cmd.exe          bitsadmin.exe /transfer /Download /priority Foreground https
      1   0.7%  mousocoreworker.exe    svchost.exe      "C:\WINDOWS\uus\ARM64\MoUsoCoreWorker.exe" useprivaten
      1   0.7%  sc.exe                 svchost.exe      "C:\WINDOWS\system32\sc.exe" start pushtoinstall regist
      1   0.7%  svchost.exe            services.exe     C:\WINDOWS\System32\svchost.exe -k netsvcs -p -s PushToIn
      1   0.7%  wmiadap.exe            svchost.exe      wmiadap.exe /F /T /R
      1   0.7%  wsqmcons.exe           svchost.exe      "C:\WINDOWS\System32\wsqmcons.exe"
      2   1.4%  systeminfo.exe         powershell.exe   ...
    ...
     32  22.x%  sshd.exe / cmd.exe / whoami.exe / powershell.exe   (the fat head — expected)
```

**Triage — six singletons, one anomaly.** Six binaries ran exactly once. Five are ordinary Windows
housekeeping, and the **parent → child** view proves it: `mousocoreworker` (Windows Update), `wmiadap` (WMI
perf), `wsqmcons` (telemetry), and the `sc start pushtoinstall` / `svchost -k netsvcs` pair are all spawned by
`svchost.exe`/`services.exe` — the expected ancestry for a system service. **`bitsadmin.exe` is the one that
doesn't fit:** a download utility, spawned by an interactive **`cmd.exe`**, with an **external URL** in its
command line writing to a user `Temp` path. That ancestry + argument shape is what separates the needle from
the benign long tail — rarity found it, ancestry and command line confirmed it.

**Outcome — surfaces a gap, closes the loop.** `bitsadmin` (T1197, BITS Jobs) had **no detection** anywhere in
the ruleset — not stock Wazuh, not the custom catalog. So it became a rule, via the same detection-as-code
path the rest of Phase 4 uses:

1. **Authored** [`sigma/rules/proc_creation_win_bitsadmin_download.yml`](../sigma/rules/proc_creation_win_bitsadmin_download.yml)
   — `bitsadmin.exe` (by image *or* `OriginalFileName`) **and** a transfer verb (`/transfer`, `/create`,
   `/addfile`), so an enumerate-only `bitsadmin /list` doesn't fire.
2. **Compiled** with `sigma-to-wazuh.py` → Wazuh rules **100511 / 100512** (T1197, level 8); verified
   **18/18** in `sigma-selftest.py` (both TP variants fire, `bitsadmin /list` correctly does not).
3. **Deployed** with `ansible-playbook siem.yml -l siem-01`, then **live-fired** with `purple-team.py`:
   T1197-1 executed on `ws-01` → the rule fired within the settle window. Loop closed on camera.

The catalog gains technique **#34 (T1197)**; the ATT&CK coverage map was regenerated (`generate-coverage.py`),
adding T1197 as a validated technique and giving Defense-Evasion/Persistence a new, hunt-born detection.

---

## Hunt C — A patient Kerberoast, by rarity not volume (Wazuh archive)

> [!check] Executed and verified live on 2026-09-12.
> Fired a single `kvno` ticket request as `jdoe` against `svc-sql`'s SPN — the exact "one targeted request"
> evasion the T1558.003 write-up already documented against rule 100031. The rule's alert count stayed at 1
> (unchanged), confirming the evasion still works. The hunt immediately surfaced
> `jdoe -> MSSQLSvc/dc-01.lab.internal:1433@LAB.INTERNAL` as a fresh singleton — a targeted Kerberoast a
> threshold rule structurally cannot see, caught anyway.

**Hypothesis.** Rule 100031 keys on *volume* — 3+ TGS-REQs from one account in 60s
([`detection-catalog.md` #3](../detection-catalog.md#3-t1558003-kerberoasting)) — so a patient attacker who
already knows which SPN is worth cracking requests **one** ticket and produces zero alerts, confirmed live
when the catalog entry was first written. But "one ticket" undersells how rare that really is: an ordinary
domain account has essentially no legitimate reason to ever request a *service* SPN's ticket directly — that
happens transparently when a real client uses the service, not via an interactive `kinit`/`kvno`/impacket
call. So the **(account, SPN) pair itself**, not the request count, is the signal — the same "the
least-frequent occurrence is the most interesting" idea as Hunt B, pointed at Kerberos tickets instead of
process execution.

**Data source.** The same Wazuh full-event archive Hunt B needs (`<logall_json>yes</logall_json>`, already
on) — `"type":"KDC Authorization"` TGS-REQ events, the same telemetry rule 100031 itself is built on.

**Analysis — `hunt-kerberoast-baseline.py`.** Stack-count every `(account, serviceDescription)` pair seen in
the archive; rank singletons first, same as `hunt-rare-process.py`. Samba logs the requesting account as the
literal string `"null"` when a Kerberoast tool's own TGS-REQ fails to resolve a requester (the same
`KRB_AP_ERR_INAPP_CKSUM` interop wall documented throughout Phase 5) — those are counted separately as
*unattributed* rather than silently dropped, since a burst of them is itself exactly what rule 100031's
`same_field` grouping on the literal `"null"` already catches.

```
== Kerberoast baseline hunt :: 9 attributed TGS-REQs (7 unattributed), 2 accounts,
   7 distinct SPNs, 7 distinct (account, SPN) pairs ==

  count  account          spn                                             first seen
  ---------------------------------------------------------------------------------------------
      1  WS-01$           LDAP/dc-01.lab.internal/lab.internal@LAB...     2026-09-12T01:37:56Z
      1  WS-01$           krbtgt/LAB.INTERNAL@LAB.INTERNAL                2026-09-12T01:37:56Z
      1  jdoe             MSSQLSvc/dc-01.lab.internal:1433@LAB.INTERNAL   2026-09-12T01:50:49Z
      3  WS-01$           ldap/dc-01.lab.internal/lab.internal@LAB...     2026-09-12T01:37:56Z
```

**Triage.** The five `WS-01$` singletons are the workstation's own machine-account authentication (LDAP,
CIFS, `krbtgt`, its own SPN) — routine domain-join traffic, easily dismissed by *who* is asking (a computer
account, requesting infrastructure tickets its own logon needs). `jdoe -> MSSQLSvc/...` is a human user
account requesting a **SQL Server** service ticket directly — no legitimate reason for that pairing to ever
exist, and it's a first-time occurrence for this account. That contrast (routine self-service infrastructure
vs. a human reaching for someone else's service ticket) is the actual triage signal, not just "singleton."

**Outcome — closes a documented evasion, as a hunt not a rule.** Deliberately **not** promoted to the ATT&CK
coverage map — a periodic archive query is a different instrument from a real-time correlation rule, the
same honesty already applied to Velociraptor's fleet hunts. But it closes the gap the catalog named as
"out of scope for what this lab can verify" back when T1558.003 was first written: a targeted, patient
Kerberoast that a threshold rule cannot see by design is still visible to an analyst who ranks by rarity
instead of volume, verified against the identical live evasion the rule itself couldn't catch.

---

## The loop, both directions

| Hunt | Signal | Data | Result | Detection outcome |
|---|---|---|---|---|
| **A — Beaconing** | inter-arrival regularity + payload consistency + persistence | Zeek `conn.log` | Sliver C2 ranked #1 by timing alone | **Confirms** Suricata 9100002 — and proves the analytic stands without the signature |
| **B — Rare process** | execution frequency (stack counting) | Sysmon EID 1 (Wazuh archive) | one-off `bitsadmin` in the long tail | **Surfaces a gap** → new Sigma rule 100511/100512 (T1197), validated live |
| **C — Kerberoast baseline** | (account, SPN) pair rarity | KDC Authorization (Wazuh archive) | `jdoe`'s single targeted ticket ranked as a fresh singleton | **Closes a documented evasion** of rule 100031 — as a hunt, not a new rule |

Three honest findings worth carrying forward, all about the *limits* of a single-signal hunt or rule:

- **Jitter defeats naive beacon hunting.** Ranking on interval regularity alone floats a no-jitter benign
  keepalive above a jittered C2. The fix isn't a better threshold — it's more signals (payload, volume) plus
  destination context. A hunt is a ranking to triage, never an alarm to trust.
- **You can't hunt what you don't collect.** The rare-process hunt was impossible until full-event archiving
  was turned on; the SIEM's default alert-only view had already discarded the population the hunt needed.
- **A rule can be structurally blind to a shape of attack, and still leave a trail elsewhere.** Rule 100031
  cannot see a single targeted ticket request by design (no volume, nothing to threshold on) — but the same
  telemetry it reads is still a rare event when ranked a different way. The rule and the hunt watch the same
  data for different signals; neither replaces the other.

---

## Reproduce

```bash
# --- Hunt A: rank conn.log by beacon behaviour (reads the sensor as root) ---
cd phase-4-detection/threat-hunting
./hunt-beaconing.py                       # or: ssh rtr-01-root cat <conn.log> | ./hunt-beaconing.py -
#   confirm it against the signature it maps to:
ssh rtr-01-root "grep -aoE '\"signature_id\":910000[12]' /var/log/suricata/eve.json | sort | uniq -c"

# --- Hunt B: stack-count process creation for an agent (needs <logall_json>yes) ---
./hunt-rare-process.py --agent ws-01
#   close the loop for a rare process with no rule:
#     1. write phase-4-detection/sigma/rules/<name>.yml   2. ./sigma-to-wazuh.py && ./sigma-selftest.py
#     3. (ansible) ansible-playbook siem.yml -l siem-01   4. (purple-team) ./purple-team.py

# --- Hunt C: rank (account, SPN) pairs by rarity (needs <logall_json>yes) ---
./hunt-kerberoast-baseline.py
#   reproduce the exact evasion + hunt result:
ssh atk-01 "kinit jdoe@LAB.INTERNAL <<< '<jdoe password>' && kvno MSSQLSvc/dc-01.lab.internal:1433@LAB.INTERNAL"
ssh siem-01 "sudo grep -ac '\"id\":\"100031\"' /var/ossec/logs/alerts/alerts.json"   # unchanged - the evasion
./hunt-kerberoast-baseline.py                                                        # jdoe -> MSSQLSvc appears
```

Scripts: [`hunt-beaconing.py`](hunt-beaconing.py), [`hunt-rare-process.py`](hunt-rare-process.py),
[`hunt-kerberoast-baseline.py`](hunt-kerberoast-baseline.py). The detection Hunts A/B feed lives as code in
[`../sigma/`](../sigma/) and the coverage they change is in [`../attack-coverage/`](../attack-coverage/);
Hunt C deliberately stays a hunt, not a coverage-map entry (see its Outcome above).
