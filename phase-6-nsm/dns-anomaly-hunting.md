# DNS anomaly hunting — DGA and beaconing, beyond the tunneling shape

**Phase 6 — NSM, follow-on to [`dns-tunneling.md`](dns-tunneling.md).** That hunt catches one specific DNS
abuse shape: long, unique, high-entropy subdomains encoding exfiltrated data. Real DNS-based C2 has other
shapes that hunt doesn't look for — a **Domain Generation Algorithm (T1568.002)** burning through many
short, random candidate domains looking for the one that's registered, and plain **periodic beaconing
(T1071.004)** hiding in repeat lookups of one ordinary-looking name. Two new hunts, same methodology as the
rest of Phase 4/6: hypothesis → data source → a small reviewable script → live verification.

> [!check] Executed and verified live on 2026-09-26.
> Generated real DNS traffic from `ws-01`: 10 distinct random-looking domains (DGA shape) and 12 queries to
> one fixed name at a steady 10s interval (beacon shape). `hunt-dns-dga.py` flagged the source host with
> **10/11 gibberish-scored domains, all NXDOMAIN** (score 100 each); `hunt-dns-beacon.py` scored the
> beaconing pair **94** (CV 0.00 — a near-perfect metronome) against normal domains scoring in the teens.
> Testing this also surfaced a real, unrelated documentation bug — see the callout below.

---

## Why these are genuinely new, not a re-run of the tunneling hunt or `hunt-beaconing.py`

- **vs. `hunt-dns-tunnel.py`:** that hunt's signal is *shape of the subdomain* (long, unique, high-entropy
  labels under one zone). DGA domains are the opposite shape — short, low-volume-per-domain, but *many
  distinct* such domains from one host. Scoring them the tunnel hunt's way (mean length ≥ 100 chars) would
  never fire; a DGA candidate like `xqzplkw7f.net` is 13 characters.
- **vs. `hunt-beaconing.py`** (Phase 4 threat-hunting, `conn.log`): that hunt groups by
  `(source, dest-ip, dest-port)`. Every DNS query on this network — malicious and benign alike — goes to the
  *same* resolver IP:53 (dc-01), so that grouping mixes one host's entire DNS history into a single pair and
  the one C2 domain's rhythm drowns in everything else the host looked up. The fix is grouping by the
  **queried domain name** instead of the destination IP — data only `dns.log`, not `conn.log`, actually has.

## Hunt 1 — DGA (`hunt-dns-dga.py`)

**Hypothesis:** malware that can't hardcode a C2 domain (trivially sinkholed/blocklisted) derives many
candidate domains from a shared algorithm and queries them until one resolves. It can't hide the shape:
short, statistically random-looking labels, high volume of *distinct* ones from one host, almost all
NXDOMAIN.

**Method:** score every `(source host, base domain)` pair on how "gibberish" its second-level label looks —
a cheap, explainable heuristic, no ML and no external corpus:

```python
score = (entropy/4.7)*50 + max(0, 0.28 - vowel_ratio)*140 + min(max_consonant_run, 6)*5 + digit_ratio*20
```

Real words and brand names score low (skewed letter frequency, vowels, short n-grams repeat); random
strings approach the 4.7 bits/char ceiling for lowercase a-z. Roll up by **source host**: any single
gibberish+NXDOMAIN domain could be a coincidence (a CDN cache-buster subdomain, say) — a host burning
through a dozen of them in one session is not.

**Verified live:** ws-01 generated 10 random 12-character labels (`snpbsnkvjjgg.net`, `xrwldqnkngxw.net`, …).
The hunt flagged the source with **10 of 11 total distinct domains** scoring 100/100 and 1/1 NXDOMAIN each —
clean separation from zero false positives on the lab's normal DNS traffic in the same window.

**Honest limitations:**
- English-letter-frequency-shaped — a dictionary-word DGA (some newer families use one specifically to evade
  this class of detector) would score low here.
- No real newly-registered-domain/WHOIS-age signal. That needs a continuously-updated external feed, which
  this lab deliberately doesn't depend on (see `docs/design-decisions.md`) — NXDOMAIN volume is the
  always-available proxy: the candidates that never resolve.

## Hunt 2 — Beaconing (`hunt-dns-beacon.py`)

**Hypothesis:** a DNS-based (or DNS-fronted) C2 channel still calls home on a regular cadence, and timing
survives even if the channel content doesn't stand out.

**Method:** group `dns.log` by `(source host, base domain)`; for pairs with enough queries, compute the
coefficient of variation (CV = stdev/mean) of inter-query intervals. Composite score blends interval
regularity with persistence — the same two-signal design `hunt-beaconing.py` uses, and for the documented
reason: CV alone is a trap, since a jittered beacon *deliberately* raises its CV to blend in, so persistence
(does it keep calling?) is what recovers it when regularity alone wouldn't.

**Verified live:** ws-01 queried one fixed name every 10 seconds, 12 times. Scored **94** (mean interval
10.0s, CV 0.00) against the lab's normal DNS traffic in the same window scoring 10–56 — comfortable
separation above the `BEACON_SCORE = 60` triage threshold.

```
    score queries   mean_iv     cv  source -> domain
  ------------------------------------------------------------
  !    94      12    10.0s   0.00  10.10.10.10 -> totally-legit-updates.net
```

## A real gotcha found while proving this live

The source IP in both results above is **dc-01** (`10.10.10.10`), not ws-01 — the host that actually ran the
test queries. Confirmed why: `rtr-01`'s Zeek sensor watches its **CORP interface**, which only sees traffic
*routed through the router* — ws-01 and dc-01 share the same CORP L2 segment, so a plain client→resolver
query between them never crosses that interface at all. What Zeek *does* see is dc-01's own re-origination
of any name it can't answer locally, out to its configured upstream forwarder — which is the leg that
actually matters for these two hunts, since that's where a real DGA/beacon domain would show up too.

Chasing down *why* dc-01 had an upstream to re-originate to at all surfaced a second, unrelated finding:
`roles/dc/files/smb.conf` sets `dns forwarder = 1.1.1.1`, live and working — directly contradicting
`phase-5-offense/atomic-red-team/README.md`'s claim that dc-01 "has no external forwarder" and public names
"deliberately don't" resolve from ws-01. That claim was already stale; corrected in place there rather than
left standing now that it's been disproven live.

## Coverage note

These are **hunts**, not real-time Wazuh rules — same category as `hunt-beaconing.py` and
`hunt-rare-process.py` in the Phase 4 threat-hunting set: an analyst tool that ranks the whole population on
behaviour, not a standing alert. Neither is wired into `technique-index.md`'s coverage count for that
reason (consistent with how the other two hunts are treated) — the value here is the analyst capability, not
a new alert-count line.

## Reproduce

```bash
# generate DGA-shaped and beacon-shaped DNS traffic from a CORP host (ws-01 used here)
# — see phase-6-nsm/hunt-dns-dga.py and hunt-dns-beacon.py headers for the exact hypothesis each looks for

./hunt-dns-dga.py                 # fetch live dns.log from rtr-01 and rank by DGA-likelihood
./hunt-dns-beacon.py              # fetch live dns.log from rtr-01 and rank by beacon score
```

Scripts: [`hunt-dns-dga.py`](hunt-dns-dga.py) · [`hunt-dns-beacon.py`](hunt-dns-beacon.py) · sibling hunt:
[`hunt-dns-tunnel.py`](hunt-dns-tunnel.py) (`dns-tunneling.md`) · related: [`hunt-beaconing.py`](../phase-4-detection/threat-hunting/hunt-beaconing.py)
