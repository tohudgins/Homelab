# NSM analysis: network reconnaissance (service scan), seen two ways

**Phase 6 — Network Security Monitoring.** A companion to [`01-attack-chain-nsm.md`](01-attack-chain-nsm.md),
on a deliberately *different* traffic class: not a credential attack against a named protocol, but **noisy
reconnaissance** — an `nmap` service/version scan from `atk-01` (`10.10.40.119`, REDTEAM) against the CORP
AD servers. Recon is the first move in almost every real intrusion, and it exercises the two sensors in the
opposite direction from the DCSync case, which makes it the ideal second report.

**Sensors** (both inline on rtr-01, watching `enp26s0` = CORP): Suricata 7.0.10 (ET Open) and Zeek.
Full PCAP: [`../captures/recon-scan.pcap`](../captures/recon-scan.pcap) (911 packets).

**The scan:**
```
atk-01$ nmap -sV -T4 --top-ports 100 10.10.10.10 10.10.10.20
# dc-01: 22 ssh, 53 domain, 88 kerberos, 135/49152-4 msrpc, 139/445 smb, 389 ldap (anon bind OK)
# fs-01: 22 ssh, 139/445 smb
```

---

## Correlation — one scan, two vantage points

| Sensor | What it saw | Verdict |
|---|---|---|
| **Suricata (signature)** | `SURICATA Applayer Mismatch protocol both directions` (×8) — nothing else scan-specific | **nearly blind** |
| **Zeek (protocol/connection)** | `conn.log`: **268 connections, 102 distinct dest ports, 189 `REJ`** from one source in ~2 s | **unmistakable** |

This is the **mirror image** of the DCSync row in report 01. There, the *content* was encrypted so the
signature engine was blind and Zeek's protocol parser saved the detection. Here, the *content* is trivial
(empty SYNs to closed ports) so there's no malicious byte-pattern to sign at all — and again it's Zeek's
connection-level view, not signatures, that makes the behaviour obvious. Different reason, same lesson:
**a signature IDS and a connection-aware NSM sensor fail and succeed on different traffic, so you run both.**

---

## 1. Suricata — why a service scan is quiet

ET Open fired **no dedicated port-scan / `ET SCAN` signature** on this scan. The only scan-attributable
alert was `SURICATA Applayer Mismatch protocol both directions` (×8) — a *side effect* of `nmap -sV`, which
sends application-layer probes (HTTP, TLS, etc.) at every open port regardless of what actually listens
there; when the SSH or SMB service answers with its own protocol, Suricata's app-layer parser sees a
request/response protocol mismatch and flags it. Useful, but incidental — a plain SYN scan (`nmap -sS`,
no `-sV`) would produce **no Suricata alert at all**.

This is an honest and important limitation to state plainly in a portfolio: **signature IDS is not a
scan detector.** Port scanning is high-volume, low-content, and perfectly protocol-legal per packet, so
there's nothing for a content signature to match. Scan detection belongs to a *stateful* view — a
threshold/anomaly engine, the firewall's own counters (rtr-01's nftables sees every `REJ`), or exactly the
kind of connection-log analysis Zeek provides below.

## 2. Zeek — the scan is a shape, not a payload

`conn.log`, one source (`10.10.40.119`) in a ~2-second window:

```
#   ts             id.resp_h     id.resp_p  proto  conn_state
    …474530        10.10.10.20   443        tcp    REJ      <- closed port, rejected
    …474533        10.10.10.10   443        tcp    REJ
    …474562        10.10.10.10   80         tcp    RSTRH
    …007063        10.10.10.20   135        tcp    REJ
    …007143        10.10.10.10   25         tcp    REJ
    … (263 more) …
```

Aggregate signature of the scan:

| Metric | Value | Why it's a scan tell |
|---|---|---|
| Connections from one source | **268** | one host, one burst |
| Distinct destination ports | **102** | fan-out across the whole top-100 range |
| `conn_state = REJ` (rejected → closed port) | **189** (71%) | a client that *means* to connect doesn't hit 189 closed ports |
| `conn_state = SF` (normal open/close) | 44 | the actual open services (correlate to the nmap output) |
| `RSTR` / `RSTO` | 29 | reset probes |

No single connection here is suspicious — each is a legal TCP handshake attempt. The **distribution** is
the detection: one source × 100+ ports × a majority of rejected connections × a two-second window is a shape
no legitimate client produces. Zeek hands you that shape directly in `conn.log`; you'd write the detection
as a threshold (`> N distinct resp_p from one orig_h in T seconds`, or an unusually high `REJ` ratio),
which is precisely the connection-level analytic that a signature engine structurally cannot express.

## 3. What this adds to the Phase 6 story

Report 01 showed the network catching a **credential/replication** attack; this one shows it catching
**reconnaissance** — and the two reports bracket the signature-vs-protocol lesson from both ends:

- **Encrypted-but-named** (DCSync): signature blind, Zeek names the operation → Zeek wins.
- **Plaintext-but-contentless** (port scan): nothing to sign, Zeek sees the fan-out → Zeek wins.
- **Known-bad content** (`.ps1` over SMB, weak-enc Kerberos): Suricata's ET rules fire directly → signatures win.

The takeaway a SOC actually uses: **layer the sensors.** Signatures give you high-confidence named alerts
on known-bad content; connection/protocol logs give you behaviour and shape even when content is opaque or
absent; and the host sensor (Wazuh, reports in `phase-4-detection/` and `phase-5-offense/`) is the backstop
when the network can't see inside at all.

---

## Reproduce

1. Capture on the sensor: `tcpdump -i enp26s0 -w recon-scan.pcap host 10.10.40.119` on rtr-01.
2. Scan from atk-01: `nmap -sV -T4 --top-ports 100 10.10.10.10 10.10.10.20`.
3. Suricata: `jq 'select(.event_type=="alert" and .src_ip=="10.10.40.119") | .alert.signature' /var/log/suricata/eve.json | sort | uniq -c`.
4. Zeek: `zeek-cut id.resp_h id.resp_p conn_state < conn.log | grep 10.10 …`; count distinct `resp_p` and the `REJ` ratio for the scan source.
