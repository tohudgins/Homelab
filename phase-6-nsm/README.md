# Phase 6 — Network Security Monitoring

Two complementary sensors run **inline on rtr-01**, watching `enp26s0` (the CORP segment where the AD
servers live; inter-segment attack traffic is routed through rtr-01, so it appears here):

- **Suricata 7.0.10** — signature IDS, ET Open ruleset, alerts to `/var/log/suricata/eve.json`. Also
  feeds Wazuh (Phase 3).
- **Zeek** — protocol-aware NSM, standalone node (`/opt/zeek/etc/node.cfg`), logs to
  `/opt/zeek/logs/current/` (`conn`, `kerberos`, `dce_rpc`, `smb_files`, `ntlm`, `ldap`, …). Boot-persistent
  via a `zeek.service` systemd unit + a `zeekctl cron` watchdog.

## What's here

- [`pcap-reports/01-attack-chain-nsm.md`](pcap-reports/01-attack-chain-nsm.md) — the Phase-5 attack chain
  (credential theft over SMB → Kerberoasting → DCSync) replayed and analysed three ways: Suricata
  signatures, Zeek protocol logs, and the Wazuh host detections, with a correlation matrix and an honest
  discussion of what encryption does and doesn't hide from a network sensor. **Re-verified live 2026-08-24.**
- [`pcap-reports/02-recon-scanning-nsm.md`](pcap-reports/02-recon-scanning-nsm.md) — a different traffic
  class: an `nmap` service scan of the CORP AD servers. The **mirror image** of the DCSync finding —
  ET Open fires no port-scan signature at all, yet Zeek's `conn.log` shows the scan unmistakably as a
  fan-out (268 connections, 102 ports, 189 `REJ` from one source in ~2 s).
- [`captures/phase5-attacks.pcap`](captures/phase5-attacks.pcap) · [`captures/recon-scan.pcap`](captures/recon-scan.pcap) — the raw captures.

## The headline finding

Signature IDS and protocol-aware NSM catch **different** things, and the two reports bracket it from both
ends. **DCSync has no usable Suricata signature** (the DRSUAPI payload is encrypted) yet Zeek logs the
`DRSGetNCChanges` operation by name; a **port scan** has no content to sign at all, yet Zeek sees the
connection fan-out. In both, the signature engine is blind for a different reason and the connection-aware
sensor covers it — and where content *is* known-bad (a `.ps1` pulled over SMB, weak-enc Kerberos) the ET
signatures fire directly. Run both, layer the host sensor (Wazuh) underneath, and no single blinded sensor
loses the detection.
