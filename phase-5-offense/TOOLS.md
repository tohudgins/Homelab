# Offensive tools used in this lab

The writeups and scripts under `phase-5-offense/` use these tools with a bare command line
and no further explanation — this page fills that gap. One paragraph each: what the tool is,
what it's actually doing, and where it shows up in this repo.

## Impacket

A Python library + collection of command-line tools (`impacket-wmiexec`, `impacket-psexec`,
`impacket-GetUserSPNs`, ...) implementing Windows/AD network protocols (SMB, MSRPC, Kerberos)
from scratch, without needing a real Windows client. `impacket-wmiexec` opens a semi-interactive
shell over WMI (spawns `WmiPrvSE.exe` on the target — the exact parent-process signal
rule 100515/100527 keys on); `impacket-GetUserSPNs` requests service tickets for every SPN in
the domain to Kerberoast them offline. Used in `apt-scenario/run-scenario.sh` and
`ad-validate.py`'s lateral-movement and Kerberoasting scenarios.

## NetExec (`nxc`)

The actively-maintained fork of CrackMapExec — a Swiss-army-knife for authenticating against
and enumerating/executing on a whole network of Windows/AD hosts over SMB, WinRM, LDAP, MSSQL,
etc. in one tool. In this lab it drives the password-spray scenario (`nxc smb <dc> -u <user> -p
<pw>` against every domain account) and was tried for WMI/WinRM lateral movement, though its
`--exec-method wmiexec` didn't work against this lab's build (see
`phase-4-detection/sigma/README.md`'s "Verification" section) — Impacket's own tools cover that
gap instead.

## BloodHound (Community Edition)

Maps Active Directory as a graph — every user, group, computer, and permission becomes a node
and edge, so an attack path like "compromise this low-priv account → it's in a group with
DCSync rights → Domain Admin" is a literal shortest-path query instead of something an analyst
has to reconstruct from ADUC by hand. `bloodhound-ce-python` (run from atk-01) is the collector
that walks the real domain over LDAP/SMB and uploads the data; the BloodHound CE web UI (local
Docker Compose, `phase-5-offense/bloodhound-ce/`, no VM or tunnel needed) is where you view and
query the graph. This lab's standing example path: `svc-backup` → `Backup Operators` → DCSync.

## Sliver

An open-source C2 (command and control) framework — the attacker's implant + operator console,
used here to generate real beacon traffic (HTTPS, configurable interval/jitter) for the network
detection side of the lab (Suricata's beaconing signature, the `hunt-beaconing.py` threat hunt)
rather than for actual post-exploitation. A jittered beacon is deliberately harder to catch on
interval-regularity alone — see the beaconing hunt's composite score in `threat-hunting/`.

## iodine

Tunnels arbitrary IP traffic inside DNS queries/responses — the classic DNS-tunneling technique
(T1071.004/T1048.003), used here between fs-01 and atk-01 to trigger both the Suricata
long-encoded-qname signature and the `hunt-dns-tunnel.py` Zeek-based hunt. It exists because DNS
is one of the few protocols almost never blocked outbound, making it a real exfiltration channel
worth having a detection for even though it's slow and lossy in practice.

## Velociraptor / VQL

An open-source endpoint DFIR and fleet-response platform (server on siem-01, clients on
dc-01/fs-01/ws-01). VQL (Velociraptor Query Language) is its SQL-like query language for asking
a question across the whole fleet at once — e.g. "does any host have a file matching this
SHA-256, or a Run-key pointing at this path" — rather than logging into each endpoint by hand.
Used here as `Custom.Hunt.ImplantIOC`, a single hunt that found the Sliver beacon's file and a
persistence entry across both Linux hosts and ws-01 in one query. See
`phase-4-detection/velociraptor/README.md`.

## Related

[`README.md`](README.md) (which script to reach for) ·
[`attack-detect-writeups/`](attack-detect-writeups/) (these tools in context) ·
[`../phase-4-detection/attack-coverage/technique-index.md`](../phase-4-detection/attack-coverage/technique-index.md)
