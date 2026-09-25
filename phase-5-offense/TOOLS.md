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

## Hashcat / John the Ripper

Offline password crackers — given a captured hash and a candidate password (from a wordlist,
rule-mangled variants, or a brute-force mask), they compute the same hash algorithm on each
candidate and compare, recovering the plaintext behind a hash pulled from somewhere like a SAM
dump or a Kerberoast ticket. Hashcat is GPU-first (OpenCL/CUDA) and by far the faster of the two
on real hardware; John the Ripper is CPU-only and needs no compute backend at all, which matters
here — this lab's ARM64 VMware VMs have no GPU passthrough and no packaged CPU OpenCL runtime for
Kali ARM64, so hashcat genuinely cannot run standalone in this environment (confirmed, not
assumed — see `attack-detect-writeups/08-sam-dump-credential-cracking-t1003.002.md`), and John
does the actual cracking. Both read the same hash-format conventions (mode `1000`/`--format=NT`
for a Windows NTLM hash, mode `13100` for a Kerberoast TGS ticket).

## Metasploit Framework

The canonical exploitation/post-exploitation framework — a library of modules (exploits,
auxiliary scanners, payloads) driven interactively through `msfconsole`, with a Postgres-backed
database tracking hosts/services/credentials/loot across a whole engagement instead of one
throwaway command at a time. Ships bundled with Kali's `kali-linux-headless` metapackage (no
separate install needed on atk-01) — confirmed arm64-native, no emulation: `Framework Version:
6.5.3-dev` running directly on Kali ARM64. The database backend isn't wired up by default;
`sudo msfdb init` creates the `msf`/`msf_test` databases and `sudo systemctl enable postgresql`
makes it survive a reboot/suspend-resume, both one-time setup steps on a fresh atk-01 build.
Verified end-to-end with `db_nmap` against dc-01 — scan results land directly in `hosts`/
`services`, the same workspace a later `use exploit/...; set RHOSTS ...` would target. Genuinely
overlaps with what Impacket/NetExec already do against this lab's Samba AD DC — the value here
isn't new attack surface, it's fluency with the single most industry-referenced pentesting tool,
run interactively rather than scripted.

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

## Responder

An LLMNR/NBT-NS/mDNS poisoner — it answers name-resolution broadcasts a Windows host sends when a DNS
lookup fails (a typo'd share name, a mistyped hostname), impersonating whatever was asked for and harvesting
the NTLMv2 challenge-response the victim sends back trying to authenticate to it. Arguably the single most
common real-world internal-network initial-access technique (MITRE
[T1557.001](https://attack.mitre.org/techniques/T1557/001/) — Adversary-in-the-Middle: LLMNR/NBT-NS
Poisoning and SMB Relay), and not in this lab's coverage map at all before this. Already shipped with
`kali-linux-headless` on atk-01, unused until now — same "already installed, never exercised" story as
Metasploit. **Real infrastructure gap it exposed:** LLMNR/NBT-NS/mDNS are link-local broadcast protocols —
`rtr-01` never forwards them across segments — so atk-01's original single REDTEAM-only NIC could never have
seen this traffic no matter how it was configured. Gave atk-01 a second NIC directly on CORP (`vmnet3`,
`10.10.10.99` static) specifically so Responder has a real broadcast domain to listen on, the same way a
real attacker needs an actual foothold on the target segment (not just adjacency to it) before this
technique works at all. `sudo responder -I eth1` on atk-01.

## Burp Suite (Community Edition) / OWASP ZAP

The two standard intercepting-proxy web application testing tools — sit between a browser and the target,
letting you see, pause, and hand-edit every HTTP request before it's sent (Burp's Repeater/Intruder, ZAP's
equivalent), rather than only running an automated scanner like `sqlmap`/`nikto` against a fixed target URL.
This is the actual day-to-day tool for manual web app pentesting and bug-bounty work — parameter tampering,
auth/session testing, business-logic flaws a scanner can't reason about. Both installed on atk-01 (`apt
install burpsuite zaproxy`, both arm64-native, confirmed via `--version`/`-version`); both are GUI
applications, reached by opening the atk-01 VM's own window in VMware Fusion (it already runs a full Xfce
desktop via `lightdm` — no VNC/X11-forwarding setup needed) rather than over SSH. Point either at the
existing DMZ Juice Shop target (`10.10.20.10:3000`) for practice.

## Related

[`README.md`](README.md) (which script to reach for) ·
[`attack-detect-writeups/`](attack-detect-writeups/) (these tools in context) ·
[`../phase-4-detection/attack-coverage/technique-index.md`](../phase-4-detection/attack-coverage/technique-index.md)
