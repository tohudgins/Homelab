# Atomic Red Team on ws-01 (offline install)

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is the attacker
side of the target host `ws-01`: small, ATT&CK-mapped "atomic" tests you fire on
demand to generate telemetry, then hunt in Wazuh (Sysmon + PowerShell Script Block
Logging are already forwarding to the SIEM). It's the `ws-01`-native counterpart to
the atk-01 → dc-01 attack paths in the rest of `phase-5-offense/`.

## Why offline (by design)

The lab is **internal and self-contained** — it must not depend on anything outside
itself to operate or to be rebuilt. `ws-01` resolves through dc-01's Samba AD DNS,
which is authoritative for `lab.internal` and has **no external forwarder**, so
internal names resolve and public names (`github.com`, …) deliberately don't. Tools
are therefore staged the way real segmented enterprises distribute software into
isolated zones — pulled once on the admin/management host and pushed to the target —
not fetched from the internet by the endpoint.

That's why the stock `Install-AtomicRedTeam -getAtomics` one-liner isn't used: it
needs ws-01 to reach `raw.githubusercontent.com`, i.e. to reach outside the lab.
Adding a DNS forwarder on dc-01 to make it work was rejected for the same reason —
see [`docs/design-decisions.md`](../../docs/design-decisions.md). (For the record:
CORP *does* have WAN egress at L3/L4 — `ping 8.8.8.8` and TCP/443 to a GitHub IP
succeed from ws-01 — so this isolation is at name resolution, which is what the
lab's operations actually traverse.)

> [!warning] Correction found 2026-09-26 — the forwarder claim above is stale.
> Building the DNS-anomaly hunts (`phase-6-nsm/hunt-dns-dga.py` /
> `hunt-dns-beacon.py`) required generating real DNS traffic from ws-01, which
> surfaced that `roles/dc/files/smb.conf` sets `dns forwarder = 1.1.1.1` — live,
> confirmed by watching dc-01 itself query `1.1.1.1` on the wire and return real
> answers (NXDOMAIN for nonexistent names, not a lab-internal refusal) for names
> ws-01 asked it to resolve. **Public names do resolve from ws-01 now**, through
> dc-01 — this README's "public names deliberately don't" claim was already
> inaccurate by the time it was checked here, not a recent regression (the
> forwarder line predates this finding; nothing in this repo's history added it
> reactively). The offline install approach itself is still the right call for
> an unrelated, still-true reason — reproducibility shouldn't depend on GitHub
> being reachable at rebuild time — it just isn't *forced* by DNS isolation the
> way this doc previously claimed.

Practical upshot for anyone hunting DNS anomalies in this lab (see
[`phase-6-nsm/`](../../phase-6-nsm/)): a CORP host's queries to its own resolver
(dc-01) never cross the wire Zeek watches — dc-01 and its clients share the CORP
L2 segment, and `rtr-01`'s sensor only sees traffic *routed through* it. What
**does** cross that interface is dc-01's own re-origination of any name it can't
answer locally, out to `1.1.1.1` — which is exactly the leg a DGA/beacon hunt
needs to see, and exactly why it works here despite the sensor's placement.

## Install / reinstall

From the Mac (has DNS + the SSH path to ws-01 via `ProxyJump rtr-01`):

```bash
./install-art-offline.sh          # defaults to ssh alias ws-01
```

It downloads `invoke-atomicredteam` + `atomic-red-team` + `powershell-yaml`, builds
**clean** tarballs, `scp`s them over, and runs `install-art-windows.ps1` to extract
into the PowerShell module path + `C:\AtomicRedTeam\atomics`, import, and verify.

### Two gotchas baked into the scripts

1. **macOS AppleDouble files.** `tar` on macOS injects `._*` resource-fork files.
   The ART module's `.psm1` dot-sources **every** `Public\*.ps1`, so a stray
   `._AtomicRunnerService.ps1` makes `Import-Module` fail with a parser error. The
   Mac side sets `COPYFILE_DISABLE=1`; the Windows side also strips `._*` as a
   belt-and-braces pass. (First install pulled in 1,978 of these — 1,929 under
   `atomics/` alone.)
2. **powershell-yaml dependency.** The module manifest has a `RequiredModules`
   dependency on `powershell-yaml` (bundles `YamlDotNet.dll`). The online installer
   would grab it from PSGallery; offline we ship it too. It's managed .NET, so it
   loads fine under Windows PowerShell 5.1 on **ARM64**.

## Use

```powershell
Invoke-AtomicTest T1033 -ShowDetailsBrief        # list a technique's tests
Invoke-AtomicTest T1033 -TestNumbers 1           # execute (benign discovery)
Invoke-AtomicTest T1059.001 -TestNumbers 1       # PowerShell exec -> Wazuh rule fires
```

Over SSH from the Mac:

```bash
ssh ws-01 'powershell -NoProfile -c "Invoke-AtomicTest T1033 -TestNumbers 1"'
```

Run simulations as a realistic victim (`asmith`/`bwilson`/`jdoe`), not `localadmin`.
`C:\AtomicRedTeam` has a Defender exclusion so flagged test artifacts aren't
quarantined mid-run.

## Verified state (2026-08-26)

- `Invoke-AtomicRedTeam` **2.1.0** + `powershell-yaml` **0.4.12** in the machine
  module path (auto-loads); **341** atomic technique folders under
  `C:\AtomicRedTeam\atomics`.
- End-to-end proof: `Invoke-AtomicTest T1033 -TestNumbers 1` executed the discovery
  commands live (`whoami` → `ws-01\localadmin`, `qwinsta`, …), generating Sysmon
  process-create telemetry into the Wazuh pipeline.
