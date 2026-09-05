# Velociraptor — endpoint DFIR + VQL fleet hunting

**The honest capability gap, closed.** The lab had a SIEM (Wazuh), case management (DFIR-IRIS), threat
intel (MISP), and network monitoring (Suricata + Zeek) — but **no live endpoint forensics**. When a Wazuh
alert or a hunt (see [`../threat-hunting/`](../threat-hunting/README.md)) says "look at this host," there was
no way to reach *onto* the box and ask questions of its live disk, registry, and processes, let alone ask the
same question of every host at once. [Velociraptor](https://docs.velociraptor.app/) is the tool pros use for
exactly that: a single Go binary — server and client — driven by **VQL**, its SQL-like query language, so a
DFIR question becomes a query you run across the whole fleet and get answers back in seconds.

> [!check] Deployed and verified live on 2026-09-04.
> Server on `siem-01` (arm64-native) + three enrolled clients — `dc-01`, `fs-01` (native linux/arm64) and
> `ws-01` (Windows-on-ARM, running the amd64 client under x64 emulation). A single **VQL hunt across the
> fleet** found a planted implant on every affected host: the Add-1 Sliver beacon in `/tmp` on both Linux
> hosts (by SHA-256) and a registry Run-key persistence entry on `ws-01`. Deployed as an Ansible role that
> re-converges `changed=0`.

---

## 1. De-risk first: is there an arm64 Windows client? (No — and what that means)

This lab is ARM64-only, so the first step was checking the release assets, not assuming:

```
$ gh api repos/Velocidex/velociraptor/releases/latest --jq '.assets[].name' | grep -iE 'windows|arm64'
velociraptor-v0.77.2-linux-arm64          <- server + Linux clients: native
velociraptor-v0.77.2-windows-386.exe
velociraptor-v0.77.2-windows-amd64.exe    <- Windows: only 386 / amd64, NO arm64
```

**There is no `windows-arm64` Velociraptor build.** `ws-01` is Windows 11 on ARM64. Rather than drop it from
the fleet, the client is the **windows-amd64 binary run under Windows 11's built-in x64 emulation** — and it
works: the service runs, enrolls, and performs real Windows DFIR (the Run-key registry collection below came
back from it). The one honest caveat: the client reports `architecture: amd64` (it sees the emulated
environment), and low-level collectors that bypass the Win32 API (raw `\\.\PhysicalDrive` access, some kernel
telemetry) may behave differently under emulation than on native hardware; the everyday DFIR surface —
files, registry, WMI, processes, event logs, all of which go through Windows APIs the emulation layer
supports — is unaffected. Native-arm64 Linux clients have no such caveat.

*This is the "verify the architecture before you design" discipline the whole lab runs on (cf. the
amd64-only TheHive/Cortex finding that sent SOC-ops to DFIR-IRIS instead).*

---

## 2. Architecture

```
        CORP (10.10.10.0/24)                         SOC (10.10.30.0/24)
   ┌──────────┬──────────┬──────────┐          ┌───────────────────────────┐
   │  dc-01   │  fs-01   │  ws-01    │  8000/tcp │  siem-01                  │
   │ linux    │ linux    │ windows   │ ────────▶ │  velociraptor-server      │
   │ arm64    │ arm64    │ amd64(emu)│  client   │  frontend :8000 (clients) │
   │ (client) │ (client) │ (client)  │  comms    │  GUI      :8889 (tunnel)  │
   └──────────┴──────────┴──────────┘          └───────────────────────────┘
        rtr-01 nftables: CORP -> SOC tcp/8000 accept  (added to the router role)
```

- **Server on `siem-01`** (already the SOC host). A single binary runs the client-facing frontend (`:8000`)
  and the admin GUI (`:8889`, bound to localhost — reached over an SSH tunnel, never exposed). Self-signed
  deployment: Velociraptor generates its own CA and pins it in every client config, so clients validate the
  server by the pinned CA, not by hostname — which is why they connect to the SOC **IP** happily even though
  the self-signed cert's CN is the default. Datastore at `/opt/velociraptor/datastore`.
- **Offline install.** The release binaries are fetched to the control node once and copied in by the role —
  no host-side internet, matching the lab's air-gapped-SOC posture (the same pattern as `isos/`).
- **Firewall.** The only new hole is `CORP → SOC tcp/8000` (client comms), added to
  `roles/router/files/nftables.conf` next to the existing Wazuh agent ports — an agent→manager channel the
  SOC already accepts in kind.

---

## 3. Deployed as code (Ansible role)

`roles/velociraptor` + `velociraptor.yml` — two plays in one run (server first, so the client play can pick
up the client config the server play derived and fetched to the controller):

- **server.yml** (siem-01): copy the binary, **generate the server config once** (non-interactive
  `config generate --merge` sets the SOC server URL + durable datastore; guarded so a re-run never
  regenerates and invalidates enrolled clients), create the GUI admin, derive the client config, install a
  systemd unit, start it, and fetch the client config to the controller.
- **client.yml** (dc-01, fs-01): copy the binary + client config, install a systemd unit, start it.
- **Idempotent:** a second `ansible-playbook velociraptor.yml` reports **`changed=0`** on all three hosts
  (the generate-once tasks skip cleanly).

The **Windows client (`ws-01`) is installed by a short documented script**, not Ansible — this repo manages
Windows manually for now (the inventory notes WinRM automation as a later increment), so forcing it here
would be dishonest about the lab's actual automation surface:

```powershell
# on ws-01 (amd64 binary + the role-derived client config, staged from the controller)
C:\Velociraptor\velociraptor.exe --config C:\Velociraptor\client.config.yaml service install
```

---

## 4. Verify by exercising: one VQL hunt, the whole fleet

Detection-as-code has a DFIR twin: **hunt-as-code**. The hunt logic is a custom Velociraptor artifact,
[`artifacts/Custom.Hunt.ImplantIOC.yaml`](artifacts/Custom.Hunt.ImplantIOC.yaml), with one source per OS
(each client runs only the source whose `precondition` matches its platform, so a single hunt covers a mixed
fleet):

- **Linux** — ELF executables staged in world-writable dirs (`/tmp`, `/dev/shm`, `/var/tmp`), hashed. This
  is the exact IOC the [Add-1 Sliver exercise](../../phase-5-offense/sliver-c2/README.md) produced (the
  beacon ran from `/tmp`); Wazuh rule 100200 catches it at *execution*, Velociraptor sweeps the fleet's
  *disks* for the dropped file whether or not it's running.
- **Windows** — autostart entries under the Run/RunOnce keys (T1547.001), across HKLM and every user hive.

**Planted** (real needles, reusing Add-1's implant): the Sliver beacon at `/tmp/corpbeacon` on `fs-01` and
`dc-01`, and a Run-key `CorpUpdater → C:\Users\Public\corpbeacon.exe` on `ws-01`. **One hunt, run from the
server API, found all three:**

```
### Linux — world-writable ELF (Custom.Hunt.ImplantIOC/LinuxWorldWritableELF)
 Fqdn    Path              SHA256
 dc-01   /tmp/corpbeacon   13a5a6bd3ec372b28850d2c21b1d2a4b537df8f51edf897f36b8ee81e2615437
 fs-01   /tmp/corpbeacon   13a5a6bd3ec372b28850d2c21b1d2a4b537df8f51edf897f36b8ee81e2615437

### Windows — Run keys (Custom.Hunt.ImplantIOC/WindowsRunKeys)   [ws-01]
 Name                  Command
 CorpUpdater           C:\Users\Public\corpbeacon.exe          <-- planted persistence (the needle)
 OneDrive              "...\OneDrive.exe" /background
 SecurityHealth        %windir%\system32\SecurityHealthSystray.exe
 VMware User Process   "...\vmtoolsd.exe" -n vmusr
```

The triage is the point: the Linux hunt returns the **same SHA-256 on two hosts** — one query establishes the
blast radius of an IOC across the fleet, the thing a SIEM alert on a single agent can't tell you. On Windows
the hunt lists every autostart entry and the analyst picks the odd one out — `CorpUpdater`, an unsigned binary
in world-writable `C:\Users\Public`, named to blend in, next to signed OS/vendor entries. That the Windows
result came back at all is the proof the emulated amd64 client does real registry DFIR.

---

## 5. Where this sits next to the SIEM

Velociraptor and Wazuh answer different questions, and the lab now has both:

| | Wazuh (SIEM/EDR) | Velociraptor (DFIR) |
|---|---|---|
| Model | continuous, always streaming events → rules | on-demand, ask a question when you need to |
| Unit | an alert, when a rule matches live telemetry | a VQL query / hunt, run across the fleet now |
| Strength | real-time detection + active response | deep live-response, fleet-wide, arbitrary questions |
| Add-1 tie-in | rule 100200 catches the beacon *executing* | hunt finds the dropped beacon *on disk, fleet-wide* |

**On coverage:** a VQL hunt is not an ATT&CK detection rule, so this add deliberately does **not** touch the
Navigator coverage map — it would overstate the ruleset. The capability it adds is orthogonal: live,
interactive, cross-fleet DFIR that starts *after* a detection or hypothesis points at a host. (The Windows
hunt does happen to enumerate T1547.001 autostarts, already covered as a real-time rule by 100070.)

**Possible next step (noted, not built):** wire a Velociraptor client-side monitoring artifact to raise into
Wazuh, so a high-signal endpoint event (e.g. a new world-writable ELF) becomes a SIEM alert too — closing
the DFIR→SIEM loop the way the MISP and IRIS integrations closed theirs.

---

## Reproduce

```bash
# 0. one-time: fetch the binaries to the controller (offline pattern; gitignored)
gh release download v0.77.2 -R Velocidex/velociraptor \
  -p 'velociraptor-v0.77.2-linux-arm64' -p 'velociraptor-v0.77.2-windows-amd64.exe' \
  -D phase-4-detection/velociraptor/binaries/

# 1. server + Linux clients (from the ansible dir); router role opens CORP->SOC:8000
ansible-playbook velociraptor.yml
ansible-playbook router.yml -l rtr-01

# 2. Windows client (manual, per this lab's Windows posture) — stage binary + the
#    role-derived /etc/velociraptor/client.config.yaml to C:\Velociraptor\ then:
#    velociraptor.exe --config C:\Velociraptor\client.config.yaml service install

# 3. list the fleet + run the hunt, via the server API
V="sudo /usr/local/bin/velociraptor --api_config /etc/velociraptor/api.config.yaml"
ssh siem-01 "$V query \"SELECT os_info.hostname, os_info.system, os_info.machine FROM clients()\""
ssh siem-01 "$V query \"SELECT artifact_set(definition=read_file(filename='/tmp/Custom.Hunt.ImplantIOC.yaml')) FROM scope()\""
ssh siem-01 "$V query \"SELECT hunt(description='implant sweep', artifacts='Custom.Hunt.ImplantIOC') FROM scope()\""
ssh siem-01 "$V query \"SELECT * FROM hunt_results(hunt_id='H.xxxx', artifact='Custom.Hunt.ImplantIOC/LinuxWorldWritableELF')\""
```

Role: [`../../phase-7-automation/ansible/roles/velociraptor/`](../../phase-7-automation/ansible/roles/velociraptor/)
· play [`velociraptor.yml`](../../phase-7-automation/ansible/velociraptor.yml) · hunt artifact
[`artifacts/Custom.Hunt.ImplantIOC.yaml`](artifacts/Custom.Hunt.ImplantIOC.yaml).
