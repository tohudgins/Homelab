# scan-01 — unattended provisioning (Ubuntu Server 26.04 ARM64)

scan-01 is the REDTEAM segment's **active vulnerability scanner** (Greenbone
Community Edition / OpenVAS). Like dmz-01, the base VM is installed **fully
headless** via Ubuntu autoinstall, so it's reproducible from these files — the
from-scratch counterpart to the `scan` Ansible role that layers Greenbone on top.

## What's here
| File | Purpose |
|---|---|
| `user-data` | Ubuntu autoinstall config (cloud-init NoCloud): hostname, user + SSH key, **static REDTEAM IP `10.10.40.20/24`** via `10.10.40.1`, `poweroff` when done |
| `meta-data` | NoCloud instance metadata (instance-id / hostname) |
| `grub.cfg` | ISO grub with `autoinstall ds=nocloud` + serial console added, so the installer runs unattended instead of prompting |

## Sizing (bigger than dmz-01 — Greenbone is heavy)
1 vCPU / 2 GB is fine for a Juice Shop box; Greenbone's ~15-container stack
(gvmd + Postgres + redis + openvas-scanner + ospd + notus + gsa + feed loaders)
is memory-hungry. scan-01 is built with **4 vCPU / 6 GB / 40 GB disk**.

## Build steps (host = macOS, VMware Fusion, ARM64)

```bash
BASE=isos/ubuntu-26.04-live-server-arm64.iso

# 1. CIDATA seed ISO (volume label MUST be CIDATA for cloud-init NoCloud)
mkdir seed && cp user-data meta-data seed/
xorriso -as mkisofs -output isos/scan-01-seed.iso -volid CIDATA -joliet -rock seed

# 2. Remaster the Ubuntu ISO with the autoinstall grub.cfg (replay preserves EFI boot)
xorriso -indev "$BASE" -outdev isos/ubuntu-scan01-auto.iso \
        -boot_image any replay -map grub.cfg /boot/grub/grub.cfg

# 3. Create the VM (4 vCPU / 6 GB / 40 GB nvme, vmxnet3 on vmnet6 = REDTEAM) with
#    BOTH ISOs attached (installer + CIDATA seed) + a file-backed serial console:
vmrun start scan-01.vmx nogui
# autoinstall runs unattended and powers the VM off when finished.

# 4. Detach both CDs (sata0:1 / sata0:2 present=FALSE) and boot from disk.
```

## Why REDTEAM, and why no Wazuh agent
scan-01 sits on REDTEAM (`10.10.40.0/24`) alongside atk-01. rtr-01 already allows
**REDTEAM → CORP** (the attack surface — so scan-01 reaches dc-01 `10.10.10.10`
and ws-01 `10.10.10.50` for authenticated scans) and **blocks REDTEAM → SOC**.
That block is deliberate: the SIEM must not be reachable by the boxes generating
the traffic it watches — so scan-01 carries **no Wazuh agent** and is unmonitored.
Greenbone's active findings are instead cross-referenced by hand against Wazuh's
own passive vulnerability-detection module on the CORP agents.

## After first boot
Docker + the Greenbone Community Edition stack are layered on by
`../ansible/roles/scan/` — the autoinstall keeps the base image minimal.

Login: user `tohudgins`, key-based (homelab key) primary; password `ScanLab2026!`.
Greenbone GSA web UI: admin / `GreenboneAdmin2026!` (see the `scan` role + the
vault's Virtual Machines note).
