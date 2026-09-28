# siem-01 — unattended provisioning (Ubuntu Server 26.04 ARM64)

siem-01 is the SOC segment's Wazuh all-in-one (manager + indexer + dashboard). It
was originally **built interactively**; these files bring it up to the same
build-from-blank standard as dmz-01/scan-01/misp-01.

> Authored 2026-09-28 from the proven dmz-01 template (same ISO, Fusion, ARM64).
> Only host-specific data differs. **Pending a from-blank build-verify**; the `siem`
> role that configures the running host was itself separately verified from a
> genuinely blank host (`f91597f`), which this OS-install step precedes.

## What's here
| File | Purpose |
|---|---|
| `user-data` | Ubuntu autoinstall (cloud-init NoCloud): hostname, user + SSH key, **static SOC IP `10.10.30.10/24`**, install-time DNS = rtr-01 (10.10.30.1), `poweroff` when done |
| `meta-data` | NoCloud instance metadata (instance-id / hostname) |
| `grub.cfg` | ISO grub with `autoinstall ds=nocloud` + serial console |

## Sizing note
Wazuh's all-in-one (OpenSearch indexer + manager + dashboard) is the heaviest Linux
box in the lab: **4 vCPU / 8 GB / 80 GB**. The 8 GB matters — the indexer's JVM heap
defaults to 50% of RAM, so cap it explicitly in the `siem` role rather than trusting
the default on a shared host (see the Wazuh notes in the role/docs).

## Build steps (host = macOS, VMware Fusion, ARM64)

```bash
ISO=isos/ubuntu-26.04-live-server-arm64.iso

# 1. Seed ISO — volume label MUST be CIDATA for cloud-init's NoCloud datasource
mkdir seed && cp user-data meta-data seed/
xorriso -as mkisofs -output isos/siem-01-seed.iso -volid CIDATA -joliet -rock seed

# 2. Remaster the Ubuntu ISO with the autoinstall grub.cfg (replay preserves EFI boot)
xorriso -indev "$ISO" -outdev isos/ubuntu-siem01-auto.iso \
        -boot_image any replay -map grub.cfg /boot/grub/grub.cfg

# 3. Create the VM (4 vCPU / 8 GB / 80 GB nvme, vmxnet3 on vmnet5 = SOC) with BOTH
#    ISOs attached (installer + CIDATA seed) and a file-backed serial console, then:
vmrun start siem-01.vmx nogui
# autoinstall runs unattended and powers the VM off when finished.

# 4. Detach both CDs (set the CD devices startConnected FALSE) and boot from disk.
```

## After first boot
`ansible-playbook siem.yml` installs Wazuh + all custom detection content. See
`../ansible/roles/siem/`.

Login: user `tohudgins`, key-based (homelab key) primary; console password fallback
`SiemLab2026!` (lab-only, isolated host — see SECURITY.md).

## Gotchas
Same ARM64/Fusion family as dmz-01 — see `../dmz-01/README.md`.
