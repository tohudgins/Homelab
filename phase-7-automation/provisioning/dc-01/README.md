# dc-01 — unattended provisioning (Ubuntu Server 26.04 ARM64)

dc-01 is the CORP Active Directory domain controller (Samba AD DC). It was
originally **built interactively**; these files bring it up to the same
build-from-blank standard as dmz-01/scan-01/misp-01, so the base VM is
reproducible from the repo alone — the from-scratch counterpart to the `dc` role
that configures the running host.

> Authored 2026-09-28 from the proven dmz-01 template (same ISO, Fusion, ARM64).
> The autoinstall *mechanism* is identical to the three hosts already built this
> way; only the host-specific data (hostname, IP, specs, DNS) differs. **Pending a
> from-blank build-verify** — the `dc` role itself was separately verified from a
> genuinely blank host (`f91597f`); this automates the OS install that preceded it.

## What's here
| File | Purpose |
|---|---|
| `user-data` | Ubuntu autoinstall (cloud-init NoCloud): hostname, user + SSH key, **static CORP IP `10.10.10.10/24`**, external install-time DNS (see below), `poweroff` when done |
| `meta-data` | NoCloud instance metadata (instance-id / hostname) |
| `grub.cfg` | ISO grub with `autoinstall ds=nocloud` + serial console, so the installer runs unattended |

## The CORP-DNS chicken-and-egg (why install-time DNS is 1.1.1.1)
dc-01 *is* CORP's only DNS provider once built, and rtr-01 deliberately does not
serve DNS to CORP (only to DMZ/SOC/RED). So a genuinely blank dc-01 has **no
internal resolver** to fetch packages with. `user-data` points install-time DNS at
`1.1.1.1`, reachable because rtr-01 permits CORP→WAN. After the build, the `dc`
role makes dc-01 CORP's resolver with `1.1.1.1` as its upstream forwarder.

## Build steps (host = macOS, VMware Fusion, ARM64)

```bash
ISO=isos/ubuntu-26.04-live-server-arm64.iso

# 1. Seed ISO — volume label MUST be CIDATA for cloud-init's NoCloud datasource
mkdir seed && cp user-data meta-data seed/
xorriso -as mkisofs -output isos/dc-01-seed.iso -volid CIDATA -joliet -rock seed

# 2. Remaster the Ubuntu ISO with the autoinstall grub.cfg (replay preserves EFI boot)
xorriso -indev "$ISO" -outdev isos/ubuntu-dc01-auto.iso \
        -boot_image any replay -map grub.cfg /boot/grub/grub.cfg

# 3. Create the VM (2 vCPU / 4 GB / 40 GB nvme, vmxnet3 on vmnet3 = CORP) with BOTH
#    ISOs attached (installer + CIDATA seed) and a file-backed serial console, then:
vmrun start dc-01.vmx nogui
# autoinstall runs unattended and powers the VM off when finished.

# 4. Detach both CDs (set the CD devices startConnected FALSE) and boot from disk.
```

## After first boot
`ansible-playbook dc.yml` provisions Samba AD DC + the deliberate weaknesses. See
`../ansible/roles/dc/`. The autoinstall keeps the base image minimal on purpose.

Login: user `tohudgins`, key-based (homelab key) primary; console password fallback
`DcLab2026!` (lab-only, isolated host — see SECURITY.md).

## Gotchas
Same ARM64/Fusion family as dmz-01 — see `../dmz-01/README.md`: the `autoinstall`
kernel param is mandatory, the seed label must be `CIDATA`, use `shutdown: poweroff`,
and `match: {name: "en*"}` keeps the netplan independent of the exact NIC name.
