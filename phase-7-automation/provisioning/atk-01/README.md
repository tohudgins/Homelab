# atk-01 — unattended provisioning (Kali Linux arm64, preseed)

atk-01 is the REDTEAM attacker box (Kali + Xfce desktop, dual-homed REDTEAM+CORP).
Kali uses the Debian installer, so this is a **preseed** (not cloud-init). These
files reproduce the base OS + desktop; the offensive toolkit is layered on
afterwards per [`../../../phase-5-offense/TOOLS.md`](../../../phase-5-offense/TOOLS.md)
— atk-01 is deliberately **not** in the Ansible inventory (an attacker box is driven
by hand, not converged).

> Authored 2026-09-28 and **build-verified from a genuinely blank VM the same day**:
> the plain custom preseed cleanly overrode Kali's stock simple-cdd flow, ran fully
> unattended, pulled the entire `kali-linux-default` toolset + Xfce, auto-powered-off,
> then booted the disk → SSH in as `tohudgins` with the homelab key → confirmed
> hostname `atk-01`, Kali Rolling, `kali-linux-default` and `kali-desktop-xfce` both
> installed, sshd active. Closes the gap where a `kali-atk01-auto.iso` existed from the
> original build but its custom seed was never committed.

## What's here
| File | Purpose |
|---|---|
| `preseed.cfg` | Kali-installer answers: hostname, `tohudgins` sudo user (root login disabled, Kali default), guided partitioning, `kali-linux-default` + `kali-desktop-xfce` + openssh-server, `poweroff` when done, late_command drops the SSH key + enables ssh |
| `grub.cfg` | Installer grub: `net.ifnames=0 auto=true priority=critical preseed/file=/cdrom/atk-01-preseed.cfg` + serial console, using the ISO's real `/install.a64/` paths |

## Networking note (dual-homed)
The preseed configures **only eth0 = REDTEAM** (vmnet6, DHCP from rtr-01) for install
connectivity. The second NIC (eth1 = CORP, static `10.10.10.99`, `ipv4.never-default`)
is set up post-build per `TOOLS.md` — it exists only for same-L2 tools like Responder.
`net.ifnames=0` (in grub) keeps the NICs as eth0/eth1 as TOOLS.md assumes.

## Build steps (host = macOS, VMware Fusion, ARM64)

```bash
ISO=isos/kali-linux-2026.2-installer-arm64.iso

# 1. Remaster: inject atk-01-preseed.cfg at the ISO root + swap in the grub.cfg.
xorriso -indev "$ISO" -outdev isos/kali-atk01-auto.iso \
        -map preseed.cfg /atk-01-preseed.cfg \
        -boot_image any replay -map grub.cfg /boot/grub/grub.cfg

# 2. Create the VM (2 vCPU / 3 GB / 40 GB, REDTEAM + CORP NICs) and boot it:
./scripts/create-vm.sh --name atk-01 --os arm-debian12-64 --cpus 2 --mem 3072 \
    --disk 40 --net vmnet6,vmnet3 \
    --iso isos/kali-atk01-auto.iso --start
# preseed runs unattended and powers the VM off when finished (large — pulls the
# kali-linux-default metapackage; allow time).

# 3. Detach the CD and boot from disk.
```

## After first boot
Layer the toolkit per `../../../phase-5-offense/TOOLS.md` (BloodHound CE collector,
Frida/jadx via pipx, SecLists, Metasploit `msfdb init`, the CORP NIC, etc.).

Login: user `tohudgins`, key-based (homelab key) primary; console password fallback
`AtkLab2026!` (lab-only, isolated host — see SECURITY.md).
