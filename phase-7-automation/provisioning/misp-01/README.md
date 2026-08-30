# misp-01 — MISP threat-intelligence platform (Ubuntu 26.04 ARM64 + Docker)

misp-01 runs **[MISP](https://www.misp-project.org/)** — the industry-standard **Threat Intelligence
Platform (TIP)** — as the professional counterpart to the Wazuh CDB threat-intel lists
(`phase-4-detection/threat-intel-cdb-enrichment.md`). MISP becomes the **IOC source of truth**: it ingests
external feeds, correlates and stores indicators as structured events, and (next step) feeds Wazuh via the
`MISP → Wazuh` integration. Segment: **SOC/MGMT**, `10.10.30.20`.

## What's here (base VM — autoinstall, same pattern as dmz-01/scan-01)
| File | Purpose |
|---|---|
| `user-data` | Ubuntu autoinstall (cloud-init NoCloud): hostname, user + SSH key, **static SOC IP `10.10.30.20/24`**, `poweroff` when done |
| `meta-data` | NoCloud instance metadata |
| `grub.cfg` | ISO grub with `autoinstall ds=nocloud` + serial console |

Build the base VM exactly like dmz-01 (seed ISO `volid CIDATA`, remaster the Ubuntu ISO's grub, create the
VM with 4 vCPU / 8 GB / 60 GB on `vmnet5` (SOC), boot, detach CDs). The VM is 8 GB because MISP's stack
(misp-core + MariaDB + Redis + misp-modules) is heavy.

## MISP deployment (codified in `roles/misp`, run `ansible-playbook misp.yml`)
The role installs Docker and stands up the **official `MISP/misp-docker`** stack (arm64-native — verified
`linux/arm64` in the `misp-core` manifest before committing, the OpenVAS lesson):
1. `curl -fsSL https://get.docker.com | sh` + add the user to `docker`.
2. `git clone https://github.com/MISP/misp-docker /opt/misp-docker`.
3. Seed `.env` from `template.env`, set `BASE_URL=https://10.10.30.20`, admin email/password, `ADMIN_ORG`,
   `GPG_PASSPHRASE` (lab secrets in the vault Virtual Machines note; MISP regenerates its own
   `ENCRYPTION_KEY`/`SALT`/`UUID` on a fresh deploy).
4. `docker compose pull && docker compose up -d`, then wait for the web UI (`/users/login` → 200).

Reach the UI from the Mac: `ssh -L 8443:127.0.0.1:443 misp-01`, then `https://127.0.0.1:8443`
(admin@misp.lab.internal). MISP pulls feeds through the already-permitted **SOC→WAN** egress; DNS resolves
via rtr-01's dnsmasq.

## Feeds (one-time, via the API/CLI after first boot)
MISP ships ~100 default feed **definitions** (disabled). Enable + fetch the high-value ones:
```bash
C=misp-docker-misp-core-1; K=<admin authkey>   # cake user change_authkey admin@misp.lab.internal
docker exec $C /var/www/MISP/app/Console/cake Server loadDefaultFeeds
# feed ids: 1=CIRCL OSINT (misp), 12=Feodo C2 IPs (csv), 41=URLhaus malware URLs (csv)
for id in 1 12 41; do
  docker exec $C curl -sk -H "Authorization: $K" -X POST https://127.0.0.1/feeds/enable/$id
  docker exec $C curl -sk -H "Authorization: $K" -X POST https://127.0.0.1/feeds/fetchFromFeed/$id
done
```
Verified live (2026-08-29): within minutes MISP ingested **43+ events / 27,000+ IOCs** — the abuse.ch
**URLhaus** feed (15k+ malicious URLs), **Feodo Tracker** botnet C2 IPs, and the **CIRCL OSINT** feed's
curated events (Turla, Dridex, PlugX, Locky, …). Real external threat intel, pulled by a real platform.

## Gotchas
- **Autoinstall doesn't grant NOPASSWD sudo** — the first user lands in the `sudo` group (password sudo).
  Added `/etc/sudoers.d/tohudgins` post-install (matching atk-01). Fold into `user-data` late-commands for
  full reproducibility.
- **Modern MISP uses SimpleBackgroundJobs**, so `cake Admin restartWorkers` returns *"does nothing"* — that's
  expected, not an error; feed pulls are processed by the background job system automatically.
- **MISP requires a strong admin password** (special char) — `MispAdmin2026@Lab` (the `@` is shell-safe;
  avoid `!` which trips shell history-expansion).

## Next (scoped for the following session)
The **MISP → Wazuh integration**: Wazuh `integratord` calls a MISP-lookup script on each alert, querying the
MISP API for the alert's IOCs and raising a custom rule on a hit — the professional pattern that makes MISP,
not the static CDB list, the live IOC engine behind the SIEM.
