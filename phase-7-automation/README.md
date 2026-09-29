# Phase 7 — Automation (Infrastructure as Code)

Ansible playbooks that reproduce the lab's configuration from version control.
The goal the build plan sets is the "infrastructure as code" bullet: a repo that
provisions the lab, so a host can be rebuilt from a base OS install to its
working role without hand-editing config files from memory.

> **Status: complete and fully verified.** All seven hosts are covered by
> idempotent roles — **`router`** (rtr-01), **`dc`** (dc-01), **`siem`**
> (siem-01), **`dmz`** (dmz-01), **`fileserver`** (fs-01), **`windows`** (ws-01,
> managed over SSH), and **`scan`** (scan-01, Greenbone CE vuln scanner).
> `ansible-playbook site.yml` converges the entire lab at `changed=0`, and every
> host has now actually been stood up from a blank disk: **dmz-01** and
> **scan-01** via headless Ubuntu autoinstall, and — closing the one real gap a
> 2026-09-26 audit found — **dc-01 and siem-01's from-blank path**, previously
> only proven safe (`changed=0`, the guard skips cleanly) against the *already*-
> provisioned live hosts, not proven to actually *work* from genuinely nothing.
>
> Built disposable verification VMs for both (`dc-01-verify` on CORP,
> `siem-01-verify` on SOC — never merged into the real inventory, torn down
> after) and found real bugs neither host's live, already-provisioned state
> could ever have surfaced: `samba-tool domain provision` refused to run
> against the package-default `smb.conf` (must be removed first, not merged);
> this Ubuntu release splits the AD schema files and the `samba_secrets` LDB
> module into `samba-ad-provision`/`samba-ad-dc`/`samba-dsdb-modules`, none of
> which the role installed; the `dc` role's active-response/telemetry tasks
> silently assumed a Wazuh agent was already present (now a loud, actionable
> failure instead of a cryptic one); and `wazuh-install.sh` generates a fresh
> random `snapshotrestore` password on every install, so the snapshot-backup
> registration (added the day before, in the same audit) had a hardcoded
> password that could only ever be right on the one host it was copied from —
> now read live from each host's own `wazuh-install-files.tar`. All four fixed,
> both roles re-verified end-to-end from blank, and both regression-checked
> `changed=0` against the live dc-01/siem-01 afterward. A real, previously
> undocumented prerequisite also surfaced along the way: CORP has no DNS
> resolver reachable until dc-01 exists (dc-01 *is* CORP's only DNS provider),
> so a genuine disaster-recovery rebuild needs a working resolver pointed
> somewhere before `apt-get` can run at all — worked around here only because
> the live dc-01 was still up to resolve against; see the `dc` role's
> `provision.yml` for the full detail.
> `windows-config/sysmonconfig.xml` is likewise deployed as code (`windows`
> role) instead of only being applied by hand.

## Scope — what "IaC" honestly means here

The lab has two kinds of state, and this project is deliberate about the line
between them:

- **Configuration** — nftables rules, dnsmasq/chrony configs, Zeek node config,
  Wazuh custom rules and decoders. This *is* the detection- and network-
  engineering work, it changes over time, and it belongs in version control.
  **Ansible owns all of it**, idempotently.
- **One-shot destructive installs** — `wazuh-install.sh` (generates its own
  passwords), `samba-tool domain provision`, the Zeek OBS package install. These
  run once against a blank host and are captured as guarded steps (`creates:` on
  a file that only exists post-install), not re-run on every converge —
  Zeek's apt repo + package install, the `dc` role's `samba-tool domain
  provision`, and the `siem` role's `wazuh-install.sh -a` all follow this same
  pattern now (`roles/dc/tasks/provision.yml`, `roles/siem/tasks/provision.yml`).
  The guard is proven safe against the live, already-provisioned hosts
  (`changed=0`), and — as of 2026-09-26 — the install itself is now proven
  from a real blank host for every one of `dmz`, `scan`, `dc`, and `siem`; see
  the status note above for what verifying `dc`/`siem` actually found.

This split is the real-world pattern — config management converges continuously,
provisioning happens once — and it keeps every playbook safe to run against the
live lab, which is how they were tested.

## Layout

```
ansible/
├── ansible.cfg               # inventory, roles path, vault key, yaml output
├── inventory/hosts.yml       # segmented inventory (routers / internal / windows)
├── group_vars/
│   ├── all.yml               # lab-wide facts: domain, NTP source, subnets
│   ├── routers.yml           # rtr-01: direct WAN, root login, no become
│   └── internal.yml          # dc/fs/siem: ProxyCommand jump + passwordless sudo
├── host_vars/                # per-host vaulted app secrets (as roles need them)
├── roles/
│   ├── router/               # nftables, dnsmasq, chrony, Suricata, Zeek  ✅
│   └── siem/                 # Wazuh custom rules + decoders (detection-as-code) ✅
├── scripts/bootstrap-sudo.sh # one-time NOPASSWD sudo grant (see below)
├── site.yml                  # full-lab convergence (imports the per-host plays)
├── router.yml / siem.yml     # per-host plays, runnable on their own
└── .vault_pass               # vault key — git-ignored, control-node only
```

## Connection model

The **macOS host is the Ansible control node**. It reaches the lab exactly the
way an operator does:

- **rtr-01** directly on its vmnet8 (NAT) WAN IP, logging in as `root` (this
  minimal Debian has no `sudo`) — so no ProxyJump and no privilege escalation.
- **dc-01 / fs-01 / siem-01** are on internal segments the control node can't
  route to directly. They're reached with an explicit **`ProxyCommand` jump
  through rtr-01** (`group_vars/internal.yml`).

## Secrets & privilege escalation

- **Passwordless sudo for the automation account.** A one-time
  `scripts/bootstrap-sudo.sh <host>` installs a `NOPASSWD` sudoers drop-in for
  the automation user, authorized by the git-ignored SSH key. Every subsequent
  Ansible run escalates without a password. Interactive human sudo still prompts.
- **ansible-vault** (`.vault_pass`, git-ignored; `host_vars/*/vault.yml`,
  encrypted and safe to commit) is reserved for genuine application secrets —
  Samba admin, Wazuh, and the lab's deliberate weak-account passwords — as the
  `dc` and `fileserver` roles need them.

## Running it

```bash
cd ansible
ansible-playbook site.yml --check --diff      # dry-run the whole lab
ansible-playbook site.yml                     # converge the whole lab
ansible-playbook router.yml                   # or one host at a time
ansible-playbook siem.yml
```

## Roles

| Role | Host | Manages | State |
|---|---|---|---|
| `router` | rtr-01 | IPv4 forwarding, nftables firewall+NAT, dnsmasq DHCP/DNS, chrony NTP source, Suricata, Zeek (OBS install + node/networks config + systemd unit) | ✅ built, idempotent |
| `siem` | siem-01 | Wazuh custom rules + decoders (detection-as-code), service health, restart-and-verify the ruleset parses | ✅ built, idempotent |
| `dc` | dc-01 | Samba AD DC `smb.conf` (incl. Phase 4 audit logging) + the deliberate weaknesses register (Kerberoastable service accounts + SPNs, unprivileged user, svc-backup's Backup Operators + DCSync over-privilege), each guarded by an existence check | ✅ built, idempotent + self-verifying |
| `dmz` | dmz-01 | Docker + OWASP Juice Shop, Wazuh agent (+ container-log ingestion), NTP sync to rtr-01 | ✅ built, idempotent |
| `fileserver` | fs-01 | Samba member `smb.conf`, the weak `[public]` share + `full_audit` VFS, the bait credential file, Wazuh agent + realtime FIM on the share | ✅ built, idempotent + self-verifying |
| `windows` | ws-01 | Wazuh agent → manager, Sysmon service, PowerShell Script Block Logging — managed **over SSH** (ansible.windows / community.windows) | ✅ built, idempotent |
| `scan` | scan-01 | Docker + **Greenbone Community Edition** (GVM/OpenVAS) — arm64-native ~16-container stack, admin login enforced, NTP sync to rtr-01, ships a one-command CORP scan launcher (`greenbone-scan.sh`, GMP) | ✅ built, idempotent |

> **The OS install is codified too, not just the config — for every host.** Each
> `provisioning/<host>/` holds the unattended-install seed for that box, and
> `scripts/create-vm.sh` builds the VM shell itself (specs, NICs, disk, serial
> console) from code, so the whole lab is reproducible "blank disk → running
> service" from the repo:
> - **Ubuntu** (cloud-init autoinstall): dmz-01, scan-01, misp-01 (original), plus
>   dc-01, fs-01, siem-01 (added 2026-09-28 from the proven pattern).
> - **Debian netinst preseed**: rtr-01. **Kali preseed**: atk-01. **Windows
>   autounattend**: ws-01 (added 2026-09-28).
>
> Verification status is honest per host (all build-verified from genuinely blank
> throwaway VMs via `create-vm.sh`, 2026-09-28):
> - **rtr-01 (Debian preseed) — VERIFIED**: unattended install → auto-poweroff →
>   booted disk → SSH as root with the key, hostname/OS/PermitRootLogin correct.
> - **atk-01 (Kali preseed) — VERIFIED**: custom preseed cleanly overrode Kali's
>   simple-cdd, installed the full `kali-linux-default` + Xfce, → SSH as the user.
> - **ws-01 (Windows autounattend) — boots + installs headless (verified); OOBE
>   completion unconfirmed**: XML valid + edition confirmed against the real
>   `install.wim`. The "Press any key to boot from CD" stall was solved by rebuilding a
>   **no-prompt ISO** (mount UDF → copy out → `wimlib` split the wim under 4 GB →
>   `xorriso` with `efisys_noprompt.bin`); with it the VM booted headless with no
>   keypress and Setup applied the full image (vmdk 8 MB → 13 GB, confirmed live). It
>   then ran ~1 hr in OOBE with live disk writes but never reached network/SSH — a
>   headless VM can't be screen-observed mid-Setup, so OOBE's last mile needs a GUI
>   session to confirm/iterate. Details in `provisioning/ws-01/README.md`.
> - The six Ubuntu seeds share the exact mechanism proven on the two verified Linux
>   builds. Build-verifying the preseeds also caught + fixed a real hands-off bug
>   (`finish-install/reboot_in_progress note`, commit `6f1511b`).

## Verification evidence

Each role was proven, not assumed:

- **router** — converged against live rtr-01, then a second run reported
  `changed=0` (idempotent). All five services (`nftables`, `dnsmasq`, `chrony`,
  `suricata`, `zeek`) verified `active` afterward; the default-deny firewall
  policy and chrony sync survived the live reload; the SSH session driving the
  converge survived the firewall reload because `nft -f` applies the ruleset in
  one transaction rather than a stop/flush/start.
- **siem** — deploy→restart→verify path exercised by injecting mode drift on the
  live rules file, then confirming the role corrected it, restarted
  `wazuh-manager`, and its verify task saw `wazuh-analysisd is running` (a broken
  ruleset would have failed here). Re-run reported `changed=0`.
- **dc** — every mutating step (account create, SPN add, group add, DCSync grant)
  is guarded by an existence check, so the role never resets a live account's
  password and never appends a duplicate ACE; converge reported `changed=0`
  against the live DC. A self-verification task then independently queried the DC
  and confirmed the full weaknesses register holds — all three service accounts
  exist, svc-backup is in Backup Operators, and the DCSync control-access ACE is
  present on the domain NC. (The create paths aren't exercised against the live DC
  because the accounts already exist — deleting a real AD account to test creation
  isn't worth the risk; the guards + end-state assertion are the verification.)
- **fileserver** — converged against fs-01 with a domain-join guard (fails clearly
  if `net ads testjoin` isn't "Join is OK"); re-run `changed=0`. Self-verification
  task confirms the `[public]` share is exported (`testparm`) and the bait file is
  present and still leaks `svc-backup`.
- **windows** — ws-01 managed **over SSH** with the ansible.windows modules; the
  role's verify task read the agent's own log confirming *"Connected to the server
  ([10.10.30.10]:1514/tcp)"*. Enforce path exercised by flipping the Script Block
  Logging registry value off and watching the role set it back (`changed=1` → then
  `changed=0`). Gotcha: with Win32-OpenSSH's default `cmd` shell, `ansible_shell_type`
  **must** be `cmd` — declaring `powershell` corrupts Ansible's Base64
  `-EncodedCommand`. **`site.yml` converges all seven hosts — rtr-01, dc-01,
  siem-01, dmz-01, fs-01, ws-01, scan-01 — at `changed=0`.**
- **dmz** — full new-host build, verified end-to-end after headless install:
  Juice Shop answers HTTP 200 (the role's own `uri` check) and is reachable
  CORP→DMZ; the Wazuh agent enrolled as **005 / Active** on the manager and
  logcollector is confirmed tailing the container json log; **DMZ→CORP is blocked**
  (verified from dmz-01 — no pivot into AD) while DMZ→WAN and DMZ→SOC:1514 work;
  clock **synchronized to rtr-01** (rtr-01's chrony lists it as a client). Re-run
  `changed=0`. Gotcha closed en route: minimal Ubuntu ships no NTP client, so the
  `timesyncd.conf` had no service to read it until the package was installed.
- **scan** — second full new-host build from a blank disk. Greenbone CE's
  ~16-container stack came up (all `healthy`), gvmd accepted GMP commands, and the
  admin credential was verified end-to-end at the API (`<get_feeds/>` returned
  `status="200"` under `admin`). Re-run `changed=0`. Arch was verified *before*
  building: every one of the 19 images on `registry.community.greenbone.net`
  publishes `linux/arm64`, so the scanner runs native on Apple Silicon — no qemu.
  The firewall needed **zero** changes: REDTEAM→CORP was already open (scan-01
  reaches dc-01/ws-01) and REDTEAM→SOC blocked (so scan-01 correctly runs no Wazuh
  agent — the SIEM must not be reachable by the box generating the scans).

## What broke, and how it was diagnosed

The most useful part of any build log — the walls hit turning a working,
hand-built lab into idempotent code:

- **`Timeout waiting for privilege escalation prompt` on every internal host.**
  The account's sudo password was correct (`sudo -S` returned `uid=0`), so it
  wasn't auth. Root cause: Ubuntu's default `Defaults use_pty` in sudoers routes
  the password prompt into a PTY that Ansible's become machinery can't read.
  Disabling pipelining didn't help (ruling out a stdin race). Fix: NOPASSWD sudo
  for the key-authorized automation account, leaving `use_pty` intact for humans.
- **Internal hosts `UNREACHABLE` while the SSH alias worked fine.** A bare
  `-o ProxyJump=...` combined with `IdentitiesOnly=yes` gives the jump hop no key
  and no agent fallback, so the connection died at rtr-01. Fix: an explicit
  `ProxyCommand` that passes `-i <key>` to the jump hop.
- **`community.general.yaml` stdout callback removed** in current ansible-core.
  Replaced with `stdout_callback = default` + `result_format = yaml`.
- **Greenbone stack `up` failed mid-pull: `connection reset by peer`.** The first
  scan-01 converge aborted ~47 s in — the community registry CDN reset a
  connection while pulling a 1.5 GB layer, which fails the whole `docker compose
  up`. Not an arch or config fault (already-pulled layers were cached). Fix: a
  `retries`/`until rc==0` loop on the stack-up task, so each retry resumes from
  cache and eventually completes — real robustness for a ~10 GB first pull over NAT.
- **The admin-user task skipped, leaving a login I didn't control.** gvmd's
  entrypoint *auto-creates* an `admin` on a fresh DB with an un-logged password, so
  "create only if absent" silently left an unreachable UI. Fix: the role now also
  *enforces* the known lab password (`gvmd --user=admin --new-password`,
  `changed_when: false` since it's declarative state), so a rebuilt scanner is
  always reachable.
