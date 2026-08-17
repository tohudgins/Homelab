# Phase 7 — Automation (Infrastructure as Code)

Ansible playbooks that reproduce the lab's configuration from version control.
The goal the build plan sets is the "infrastructure as code" bullet: a repo that
provisions the lab, so a host can be rebuilt from a base OS install to its
working role without hand-editing config files from memory.

> **Status: in progress.** Control node + inventory + secrets model are in place.
> Two roles — **`router`** (rtr-01) and **`siem`** (siem-01) — are built,
> converged against the live lab, and proven idempotent (`changed=0` on
> re-run). `dc` (Samba AD DC) and `fileserver` (fs-01) are next.

## Scope — what "IaC" honestly means here

The lab has two kinds of state, and this project is deliberate about the line
between them:

- **Configuration** — nftables rules, dnsmasq/chrony configs, Zeek node config,
  Wazuh custom rules and decoders. This *is* the detection- and network-
  engineering work, it changes over time, and it belongs in version control.
  **Ansible owns all of it**, idempotently.
- **One-shot destructive installs** — `wazuh-install.sh` (generates its own
  passwords), `samba-tool domain provision`, the Zeek OBS package install. These
  run once against a blank host and are captured as guarded/prerequisite steps,
  not re-run on every converge. Where a role can make them safely idempotent
  (Zeek's apt repo + package, guarded `creates=` provisioning) it does; where it
  can't without risking a working host, the role manages the *config on top* and
  the install is documented.

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
| Windows | ws-01 | Sysmon + Wazuh agent via WinRM | ⬜ later increment (the one host without a role) |

> **dmz-01 is a from-scratch VM**, not just a role: it was installed fully
> headless via Ubuntu autoinstall (see `provisioning/dmz-01/`) and then configured
> by the `dmz` role — the build's only end-to-end "blank disk → running service"
> example.

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
  present and still leaks `svc-backup`. The full lab (`site.yml`) converges all
  five hosts — rtr-01, dc-01, siem-01, dmz-01, fs-01 — at `changed=0`.
- **dmz** — full new-host build, verified end-to-end after headless install:
  Juice Shop answers HTTP 200 (the role's own `uri` check) and is reachable
  CORP→DMZ; the Wazuh agent enrolled as **005 / Active** on the manager and
  logcollector is confirmed tailing the container json log; **DMZ→CORP is blocked**
  (verified from dmz-01 — no pivot into AD) while DMZ→WAN and DMZ→SOC:1514 work;
  clock **synchronized to rtr-01** (rtr-01's chrony lists it as a client). Re-run
  `changed=0`. Gotcha closed en route: minimal Ubuntu ships no NTP client, so the
  `timesyncd.conf` had no service to read it until the package was installed.

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
