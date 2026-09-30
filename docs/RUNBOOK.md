# Homelab Runbook

How to actually *use* this lab — start it, run a simulation, hunt the results, add
new hosts, and reset. The lab is a platform, not a one-off build; this is the
operator's guide to driving it.

> Prereqs on the control node (macOS): VMware Fusion, Ansible (`pipx install
> --include-deps ansible`), the homelab SSH key at `~/.ssh/id_ed25519_homelab`,
> and the SSH aliases in `~/.ssh/config`. `scripts/.lab-secrets` (git-ignored) holds
> every credential these scripts need as plain `VAR=value` lines — see the table in
> §4 for what goes in it.

## 1. Start / stop the lab (the `make` control surface)

Everything runs through `scripts/lab.sh`, wrapped by a `Makefile`:

```bash
make status                 # power state of every VM
make up PROFILE=soc         # start a run profile's VMs
make converge                     # ansible-playbook site.yml (bring config to desired state)
make converge PLAY=misp.yml       # or iris.yml / velociraptor.yml / osquery.yml / patch.yml — site.yml does NOT include these
make down                   # suspend everything running
make stop                   # clean poweroff of everything
make snapshot NAME=clean    # snapshot every running VM
make restore NAME=clean     # revert to a snapshot
make profiles               # list profiles
make dashboards              # open SSH tunnels to every lab web UI, one command
make attack MODE=capstone    # run a simulation with creds from scripts/.lab-secrets (MODE=ad-validate too)
```

### Reaching each tool's web UI

Five UIs live behind SSH tunnels (the segmented network routes through rtr-01 as a
jump host, same as SSH); one is local. `make dashboards` opens all the tunnels at
once instead of hand-typing an `ssh -L` per tool per session:

| Tool | URL once tunneled | Needs |
|---|---|---|
| Wazuh dashboard | `https://localhost:9001` | siem-01 up |
| Velociraptor GUI | `https://localhost:8889` | siem-01 up |
| MISP | `https://localhost:9002` | misp-01 up |
| DFIR-IRIS | `https://localhost:8443` | misp-01 up |
| Greenbone/OpenVAS | `https://localhost:9392` | scan-01 up |
| BloodHound CE | `http://localhost:8080` | local `docker compose up -d` in `phase-5-offense/bloodhound-ce/` — **no tunnel needed** |

Credentials for all of these: the vault's Virtual Machines note. `Ctrl+C` closes
every tunnel `make dashboards` opened.

### Run profiles — never run everything (24 GB host ceiling)

| Profile | VMs | Use it for |
|---|---|---|
| `networking` | rtr-01 | firewall/segmentation work |
| `ad` | rtr-01 dc-01 ws-01 | Active Directory / GPO |
| `soc` | rtr-01 dc-01 ws-01 siem-01 | detection engineering (the daily driver) |
| `soc-ops` | rtr-01 dc-01 siem-01 misp-01 | case management / threat intel (MISP+IRIS) — swaps ws-01 for misp-01, same 24 GB. **`make converge` alone won't configure misp-01** — run `make converge PLAY=misp.yml` then `PLAY=iris.yml` too |
| `attack` | + fs-01 atk-01 | attack/detect pairing (suspend dmz first) |
| `vulnscan` | rtr-01 dc-01 scan-01 | authenticated vuln scanning |
| `services` | rtr-01 dc-01 siem-01 fs-01 dmz-01 | file/web services + monitoring |

`site.yml` (what plain `make converge` runs) covers rtr-01/dc-01/siem-01/dmz-01/fs-01/scan-01/ws-01 only —
**misp-01 (MISP + IRIS), Velociraptor, osquery, and the patch cycle are standalone plays**, run explicitly with
`PLAY=misp.yml`, `PLAY=iris.yml`, `PLAY=velociraptor.yml`, `PLAY=osquery.yml`, or `PLAY=patch.yml` (see
"Patching" below — always preview it first) the first time each is needed.

## 2. Run a simulation (the detection loop)

The lab exists to run this loop, over and over, on new techniques:

```bash
make up PROFILE=attack       # SOC + attacker box
make converge                # ensure everything is in its known-good state
```

1. **Attack** — from atk-01 (`ssh atk-01`): recon, BloodHound collection, execute a
   path (Kerberoasting, the fs-01 credential share, DCSync, etc. — see
   `phase-5-offense/README.md` for which of the 3 offense scripts to reach for). The
   two that need ws-01's admin credential (`ad-validate.py`, the `run-scenario.sh`
   capstone) don't need it typed by hand: `make attack MODE=ad-validate` or
   `MODE=capstone` (`ARGS=--verify` etc.) pulls `ADMIN_USER`/`ADMIN_PW` from
   `scripts/.lab-secrets` and, for the capstone, syncs the latest script to atk-01
   first — see `scripts/run-attack.sh`.
2. **Hunt** — in Wazuh (`make dashboards` → `https://localhost:9001`, or `ssh siem-01`):
   find the telemetry, confirm the detection fired, or write a new rule (`phase-4-detection/`).
3. **Evade** — try to slip past your own rule; document what worked.
4. **Snapshot** before a destructive test, `make restore NAME=clean` after.

**On the target side (ws-01)**: Sysmon + PowerShell Script Block Logging + the
Wazuh agent are already feeding the SIEM. **Atomic Red Team is installed**
(`Invoke-AtomicRedTeam` 2.1.0 + `powershell-yaml`, full atomics at
`C:\AtomicRedTeam\atomics`, `C:\AtomicRedTeam` Defender exclusion set). Fire a test
and hunt it: `ssh ws-01 'powershell -c "Invoke-AtomicTest T1059.001 -TestNumbers 1"'`.
It was installed **offline by design** — the lab is internal/self-contained, so CORP
resolves only internal names (no external DNS forwarder on dc-01) and tools are
staged from the admin host rather than pulled from the internet. The stock
`Install-AtomicRedTeam` one-liner is intentionally not used (it needs ws-01 to reach
GitHub). Reproducer in `phase-5-offense/atomic-red-team/`; rationale in
`docs/design-decisions.md`.

**Realistic victim identities**: `asmith` (designated victim) and `bwilson` are
ordinary domain users (plus `jdoe`); run simulations as one of these, not
`localadmin`. All are (re)created idempotently by the `dc` role.

### Run one technique at a time (and watch it)

The full battery takes ~15 minutes. To see a single technique work, list them and run one:

```bash
make up PROFILE=attack                    # rtr-01, dc-01, ws-01, siem-01, fs-01, atk-01
make dashboards                           # in a second terminal: Wazuh at https://localhost:9001

phase-5-offense/purple-team/ad-validate.py --list              # every scenario, technique ID, rule ID(s)
make attack MODE=ad-validate ARGS='--only Kerberoast'          # run just that one (repeat --only to add more)
```

Each scenario prints `PASS`/`FAIL`, the rule ID(s) it expects and how many alerts appeared.
To watch the alert arrive, filter the Wazuh dashboard on `rule.id` (or `ssh siem-01 'sudo tail -f
/var/ossec/logs/alerts/alerts.json'`). Give it ~25–35 s: agent → manager → correlation has real latency.
Scenarios that need a host that is off (dmz-01) report `SKIP`, not `FAIL`.

Gotchas that cost real time (each one looked like a broken detection):
- **`ignore=` on a Wazuh rule is a per-rule timer, not per account/IP.** Once a frequency rule fired for one
  target it was silent for every other target for that long. It is removed from every rule here; if you add a
  frequency rule, don't set `ignore` (see `phase-4-detection/detection-catalog.md`, T1110.001).
- **Domain passwords used to expire after 42 days**, taking Kerberoast/DCSync/the weak share down together (4
  scenarios failed at once). The `dc` role now sets the domain max password age to 0; if those accounts ever
  reject a login again, check `samba-tool domain passwordsettings show` first.
- **Stale Ansible SSH connections.** `ansible.cfg` reuses connections (`ControlPersist`). After rebuilding or
  deleting a VM that had the same IP/user, the next playbook can hang on its first task for the full timeout.
  Fix: `pkill -f 'ssh.*ansible/cp'; rm -f ~/.ansible/cp/*`.
- **Only one rule fires per event.** Two rules matching the same event don't both alert; the first sibling
  wins (that's why the 7-Zip image-name rule 100518 stays quiet when the `OriginalFileName` rule 100517 fires).
- **misp-01 is off in most profiles, and that used to flood the dashboard.** The manager looks up every
  alert's IPs/hashes in MISP; each failed lookup raised its own alert (`100302`), whose text contains
  MISP's IP, which triggered another lookup: a loop of ~200 alerts per 20 minutes that buried real
  detections. Errors are now silent, and you get one level-7 alert, `100303` ("MISP integration failing"),
  at most every 10 minutes. It means enrichment is offline, not that something is under attack. Start
  misp-01 (`make up PROFILE=soc-ops`, mind the RAM ceiling) if you want it gone.
- **Silencing a Wazuh rule: use a level below 3, not `noalert="1"` or level 0.** `noalert` makes Wazuh keep
  scanning and settle on a generic catch-all rule, and level 0 isn't retained for frequency correlation;
  a correlation rule downstream then never sees the match. Level 1–2 is quiet *and* countable (see the
  comment on rule 100302).

### Vulnerability scanning (scan-01 / Greenbone CE)

A different loop from attack/detect — active vulnerability assessment of the CORP
hosts, cross-referenced against Wazuh's own passive vuln module:

```bash
make up PROFILE=vulnscan                       # rtr-01 dc-01 scan-01
ssh scan-01 'sudo /opt/greenbone/greenbone-scan.sh'         # create target+task, launch
ssh scan-01 'sudo /opt/greenbone/greenbone-scan.sh status'  # watch progress
```

- The launcher (GMP via the stack's `gvm-tools`) creates a **Target** for dc-01 +
  ws-01 (`10.10.10.10,10.10.10.50`) and a **"Full and fast" Task**, idempotently,
  then starts it. Reachable because rtr-01 allows **REDTEAM → CORP**. `vulnscan`
  itself only boots dc-01 — ws-01 stays suspended unless you bring it up too
  (e.g. via `soc`/`ad`), in which case it just scans dead and reports 0 results
  for that host, same as any other target that's actually off.
- The **GSA web UI** (Scans › Tasks, reports, CVE detail) is on scan-01 at
  `127.0.0.1:443` (nginx's real TLS port — its own `:9392` is just a plain-HTTP
  redirect-to-`:443` compat port, not a second TLS listener) — `make dashboards`
  (§1) tunnels it to `https://localhost:9392` (admin / see the vault's Virtual
  Machines note).
- **First run only:** the NVT/SCAP/CERT/GVMD_DATA feeds must finish syncing
  (~20-40 min after the stack first comes up) before scan configs exist. `<get_feeds/>`
  with no `<currently_syncing>` means ready; the launcher says so if they aren't.
- **Cross-reference (separate, sequential step — not simultaneous):** `vulnscan`
  (rtr-01+dc-01+scan-01 = 18 GB) deliberately leaves siem-01 out to stay well
  under the 24 GB ceiling; it isn't needed to *run* the scan. To compare
  Greenbone's active findings against Wazuh's passive package-CVE detections for
  the same hosts, suspend scan-01 once the scan's done and bring up `soc` (or
  `soc-ops`) instead — the GSA report already has everything Greenbone found, so
  nothing is lost by not running both stacks at once.

### Patching (closing the vulnerability-management loop)

Scanning finds problems; this fixes them — `scan → patch → rescan`. Manual and on-demand by design
(`phase-7-automation/ansible/patch.yml`), never on a timer: parts of this stack are version-sensitive and
drift has broken it before, so what gets patched is a deliberate act.

```bash
make up PROFILE=...                                            # the hosts you're about to patch
( cd phase-7-automation/ansible && ansible-playbook patch.yml --check --diff )   # PREVIEW — read it
make converge PLAY=patch.yml                                   # apply
make converge                                                  # re-converge: must stay changed=0
make stop && make up PROFILE=...                               # real reboot if the play said REBOOT REQUIRED
```

What it does: holds every installed Wazuh-family, `filebeat` and Zeek package where it is, then
`apt dist-upgrade`s everything else, `autoremove`s superseded kernels, clears the apt cache, and **reports**
(never performs) `reboot-required`. Live-verified 2026-09-30 on rtr-01 (Debian 13) and dc-01/siem-01/dmz-01
(Ubuntu 26.04): ~60–78 packages per host, zero failures, re-converge `changed=0` on all four, every held
package unchanged, disk net-neutral (rtr-01 +0.3G, others unchanged at 0.1G resolution).

Things this play exists because of — each found by **simulating the upgrade first** (`apt-get -s upgrade`),
not by reading docs:

- **A blanket upgrade would have broken the SIEM.** siem-01's `wazuh-manager`/`indexer`/`dashboard` are held by
  *no* role (only the agent is, and only on dmz-01/fs-01) — `apt upgrade` would have moved all three
  4.14.7 → 4.14.8, past every pinned agent, skipping Wazuh's own upgrade procedure. dc-01's agent (installed
  out-of-band; `roles/dc` only configures it) would have jumped past its manager too. The hold list is built
  from what's actually installed, so it also caught a `wazuh-agent` on rtr-01 nobody expected.
- **`make down` never loads a new kernel.** Suspend/resume keeps whatever kernel the VM booted with. dmz-01 had
  7.0.0-34 installed but was still *running* 7.0.0-31. Only a real power cycle (`make stop`) picks it up — after
  which nginx, Docker, the agent and Juice Shop-via-nginx were all confirmed healthy from a genuine boot.
- **Not held on purpose** (they need patching too, but restart something live — read the `--check` output):
  `samba*`/`krb5*` on dc-01, `docker.io`/`containerd` on the app hosts (the MISP/IRIS/Greenbone stacks are slow to
  come back), `dnsmasq` on rtr-01 (briefly interrupts DHCP/DNS for every segment).
- **Scope:** Linux fleet only. ws-01 (Windows) needs Windows Update / `ansible.windows`, not built.

**Known hole this surfaced — rtr-01 is not rebuildable from blank as verified.** `roles/router` installs Zeek
*unpinned*, and the upstream repo now offers **only 9.0.0** (8.2.1 exists solely in rtr-01's local dpkg state —
confirmed via `apt-cache policy zeek`). The live sensor runs 8.2.1, held; a from-blank rebuild today would
install 9.0.0, untested against `zeek-node.cfg`/`zeek-networks.cfg` or the phase-6 DNS-hunting scripts (written
against 8.x log formats). Pinning the role to 8.2.1 would instead make the rebuild *fail*. The fix is a decision,
not an edit: validate the lab on Zeek 9, or archive the 8.2.1 packages while they still exist on rtr-01.

## 3. Add a new host (the scalability story)

The lab scales by the same pattern every existing host follows — this is why it's
built on Ansible roles, not hand config:

1. **Build the VM** — hand-built `.vmx` on the right vmnet (segment), or the
   headless autoinstall pattern in `phase-7-automation/provisioning/dmz-01/` for a
   from-blank Ubuntu box. Give it a static IP from `docs/00-ip-plan.md`.
2. **Register it** for control: add its `.vmx` path to `scripts/lab.sh` (`vmx_path`
   handles the default `<name>.vmwarevm/<name>.vmx` layout automatically) and add it
   to a run profile.
3. **Make it reachable**: add an SSH alias in `~/.ssh/config` (`ProxyJump rtr-01`
   for internal segments) and bootstrap passwordless sudo:
   `phase-7-automation/ansible/scripts/bootstrap-sudo.sh <host>`.
4. **Put it under config management**: add it to `inventory/hosts.yml` (under the
   segment group so it inherits the ProxyCommand jump + become), write a role under
   `roles/<role>/`, add a `<host>.yml` play, and wire it into `site.yml`.
5. **Converge + verify**: `make converge`, then re-run for `changed=0`.

New segments scale the same way: create the vmnet (DHCP off), add an nftables
stanza to the `router` role, converge rtr-01.

### Testing a firewall change safely (and recovering if you lock yourself out)

rtr-01 is both the firewall *and* the only SSH jump host into every internal segment
(`docs/00-ip-plan.md`) — a bad nftables change can lock you out of the whole network in
one `nft -f`, with the router role's own reload handler (deliberately not the Ansible
converge path). Two layers, for the two moments this actually happens:

**Before committing a change — test it live with an auto-revert safety net:**
```bash
ssh rtr-01-root                                          # sudo isn't installed on rtr-01
nft list ruleset > /tmp/candidate.conf                   # start from the live ruleset
vim /tmp/candidate.conf                                  # make your change — keep the `flush ruleset` line
nft-safe-apply.sh /tmp/candidate.conf 5                  # apply, auto-reverts in 5 min unless confirmed
# ... from a NEW session, confirm you can still reach everything you expect to ...
nft-safe-apply.sh confirm                                # only if it's actually safe
```
Same commit-confirm pattern production network gear (`Junos`/`IOS-XR`'s `commit confirmed`)
builds in natively. If you don't confirm — including if the change broke your access and you
*can't* — it auto-reverts to the exact pre-apply ruleset on its own; no action needed. Only
once a change is proven safe does it get copied into
`phase-7-automation/ansible/roles/router/files/nftables.conf` and converged for real. Live-fire
tested (2026-09-30): apply → wait → unconfirmed auto-revert (byte-identical ruleset restored,
confirmed via diff) and apply → confirm → change persists past the same timeout, both clean.

**If you're already locked out anyway:** the safe-apply tool only helps if you used it *before*
the bad change. If SSH to rtr-01 is just gone — VMware Fusion's console window reaches the VM
directly, independent of any network path through it (the same role an iLO/iDRAC plays on real
hardware): open Fusion, select `rtr-01`, use the console to log in locally and run
`nft -f /etc/nftables.conf` (the known-good, committed ruleset) to recover.

## 4. Where things live

| Need | Location |
|---|---|
| IP plan / segments | `docs/00-ip-plan.md` |
| Firewall / DHCP / DNS / NSM config | `phase-7-automation/ansible/roles/router/` |
| Firewall change testing / OOB recovery | §3 above ("Testing a firewall change safely") — `nft-safe-apply.sh` on rtr-01 |
| AD config + deliberate weaknesses | `roles/dc/` + `phase-2-identity/known-weaknesses.md` |
| Detection rules/decoders | `roles/siem/` + `phase-4-detection/` |
| Attack writeups + BloodHound | `phase-5-offense/` |
| NSM / PCAP analysis | `phase-6-nsm/` |
| Archive/alert log retention (siem-01, cron 03:30 daily) | `roles/siem/files/wazuh-log-retention.sh` (90-day default, `wazuh_log_retention_days`) |
| App-level backup/restore (Wazuh/MISP/IRIS, daily cron) | [`docs/backup-restore.md`](backup-restore.md) |
| **Off-host copy of those backups** (they otherwise share a disk with the data they protect) | `make backup-pull` (`scripts/pull-backups.sh`) → `~/Homelab-backups/` on this Mac. On-demand, not scheduled — run it yourself, or add it to your own crontab. Bounded: mirrors Wazuh's snapshot repo + IRIS in full (both small; OpenSearch snapshots are incremental), but only MISP's *latest* DB+state dump, not the full 30-day retention window (each dump is ~650M and non-incremental — mirroring all of them would eventually add tens of GB) |
| Does a manager restart/outage lose telemetry? | [`docs/pipeline-resilience.md`](pipeline-resilience.md) — live-tested: no, the agent-side queue survives it |
| "Who watches the watchmen" — siem-01 external availability check (rtr-01, cron every 5 min) | `roles/router/files/monitor-siem-availability.sh` → `/var/log/siem-monitor.log` on rtr-01 (state-transition only, no spam) |
| siem-01's own cron-job failure alerting (retention + snapshot-backup) | `/var/log/cron-failures.log` on siem-01, fed into Wazuh's own pipeline — rule 100563, reaches IRIS |
| Velociraptor DFIR→SIEM escalation (daily cron, siem-01) | `phase-4-detection/velociraptor/velociraptor-hunt-escalate.py` — rules 100564–100566, reaches IRIS |
| wtmpdb login/logout feed (cron every 5 min, dc-01/fs-01) | `phase-4-detection/osquery/wtmpdb-wazuh-feed.py` → `/var/log/wtmpdb-events.log` — rule 100567 (visibility, level 3) |
| **Credentials, per-VM config** | the second-brain `Virtual Machines` note (not in git) |

### Environment variables / secrets

Every credential a script needs goes in `scripts/.lab-secrets` (git-ignored, plain
`VAR=value` lines) — `lab.sh`, `run-attack.sh`, and `ad-validate.py` all read it
the same way. Actual values live in the vault's `Virtual Machines` note, never here.

| Variable | Used by | Purpose |
|---|---|---|
| `WS01_VMENC_PASS` | `lab.sh` (start/stop/suspend) | ws-01's VM-encryption passphrase — Fusion forces this on for a Windows 11 guest's vTPM |
| `ADMIN_USER` / `ADMIN_PW` | `run-attack.sh`, `ad-validate.py`, `run-scenario.sh` | ws-01's local-admin Windows credential — gates the WMI/WinRM/PsExec lateral-movement scenarios; skip cleanly (not fail) when unset |
| `SPRAY_PW` | `run-scenario.sh` | the weak password the capstone's password-spray phase guesses; defaults to a known lab value if unset |
| `DOMAIN_ADMIN_PW` | `run-attack.sh` → `ad-validate.py` | the domain `Administrator` password, for the scenarios that act as a stolen domain-admin credential (SYSVOL Remote Write). Not stored in `.lab-secrets`: `run-attack.sh` reads it from `dc-01`'s Ansible vault unless you export it; skips cleanly if neither is available |

## 5. End a session

```bash
make down     # suspend all (fast resume, preserves state)   — or —
make stop     # clean poweroff (cold boot next time)
```

Always suspend before unplugging the external SSD. Cap snapshots at 2 per VM.

## 6. CI — validate the repo before you push

GitHub Actions can't run VMware or the VMs, so [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
statically validates the committed artifacts instead — the same checks a
detection/infra team runs on the parts that don't execute in CI. Each job maps to
a command you can run locally:

```bash
# one-time: the linters CI uses (versions pinned in requirements-ci.txt —
# Dependabot watches that file, so this stays in sync with ci.yml automatically).
# sigma-cli and semgrep have conflicting transitive deps, so install per-tool
# from that file rather than as one blanket `-r requirements-ci.txt` — same
# pattern each ci.yml job uses:
for t in yamllint ansible-lint 'sigma-cli\|pyyaml\|defusedxml' ruff semgrep; do
  pip install $(grep -E "^($t)==" requirements-ci.txt)
done
ansible-galaxy collection install -r phase-7-automation/ansible/collections/requirements.yml

# the checks (each is one CI job)
yamllint .                                                      # YAML lint
( cd phase-7-automation/ansible && ansible-playbook --syntax-check site.yml )
ansible-lint phase-7-automation/ansible/                        # run from repo root
sigma check phase-4-detection/sigma/rules/                      # detection schema
ruff check .                                                    # Python lint
semgrep scan --config p/python --error --metrics=off            # Python SAST
shellcheck -S warning $(git ls-files '*.sh')                    # shell lint
gitleaks detect -c .gitleaks.toml --exit-code 1                 # secret scan
# Container image scan (Trivy) — informational, not gating; see ci.yml's
# `containers` job for the full command and why it's scoped to only the 3
# images phase-5-offense/bloodhound-ce/docker-compose.yml pins directly.

# Wazuh rule/decoder files are multi-root XML fragments — wrap before validating:
for x in $(git ls-files '*.xml'); do
  printf '<_r>%s</_r>' "$(cat "$x")" | xmllint --noout - || echo "BAD: $x"
done
```

Config lives at the repo root: `.yamllint`, `.ansible-lint`, `ruff.toml`,
`.gitleaks.toml`. `ansible-lint` runs at `profile: basic` and must be invoked
**from the repo root** so it picks up both `.ansible-lint` and `.yamllint`.

**Semgrep gotcha, found standing this up:** loading two overlapping registry
configs together (`--config p/security-audit --config p/python`, both of which
register some of the same underlying rules) makes `# nosemgrep: <rule-id>`
suppress only one of the two copies — a documented, suppressed finding comes
back as an unsuppressed duplicate. Use one sufficient config (`p/python`) rather
than stacking packs, or verify with `--json` that a suppression actually holds
before trusting it.

## 7. Docs site — the portfolio pages

[`mkdocs.yml`](../mkdocs.yml) builds a [MkDocs Material](https://squidfunk.github.io/mkdocs-material/) site
out of the same markdown the repo already has — `docs/` holds a few build-plan pages directly plus a
symlink per phase directory (`docs/phase-4-detection -> ../phase-4-detection`, etc.), so the site reads the
exact files the catalog/writeups/CI already validate, never a copy that can drift — the same principle
behind the ATT&CK coverage map being generated rather than hand-maintained
([`attack-coverage/README.md`](phase-4-detection/attack-coverage/README.md)). A separate workflow,
[`.github/workflows/docs.yml`](../.github/workflows/docs.yml), builds and publishes it to GitHub Pages on
every push to `main` — kept out of `ci.yml` deliberately, so a docs-only change isn't gated on the full
static-validation suite and vice versa.

```bash
# one-time: the site-building tools (versions pinned in requirements-docs.txt)
pip install -r requirements-docs.txt

mkdocs serve      # live preview at http://127.0.0.1:8000 while editing
mkdocs build      # writes site/ (gitignored) — what CI publishes
```

`mkdocs-callouts` translates this repo's GitHub/Obsidian-style `> [!check]`/`> [!warning]` blocks into
Material's admonition boxes — without it they'd render as plain, unstyled blockquotes. Four pre-existing
cross-links (the top-level `README.md`, `.github/workflows/ci.yml`, and two `../docs/design-decisions.md`
references whose relative-path math only resolves from the real repo layout, not the symlinked one
`docs_dir` presents) show as warnings on a `mkdocs build` — real 404s if clicked inside the site, left as-is
rather than rewritten, since the same links work correctly wherever GitHub renders these files directly.

**One manual, one-time step this can't do for you:** GitHub repo → Settings → Pages → Build and deployment →
Source → **GitHub Actions**. Until that's set, `docs.yml` still builds and uploads the site artifact on every
push, there's just nowhere for `deploy-pages` to publish it yet.
