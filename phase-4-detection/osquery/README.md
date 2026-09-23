# osquery — continuous, scheduled fleet-state querying

**A different instrument from Velociraptor, not a duplicate of it.** [Velociraptor](../velociraptor/README.md)
answers "ask this question of the fleet right now" — an analyst-driven VQL hunt, run once, when there's
already a reason to look. [osquery](https://osquery.io/) answers a different question: "keep asking this
question, continuously, whether or not anything looks wrong yet" — a small set of SQL queries run on a
schedule, every host, all the time, logging only what *changed* since the last run. It's one of the most
common tools in real SOCs for exactly that reason: cheap, continuous, low-noise fleet visibility that's
already running before an incident starts, not stood up in response to one.

> [!check] Deployed and verified live on 2026-09-22.
> Real official arm64 packages from `pkg.osquery.io` on `dc-01`/`fs-01` (Ubuntu 26.04 ARM64) — confirmed the
> apt repo actually publishes an arm64 index before trusting it, the same "verify the architecture" discipline
> as every other tool in this lab. Six scheduled queries (`os_version`, `users`, `listening_ports`,
> `processes`, `crontab`, `logged_in_users`) produced real, varied differential results within minutes:
> `processes` showed genuine add/remove churn (kernel worker threads); `listening_ports`' own churn turned
> out to be mostly a red herring — see §4 below — and `crontab` picked up dc-01's real system cron jobs. Fed into Wazuh via
> its osquery wodle in log-tail mode (`run_daemon: no`) — osqueryd runs as its own systemd service, the same
> way a real fleet-management tool would consume it, not as a Wazuh-managed subprocess. **Confirmed reaching
> the manager**: 122 real `location: osquery` events in siem-01's archive from dc-01 alone, structured under
> `data.osquery.*`, decoded by Wazuh's stock `json` decoder and matched by its own **built-in** rule **24010**
> ("osquery: `<query name>` query result", level 3) — no custom decoder or rule needed for basic visibility,
> confirming osquery is first-class-supported by Wazuh out of the box, not a bolt-on integration.

> [!check] Differentials promoted to real alerts, closed 2026-09-22.
> Rule 24010 (Wazuh's stock osquery catch-all, level 3) fires identically for every query in the schedule —
> a genuinely new artifact looked exactly like routine snapshot noise. Three children of it now promote the
> security-relevant "added" rows to real alerts: **100550** (new listening port), **100551** (new cron
> entry), **100552** (new local account). See §4 below for what it took to make that signal trustworthy
> rather than just louder, and the real live verification against each rule.

---

## 1. Why a separate tool, not just "more Velociraptor"

Same fleet, two genuinely different jobs:

| | Velociraptor | osquery |
|---|---|---|
| Triggered by | an analyst, when there's already a reason to look | nothing — it just runs, all the time |
| Shape | one VQL query (or hunt), fleet-wide, once | a fixed schedule of queries, every host, forever |
| Output | the current answer to your question | a stream of what *changed* since last time (differential) |
| Best at | "does any host have this IOC" DFIR sweeps | "what does normal look like, and did it just change" |

A real SOC runs both: osquery's continuous schedule is what makes "rare process" or "new listening port"
hunts possible in the first place (see [`../threat-hunting/`](../threat-hunting/README.md)'s
`hunt-rare-process.py`, built against Sysmon telemetry the same way this could feed a Linux-side equivalent),
and Velociraptor is what you reach for once osquery's stream — or any other alert — gives you a reason to.

## 2. Deployment — real upstream packages, verified before trusting

`pkg.osquery.io/deb` redirects to `pkg.osquerypackages.com/deb`; confirmed live it publishes both `amd64` and
`arm64` `Packages` indexes before writing the Ansible role around it, not assumed from the project's own
marketing copy. Installed via the `osquery` role (`phase-7-automation/ansible/roles/osquery/`), applied to
`dc-01`/`fs-01` — Ubuntu/arm64 hosts — the same `hosts: domain_controllers:fileservers` group Velociraptor's
Linux clients use.

`osqueryd` runs as its own systemd service (the package's own default unit, `/etc/osquery/osquery.conf` +
`/etc/osquery/osquery.flags`) rather than as a process Wazuh spawns and manages — a deliberate choice: real
fleets run osquery as a long-lived agent that any number of consumers (a SIEM, a fleet-management platform
like Fleet/Kolide, a simple log shipper) can tail independently, not as a subprocess owned by one of them.
Wazuh's own `<wodle name="osquery">` supports both models; this lab uses `run_daemon: no` — the agent only
tails `osqueryd.results.log` and forwards each line as an event, never starting or stopping the daemon
itself.

## 3. The query pack

Six scheduled queries, chosen for real security-relevant signal without being invasive (no shell history, no
full file content):

| Query | Interval | Why |
|---|---|---|
| `os_version` | 1h | identity/inventory baseline |
| `users` (uid ≥ 1000, or root) | 1h | local account baseline — a new row is a new account |
| `listening_ports` | 5m | network exposure — a new row is a new listening service (`WHERE family != 1` — see §4) |
| `processes` | 5m | what's actually running — the noisiest query by design (kernel workers churn constantly; a real deployment would filter this down or accept the noise as the cost of visibility) |
| `crontab` | 5m | scheduled persistence — the same tactic the [Registry Run Keys](../../phase-5-offense/attack-detect-writeups/07-registry-run-keys-t1547.001.md) writeup covers on Windows |
| `logged_in_users` | 5m | who's actually on the box right now |

Schema verified query-by-query in `osqueryi` before writing the schedule (`listening_ports` in particular
has no `name` column despite what memory suggested — checked with `.schema`, not assumed).

## 4. Promoting differentials to real alerts

Stock rule 24010 treats every scheduled-query result identically — level 3, "here's today's snapshot." The
gap this closes: a genuinely new artifact (a fresh listener, a new cron job, a new local account) looked
exactly like routine background noise. Three children of 24010 in `local_rules.xml` promote the
security-relevant `action: "added"` rows:

| Rule | Fires on | Level | MITRE | Verified live (2026-09-22) |
|---|---|---|---|---|
| **100550** | new `listening_ports` row | 6 | T1543.002, T1059.004 | `python3 -m http.server` bound to `0.0.0.0:8899` on dc-01 → fired with the real pid/address/port/protocol interpolated |
| **100551** | new `crontab` row | 6 | T1053.003 | a real `crontab` addition on dc-01 → fired with the real command + schedule interpolated |
| **100552** | new `users` row | 10 | T1136.001, T1098 | a real `useradd` on dc-01 → fired with the real username/uid/shell interpolated |

`processes` and `logged_in_users` are deliberately **not** promoted to real-time alerts: `processes` churns
constantly by design (see the table above), and `logged_in_users` adds a row on every ordinary SSH login in a
lab where that happens all the time — a naive real-time rule on either would page constantly. Both stay
visibility-only under 24010, but "real baselining" turned out to mean a **hunt**, not a rule — see
[`../threat-hunting/README.md`](../threat-hunting/README.md)'s Hunt D (`hunt-rare-osquery.py`), which
stack-counts both by rarity the same way Hunt B already does for Windows Sysmon telemetry. Verified live: a
planted `python3 -m http.server` on dc-01 correctly ranked as a fresh singleton among 175 legitimate boot-time
processes. Checking `logged_in_users` the same way surfaced a genuinely different, deeper finding: the query
returns **zero rows on dc-01 regardless of active sessions**, because `/run/utmp` doesn't exist on this
host at all — `systemd-logind` tracks sessions fine (`loginctl list-sessions`), but osquery's table reads the
legacy utmp file specifically, which nothing here writes. That's a PAM/utmp wiring gap, not a baselining one,
and it's left open as real follow-up work rather than papered over.

**A real noise source found before any of this could work**: `listening_ports`' own "added" stream was 76%
garbage (194 of 256 events on dc-01) — every AF_UNIX socket (`family=1`) the table returns comes back with
`port=0`/`protocol=0`/`address=""`, flapping added/removed on its own schedule, unrelated to any real
network-exposure change. Confirmed with `osqueryi` (`SELECT ... , family FROM listening_ports WHERE port=0`)
before writing the promotion rule — a rule keyed on "added" without this fix would have paged on Unix-socket
churn from the first restart. Fixed at the source, not filtered in the rule: `osquery.conf`'s query now reads
`WHERE family != 1`, so every consumer of this stream benefits, not just 100550. Verified the fix doesn't
create its own false "added" burst on redeploy either — osquery diffs by query *name*, not by SQL text, so
the already-open real ports (unchanged before/after the `WHERE` clause) produced no event at all; only the
163 now-excluded Unix-socket rows fired a one-time `removed` (un-alerted, since only `added` is promoted).

## 5. Related

[`../velociraptor/README.md`](../velociraptor/README.md) (the on-demand counterpart) ·
[`../threat-hunting/README.md`](../threat-hunting/README.md) (the hunting discipline this continuous data
feeds) · `phase-7-automation/ansible/roles/osquery/` · [`../../phase-5-offense/TOOLS.md`](../../phase-5-offense/TOOLS.md)
