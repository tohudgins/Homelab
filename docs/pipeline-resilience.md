# Pipeline resilience — does a Wazuh manager outage lose telemetry?

**Closes an architectural review item (2026-09-30).** Every converge that restarts `wazuh-manager`
disconnects every agent for a few seconds — observed directly, repeatedly, during ordinary Ansible work this
session (`ossec.log`: `Lost connection with manager` / `Connected to the server`, each restart). The question
that raises and this lab had never actually answered: **is anything generated during that gap lost, or does
the agent buffer it?** A real SOC has to know this — it directly bounds how much you trust "no alert" as
"nothing happened" versus "something happened during a restart window."

> [!check] Live-tested, not assumed, 2026-09-30 — zero events lost across a real manager outage.

## Method

A real outage, not a simulated one: stop `wazuh-manager` on siem-01 entirely, generate known, uniquely
identifiable attack telemetry on an agent (dmz-01) while it's down, then restart the manager and check
whether every event survived.

```bash
# 1. Baseline
ssh siem-01 "sudo grep -c '\"id\":\"100580\"' /var/ossec/logs/alerts/alerts.json"   # 5

# 2. Take the manager down
ssh siem-01 'sudo systemctl stop wazuh-manager'
# confirmed on dmz-01: wazuh-agentd: ERROR (1216): Unable to connect ... 'Transport endpoint is not connected'

# 3. Generate 5 uniquely-tagged SQLi requests against dmz-01 (rule 100580, the T1190
#    host-side layer — see phase-4-detection/detection-catalog.md #38) WHILE the
#    manager is down, from atk-01:
for i in 1 2 3 4 5; do
  ssh atk-01 "curl -sk 'http://10.10.20.10:3000/rest/products/search?q=test%27%20OR%201=1--&outagetest=$i'"
done
# confirmed: all 5 land in dmz-01's local nginx access log regardless of agent state
# (nginx writes to disk directly; it has no dependency on Wazuh at all)

# 4. Bring the manager back
ssh siem-01 'sudo systemctl start wazuh-manager'
# dmz-01 reconnects automatically: wazuh-agentd: INFO (4102): Connected to the server

# 5. Recount
ssh siem-01 "sudo grep -c '\"id\":\"100580\"' /var/ossec/logs/alerts/alerts.json"   # 13
```

## Result

**13 − 5 = 8 new alerts — all 8 accounted for, none missing.** The test actually produced 8 outage-window
events, not 5: an unrelated pre-existing issue (a stale Docker bridge after this VM's most recent
suspend/resume — the exact known condition `roles/dmz/tasks/main.yml`'s "Restart Docker if its bridge
network came back down" task exists to self-heal, not yet re-converged since the last resume) made the
*first* 3 attempts (`outagetest=1,2,3`) hang and time out client-side — but they still reached nginx and were
logged before timing out. Re-converging `dmz.yml` fixed connectivity mid-test (manager still down throughout),
then the same 5 requests (`outagetest=1..5`) ran clean. All 8 lines — the 3 stalled ones and the 5 clean ones
— sat on dmz-01's disk through the entire manager outage, and every one of them produced a real, correctly
timestamped alert within **~1–2 seconds of the agent reconnecting**:

```
2026-09-30T03:18:39 ... outagetest=1   (stalled request, logged before timing out)
2026-09-30T03:18:39 ... outagetest=2   (stalled request, logged before timing out)
2026-09-30T03:18:39 ... outagetest=3   (stalled request, logged before timing out)
2026-09-30T03:18:40 ... outagetest=1   (clean retry, after the mid-test dmz-01 fix)
2026-09-30T03:18:40 ... outagetest=2   (clean retry, after the mid-test dmz-01 fix)
2026-09-30T03:18:40 ... outagetest=3   (clean retry, after the mid-test dmz-01 fix)
2026-09-30T03:18:40 ... outagetest=4   (clean retry, after the mid-test dmz-01 fix)
2026-09-30T03:18:40 ... outagetest=5   (clean retry, after the mid-test dmz-01 fix)
```

**Zero telemetry loss.** Wazuh's agent-side architecture is two independent pieces working exactly as
designed: `wazuh-logcollector` keeps tailing local log files regardless of network state (it has no
awareness of whether `wazuh-agentd` can reach the manager), and `wazuh-agentd` queues what logcollector
hands it locally, draining the backlog the moment the connection comes back — not just resuming live tailing
from "now."

## What this does and doesn't cover

- **Covers:** ordinary restarts (a converge, a patch, a brief network blip) — exactly the outage shape this
  lab actually produces. The queue is disk-backed and bounded (`client_buffer`/internal queue limits), not
  infinite — this test moved 8 events, not thousands; an outage long enough or busy enough to fill that
  buffer would behave differently, untested here.
- **Doesn't cover:** an agent that's rebuilt/replaced during the outage (a fresh agent has no backlog to
  drain, by definition), or the manager's own indexer/analysisd queue on the receiving side under heavy
  concurrent load from many agents at once — this test used one agent, one attack shape.

## Why this matters operationally

A "no alert during the incident window" finding during IR now has real evidentiary weight *if* the SIEM
itself was healthy for a normal restart-shaped outage — telemetry generated during a brief manager
restart is not silently lost. It does **not** license assuming this holds for every outage shape (a longer
outage, a disk-full agent, a genuinely crashed — not restarted — agent all need their own answer); this
result is specifically "converge-shaped restarts don't lose data," not "the pipeline is lossless."
