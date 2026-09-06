#!/usr/bin/env python3
# ===========================================================================
# hunt-rare-process.py — hunt for suspicious process execution by RARITY
# ("stack counting" / long-tail analysis) over Sysmon EID 1 telemetry.
#
# HYPOTHESIS: on any given endpoint the same few binaries run constantly
# (cmd, powershell, the agent, housekeeping tasks) while an attacker's tooling
# — a LOLBin pressed into service, a one-off downloader, a renamed binary —
# executes rarely. So the RAREST processes are, disproportionately, the ones
# worth looking at. "The least-frequent occurrences are often the most
# interesting" is the oldest hunt in the book (SANS stack counting).
#
# METHOD: pull process-creation events (Sysmon Event ID 1) for one agent from
# the Wazuh full-event archive, then:
#   1. frequency-count by image (basename, case-normalised) and show the long
#      tail rarest-first — with a sample command line + parent for triage;
#   2. frequency-count parent -> child pairs and show the rarest ancestry, which
#      catches a common binary launched from an *uncommon* parent (e.g. a shell
#      spawned by an Office app or a service host).
#
# DATA SOURCE — and a real prerequisite this hunt exposed: Wazuh only writes
# *rule-matched* events to alerts.json, and the stock Sysmon EID1 rules only
# alert on already-suspicious patterns. You cannot find a rare-but-benign-looking
# process in a corpus that has been pre-filtered to suspicious ones. Hunting
# process rarity therefore requires COLLECTING every process event first —
# `<logall_json>yes</logall_json>` on the manager, which streams the full event
# set to /var/ossec/logs/archives/archives.json. This script reads that archive
# over SSH (sudo grep to pre-filter by agent), or a local file / stdin.
#
#   ./hunt-rare-process.py                 # fetch ws-01 events live from the SIEM
#   ./hunt-rare-process.py --agent dc-01
#   ./hunt-rare-process.py archives.json   # analyze a local copy
#   cat archives.json | ./hunt-rare-process.py -
# ===========================================================================
import json
import subprocess
import sys

SIEM_SSH = "siem-01"
ARCHIVE = "/var/ossec/logs/archives/archives.json"
DEFAULT_AGENT = "ws-01"
TOP_TAIL = 15   # how many of the rarest images / relationships to show


def parse_args():
    agent, source = DEFAULT_AGENT, None
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--agent":
            agent = args[i + 1]
            i += 2
        else:
            source = args[i]
            i += 1
    return agent, source


def load_events(agent, source):
    """Return raw JSON-lines text of archive events for the agent."""
    if source == "-":
        return sys.stdin.read()
    if source:
        return open(source).read()
    # live: pre-filter on the SIEM to the agent's Sysmon EID1 lines (keeps the
    # transfer small — archives.json holds every event from every agent)
    remote = (f"sudo grep -a '\"name\":\"{agent}\"' {ARCHIVE} 2>/dev/null "
              f"| grep -a '\"eventID\":\"1\"'")
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=15", SIEM_SSH, remote],
                       capture_output=True, text=True, timeout=120)
    if r.returncode not in (0, 1):  # grep rc=1 = no matches, not an error
        sys.exit(f"could not read {ARCHIVE} on {SIEM_SSH}: {r.stderr.strip()}")
    return r.stdout


def eid1_events(text, agent):
    """Yield (image, parent, cmdline, user) for each Sysmon EID1 event."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("agent", {}).get("name") != agent:
            continue
        win = e.get("data", {}).get("win", {})
        if win.get("system", {}).get("eventID") != "1":
            continue
        ed = win.get("eventdata", {})
        img = ed.get("image")
        if not img:
            continue
        yield (img, ed.get("parentImage", "?"),
               ed.get("commandLine", ""), ed.get("user", "?"))


def base(path):
    return path.replace("/", "\\").split("\\")[-1].lower() if path else path


def main():
    agent, source = parse_args()
    events = list(eid1_events(load_events(agent, source), agent))
    if not events:
        sys.exit(f"no Sysmon EID1 events for agent '{agent}' — is <logall_json> on "
                 f"and has the agent generated process activity?")

    # --- stack count by image basename ---
    img_count, img_sample = {}, {}
    for img, parent, cmd, user in events:
        b = base(img)
        img_count[b] = img_count.get(b, 0) + 1
        # keep the fullest sample cmdline for triage
        if b not in img_sample or len(cmd) > len(img_sample[b][1]):
            img_sample[b] = (base(parent), cmd, img)

    total = len(events)
    print(f"\n== Rare-process hunt :: agent={agent} :: {total} process-creation "
          f"events, {len(img_count)} distinct images ==")
    print("   long tail first — the rarest binaries are the most interesting\n")
    print(f"  {'count':>5} {'%':>6}  {'image':<22} {'parent':<16} sample command line")
    print("  " + "-" * 96)
    for b, n in sorted(img_count.items(), key=lambda x: (x[1], x[0]))[:TOP_TAIL]:
        parent, cmd, _ = img_sample[b]
        cmd = " ".join(cmd.split())[:60]
        print(f"  {n:>5} {100*n/total:>5.1f}%  {b:<22} {parent:<16} {cmd}")

    # --- stack count by parent -> child relationship ---
    rel_count, rel_sample = {}, {}
    for img, parent, cmd, user in events:
        key = (base(parent), base(img))
        rel_count[key] = rel_count.get(key, 0) + 1
        if key not in rel_sample:
            rel_sample[key] = cmd
    print(f"\n  Rarest parent -> child relationships "
          f"({len(rel_count)} distinct pairs):")
    print(f"  {'count':>5}  {'parent':<18} -> {'child':<20} sample command line")
    print("  " + "-" * 90)
    for (parent, child), n in sorted(rel_count.items(), key=lambda x: (x[1], x[0]))[:TOP_TAIL]:
        cmd = " ".join(rel_sample[(parent, child)].split())[:52]
        print(f"  {n:>5}  {parent:<18} -> {child:<20} {cmd}")

    # --- singletons: the classic "seen exactly once" set ---
    singles = sorted(b for b, n in img_count.items() if n == 1)
    print(f"\n  {len(singles)} image(s) seen exactly once: {', '.join(singles)}")
    print("  -> triage each against known-good baselines and existing detections;")
    print("     an unfamiliar LOLBin with no rule is a detection gap to close.\n")


if __name__ == "__main__":
    main()
