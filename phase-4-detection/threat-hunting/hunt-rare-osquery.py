#!/usr/bin/env python3
# ===========================================================================
# hunt-rare-osquery.py — hunt osquery's own "added" differential stream by
# RARITY, the Linux/osquery counterpart to hunt-rare-process.py's Sysmon EID1
# approach.
#
# HYPOTHESIS: osquery's `processes`/`logged_in_users` queries
# (phase-4-detection/osquery/) stay visibility-only under stock rule 24010
# (level 3) — promoting every "added" row to a real alert would page
# constantly on kernel worker churn and routine SSH logins. But "how often
# has THIS process name / THIS login ever shown up" is exactly the same
# long-tail signal Hunt B already applies to Windows Sysmon telemetry — it
# was just never pointed at the Linux hosts (dc-01/fs-01) osquery actually
# covers.
#
# METHOD: pull osquery's "added" differential events for a given query name
# from the Wazuh full-event archive, stack-count by the field that actually
# identifies "what showed up" (process name for `processes`, (type, user)
# for `logged_in_users`), and rank the long tail — same idiom as
# hunt-rare-process.py, same DATA SOURCE prerequisite
# (<logall_json>yes</logall_json>, already on for every hunt in this folder).
#
#   ./hunt-rare-osquery.py                      # fetch dc-01, both queries, live
#   ./hunt-rare-osquery.py --agent fs-01
#   ./hunt-rare-osquery.py --query processes    # just one query type
#   ./hunt-rare-osquery.py archives.json        # analyze a local copy
#   cat archives.json | ./hunt-rare-osquery.py -
# ===========================================================================
import json
import subprocess
import sys

SIEM_SSH = "siem-01"
ARCHIVE = "/var/ossec/logs/archives/archives.json"
DEFAULT_AGENT = "dc-01"
QUERIES = ("processes", "logged_in_users")
TOP_TAIL = 15


def parse_args():
    agent, source, query = DEFAULT_AGENT, None, None
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--agent":
            agent = args[i + 1]
            i += 2
        elif args[i] == "--query":
            query = args[i + 1]
            i += 2
        else:
            source = args[i]
            i += 1
    return agent, source, query


def load_events(agent, source):
    """Return raw JSON-lines text of archive events for the agent."""
    if source == "-":
        return sys.stdin.read()
    if source:
        return open(source).read()
    # live: pre-filter on the SIEM to this agent's osquery lines (keeps the
    # transfer small — archives.json holds every event from every agent)
    remote = (f"sudo grep -a '\"name\":\"{agent}\"' {ARCHIVE} 2>/dev/null "
              f"| grep -a '\"location\":\"osquery\"'")
    r = subprocess.run(["ssh", "-o", "ConnectTimeout=15", SIEM_SSH, remote],
                       capture_output=True, text=True, timeout=120)
    if r.returncode not in (0, 1):  # grep rc=1 = no matches, not an error
        sys.exit(f"could not read {ARCHIVE} on {SIEM_SSH}: {r.stderr.strip()}")
    return r.stdout


def osquery_added_events(text, agent, query_filter):
    """Yield (query_name, columns, calendarTime) for each 'added' osquery event."""
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
        osq = e.get("data", {}).get("osquery")
        if not osq or osq.get("action") != "added":
            continue
        name = osq.get("name")
        if name not in QUERIES:
            continue
        if query_filter and name != query_filter:
            continue
        yield name, osq.get("columns", {}), osq.get("calendarTime", "?")


def main():
    agent, source, query_filter = parse_args()
    events = list(osquery_added_events(load_events(agent, source), agent, query_filter))
    if not events:
        sys.exit(f"no osquery 'added' events for agent '{agent}' among {QUERIES} — "
                 f"is <logall_json> on and has the schedule run at least once?")

    for qname in QUERIES:
        if query_filter and qname != query_filter:
            continue
        subset = [(cols, t) for n, cols, t in events if n == qname]
        if not subset:
            continue

        if qname == "processes":
            def key_of(cols):
                return (cols.get("name") or "?").lower()
            label = "process name"
        else:  # logged_in_users
            def key_of(cols):
                return f"{cols.get('type', '?')}:{cols.get('user', '?')}"
            label = "type:user"

        count, sample = {}, {}
        for cols, t in subset:
            k = key_of(cols)
            count[k] = count.get(k, 0) + 1
            if k not in sample or t < sample[k][1]:
                sample[k] = (cols, t)

        total = len(subset)
        print(f"\n== Rare-osquery hunt :: agent={agent} :: query={qname} :: "
              f"{total} 'added' events, {len(count)} distinct {label} values ==")
        print("   long tail first — the rarest values are the most interesting\n")
        print(f"  {'count':>5} {'%':>6}  {label:<28} {'first seen':<24} sample")
        print("  " + "-" * 96)
        for k, n in sorted(count.items(), key=lambda x: (x[1], x[0]))[:TOP_TAIL]:
            cols, t = sample[k]
            extra = " ".join(f"{ck}={cv}" for ck, cv in cols.items()
                              if ck not in ("name", "type", "user"))[:40]
            print(f"  {n:>5} {100 * n / total:>5.1f}%  {k:<28} {t:<24} {extra}")

        singles = sorted(k for k, n in count.items() if n == 1)
        print(f"\n  {len(singles)} {label} value(s) seen exactly once: "
              f"{', '.join(singles) or '(none)'}")
        print("  -> triage each against expected baseline behavior for this host;")
        print("     an unfamiliar process/login with no rule is a detection gap to close.\n")


if __name__ == "__main__":
    main()
