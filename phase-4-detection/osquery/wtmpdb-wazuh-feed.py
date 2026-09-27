#!/usr/bin/env python3
# ===========================================================================
# wtmpdb-wazuh-feed.py — feeds NEW wtmpdb login/logout sessions into Wazuh as
# structured, per-session JSON. Closes the "wiring wtmpdb into Wazuh is real,
# separate follow-up work" item left open when libpam-wtmpdb was installed
# (osquery role) to work around osquery's logged_in_users being permanently
# incompatible with this OS's retired legacy utmp.
#
# Confirmed live (2026-09-27): Ubuntu's own `last` command already reads
# wtmpdb transparently on this OS (util-linux ships a wtmpdb-aware `last`),
# and Wazuh's own stock full_command "last -n 20" localfile already picks up
# some of that via rule 535 -- but only as one opaque unstructured text diff
# per change, level 1, no user/tty/host fields, nothing to alert on. This
# gives real structured, queryable, per-session events instead.
#
# `wtmpdb last --since TIME` is TIMESTAMP-INCLUSIVE (confirmed live: querying
# with --since set to an entry's own login time re-returns that exact entry),
# so a naive "since = last cursor" would re-emit the boundary session every
# run. Dedup is therefore anchored on a persistent, bounded set of session
# keys (user, tty, hostname, login) that have already been emitted -- NOT on
# the cursor alone. This is correct under both readings of --since: whether it
# returns only sessions whose login >= TIME, or also older sessions still open
# at TIME, a session is emitted exactly once and never re-emitted while it
# keeps being returned. (An earlier version tracked only the keys at the
# cursor's exact second, which would have re-emitted a long-lived login every
# run if --since turns out to include still-open older sessions -- not retested
# live yet, so the dedup is made robust to it rather than assuming.)
#
# One session -> one event, at first sighting. A session still open when first
# seen is emitted once with logout="still logged in"; its later logout is not
# re-emitted. For login-visibility (rule 100567, level 3) the login event is
# the one that matters; this deliberately avoids duplicate per-session events.
#
# First run seeds the cursor at "now" rather than backfilling wtmpdb's full
# history: this lab's wtmpdb databases already hold weeks of attack-
# simulation login churn, and flooding the SIEM with all of it re-labeled as
# "just detected" on deploy day would be noise, not signal. Only sessions
# starting after this script is first installed are ever surfaced.
#
# Real bug found live (2026-09-27): `wtmpdb last -s TIME` only accepts TIME as
# plain "YYYY-MM-DD HH:MM:SS" (confirmed via --help), but `--time-format iso`
# output (what entries' own "login" field uses, needed for real precision) is
# "2026-09-27T21:37:10+0000" -- a different format. Feeding an entry's raw
# "login" value straight back in as next run's cursor made every second run
# fail outright (wtmpdb exit 1). to_since_arg() converts between the two.
# ===========================================================================
import json
import subprocess
import time
from datetime import datetime

WTMPDB_BIN = "/usr/bin/wtmpdb"
STATE_FILE = "/var/lib/wtmpdb-wazuh-feed/state.json"
EVENTS_LOG = "/var/log/wtmpdb-events.log"


def to_since_arg(iso_ts):
    """Convert a --time-format iso timestamp to the plain form --since requires."""
    return datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%S%z").strftime("%Y-%m-%d %H:%M:%S")


# Bounds the persistent dedup set. A 5-min window holds a handful of sessions;
# 1000 keys is far more than any real backlog and keeps the state file tiny.
SEEN_MAX = 1000


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        return {"cursor": now, "seen": []}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def fetch_since(cursor):
    result = subprocess.run(
        [WTMPDB_BIN, "last", "-j", "--time-format", "iso", "-s", cursor],
        capture_output=True, text=True, timeout=30, check=True,
    )
    return json.loads(result.stdout or "{}").get("entries", [])


def entry_key(entry):
    return (entry.get("user"), entry.get("tty"), entry.get("hostname"), entry.get("login"))


def main():
    state = load_state()
    # Back-compat: older state files used "seen_at_cursor" (only the keys at the
    # cursor's exact second). Seed the new persistent set from it if present.
    seen = set(tuple(k) for k in state.get("seen", state.get("seen_at_cursor", [])))
    entries = fetch_since(state["cursor"])

    new_entries = [e for e in entries if entry_key(e) not in seen]

    if new_entries:
        with open(EVENTS_LOG, "a") as f:
            for e in new_entries:
                # Nested under "wtmpdb", not top-level: "user" and "hostname" are
                # both Wazuh core/reserved field names (confirmed live -- "user"
                # silently aliases to dstuser, "hostname" gets shadowed by the
                # AGENT's own hostname, so $(user)/$(hostname) in a rule
                # description either render wrong or blank). Same namespacing
                # velociraptor-hunt-escalate.py already uses for this exact reason.
                f.write(json.dumps({
                    "source": "wtmpdb",
                    "wtmpdb": {
                        "user": e.get("user"),
                        "tty": e.get("tty"),
                        "hostname": e.get("hostname"),
                        "login": e.get("login"),
                        "logout": e.get("logout"),
                        "length": e.get("length"),
                    },
                }) + "\n")

    if entries:
        latest_login = max(e.get("login") for e in entries if e.get("login"))
        # Dedup is anchored on the persistent `seen` set, NOT the cursor: every key
        # returned this run is folded back in, so a session that keeps appearing
        # (e.g. a long-lived login `--since` may re-return under either of its
        # possible semantics) is never re-emitted, while keys that stop appearing
        # eventually age out under SEEN_MAX. Order-preserving dedup keeps the newest.
        merged = list(dict.fromkeys([tuple(k) for k in seen] + [entry_key(e) for e in entries]))
        state = {"cursor": to_since_arg(latest_login), "seen": [list(k) for k in merged[-SEEN_MAX:]]}
        save_state(state)

    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
          f"fetched={len(entries)} new={len(new_entries)} cursor={state['cursor']}")


if __name__ == "__main__":
    main()
