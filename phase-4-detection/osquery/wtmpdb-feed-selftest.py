#!/usr/bin/env python3
# Offline self-test for wtmpdb-wazuh-feed.py's dedup/cursor logic — no lab needed.
# Stubs the wtmpdb call and asserts each session is emitted exactly once under BOTH
# possible --since readings (strict login>=cursor, and spanning still-open sessions).
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("feed", os.path.join(HERE, "wtmpdb-wazuh-feed.py"))
feed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(feed)


def entry(user, login, tty="ssh", host="10.0.0.9", logout="still logged in "):
    return {"user": user, "tty": tty, "hostname": host, "login": login, "logout": logout}


def run_case():
    tmp = tempfile.mkdtemp()
    feed.STATE_FILE = os.path.join(tmp, "state.json")
    feed.EVENTS_LOG = os.path.join(tmp, "events.log")
    batches = {}
    feed.fetch_since = lambda cursor: batches["cur"]

    def emitted():
        return sum(1 for _ in open(feed.EVENTS_LOG)) if os.path.exists(feed.EVENTS_LOG) else 0

    checks = []
    # run 1: two logins in the same window
    batches["cur"] = [entry("alice", "2026-09-27T10:00:00+0000"),
                      entry("bob", "2026-09-27T10:00:05+0000")]
    feed.main()
    checks.append((emitted(), 2, "two new logins"))
    # run 2: strict --since re-returns the boundary session (bob) + one new
    batches["cur"] = [entry("bob", "2026-09-27T10:00:05+0000"),
                      entry("carol", "2026-09-27T10:05:00+0000")]
    feed.main()
    checks.append((emitted(), 3, "boundary session not re-emitted"))
    # run 3: spanning --since re-returns an OLDER still-open session (alice)
    batches["cur"] = [entry("alice", "2026-09-27T10:00:00+0000"),
                      entry("carol", "2026-09-27T10:05:00+0000")]
    feed.main()
    checks.append((emitted(), 3, "older still-open session not re-emitted"))
    # run 4: nothing new
    batches["cur"] = [entry("carol", "2026-09-27T10:05:00+0000")]
    feed.main()
    checks.append((emitted(), 3, "idempotent when nothing new"))
    return checks


def main():
    ok = True
    for got, want, desc in run_case():
        status = "PASS" if got == want else "FAIL"
        if got != want:
            ok = False
        print(f"  [{status}] emitted={got} expected={want}  {desc}")
    print(f"\n== {'all cases pass' if ok else 'FAILURES'} ==")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
