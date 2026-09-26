#!/usr/bin/env python3
# ===========================================================================
# velociraptor-hunt-escalate.py — closes the DFIR->SIEM loop the
# velociraptor/README.md's own "possible next step, noted not built" named
# (2026-09-26 gap audit): Velociraptor's fleet hunts were on-demand only, so
# even a genuine hit (a planted implant, a persistence entry) never became a
# SIEM alert unless an analyst happened to run the hunt and look at the
# output. This runs the lab's existing Custom.Hunt.ImplantIOC hunt on a
# schedule and escalates any high-confidence hit into Wazuh's own alerting —
# the same analyst-visible, IRIS-reaching path a real detection takes —
# instead of building a second, parallel notification system.
#
# Runs on siem-01, which already hosts both the Velociraptor server and the
# Wazuh manager, so no cross-host complexity: trigger the hunt via the local
# API config, wait for the (small, 3-host) fleet to check in, then inject one
# Wazuh event per finding via the analysisd queue socket — the identical
# technique custom-misp.py/custom-iris.py already use for their own
# integrations, just triggered by a schedule instead of an inbound alert.
#
# Two different confidence bars per platform, not "escalate everything the
# hunt returns": a world-writable ELF (Linux source) is already the
# high-confidence signal on its own — nothing legitimate lives in
# /tmp,/dev/shm,/var/tmp as an executable in this lab, so every hit is
# escalated. A Windows Run-key entry is not — most of what the hunt returns
# on any real Windows box is legitimate autostart software (OneDrive,
# SecurityHealth, vendor tools), so only entries NOT in the small known-good
# allowlist below are escalated; growing that allowlist as new legitimate
# software is added is expected maintenance, not a workaround.
#
# Usage: velociraptor-hunt-escalate.py
# ===========================================================================
import json
import subprocess
import time
from socket import socket, AF_UNIX, SOCK_DGRAM

VELOCIRAPTOR_BIN = "/usr/local/bin/velociraptor"
API_CONFIG = "/etc/velociraptor/api.config.yaml"
HUNT_ARTIFACT = "Custom.Hunt.ImplantIOC"
WAIT_FOR_RESULTS_SECONDS = 30
SOCKET_ADDR = "/var/ossec/queue/sockets/queue"
LOG_FILE = "/var/log/velociraptor-hunt-escalate.log"

# Windows Run-key entries known to be legitimate on this lab's fleet (see
# velociraptor/README.md's own example hunt output). An entry NOT in this
# list is escalated — growing this list is the expected way to tune false
# positives as real software changes, not evidence the rule is broken.
WINDOWS_RUNKEY_ALLOWLIST = {
    "OneDrive",
    "SecurityHealth",
    "VMware User Process",
}


def vql(query):
    """Run one VQL query via the local API config and return parsed JSON (a list)."""
    result = subprocess.run(
        [VELOCIRAPTOR_BIN, "--api_config", API_CONFIG, "query", query],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        raise RuntimeError(f"velociraptor query failed: {result.stderr.strip()}")
    return json.loads(result.stdout or "[]")


def send_event(msg):
    """Inject an event into analysisd (location 'velociraptor') so rules can match it."""
    payload = json.dumps(msg)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(SOCKET_ADDR)
    sock.send(f"1:velociraptor:{payload}".encode())
    sock.close()


def main():
    hunt_resp = vql(
        f"SELECT hunt(description='scheduled implant sweep', artifacts='{HUNT_ARTIFACT}') "
        "AS HuntId FROM scope()"
    )
    hunt_id = hunt_resp[0]["HuntId"]["HuntId"]

    time.sleep(WAIT_FOR_RESULTS_SECONDS)

    linux_hits = vql(
        f"SELECT * FROM hunt_results(hunt_id='{hunt_id}', "
        f"artifact='{HUNT_ARTIFACT}/LinuxWorldWritableELF')"
    )
    windows_hits = vql(
        f"SELECT * FROM hunt_results(hunt_id='{hunt_id}', "
        f"artifact='{HUNT_ARTIFACT}/WindowsRunKeys')"
    )

    escalated = 0
    for hit in linux_hits:
        send_event({
            "integration": "velociraptor",
            "velociraptor": {
                "hunt_id": hunt_id,
                "artifact": f"{HUNT_ARTIFACT}/LinuxWorldWritableELF",
                "hostname": hit.get("Fqdn"),
                "path": hit.get("Path"),
                "sha256": hit.get("SHA256"),
                "size": hit.get("Size"),
            },
        })
        escalated += 1

    for hit in windows_hits:
        if hit.get("Name") in WINDOWS_RUNKEY_ALLOWLIST:
            continue
        send_event({
            "integration": "velociraptor",
            "velociraptor": {
                "hunt_id": hunt_id,
                "artifact": f"{HUNT_ARTIFACT}/WindowsRunKeys",
                "hostname": hit.get("Fqdn"),
                "name": hit.get("Name"),
                "command": hit.get("Command"),
                "path": hit.get("Path"),
            },
        })
        escalated += 1

    with open(LOG_FILE, "a") as f:
        f.write(
            f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
            f"hunt={hunt_id} linux_hits={len(linux_hits)} "
            f"windows_hits={len(windows_hits)} escalated={escalated}\n"
        )


if __name__ == "__main__":
    main()
