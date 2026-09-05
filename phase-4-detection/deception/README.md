# Deception — an AD honeytoken tripwire

**The cheapest, highest-signal detection in the lab.** Every other rule in the catalog reasons about
*behaviour* and lives with a false-positive tradeoff — a brute-force threshold a real user can trip, a
discovery command an admin also runs. A **honeytoken** sidesteps that entirely: plant something that looks
valuable but that **no legitimate process ever touches**, and any interaction with it is malicious *by
definition*. There is no benign explanation, so the rule fires at **level 14** — above everything else in the
catalog — with essentially zero false positives.

> [!check] Deployed and verified live on 2026-09-05.
> A decoy AD service account `svc-sqladmin` (attractive `MSSQLSvc/sql-prod.lab.internal` SPN, strong
> uncrackable password) was planted on `dc-01`. A **targeted single-SPN Kerberoast** of it from `atk-01`
> tripped **rule 100420 (L14)** on the first request — while the volume-based Kerberoasting rule (100031)
> stayed silent, exactly the evasive case it can't catch. A wrong-password logon **as** the decoy tripped
> **rule 100421 (L14)**. Both managed as code (dc role: the decoy; siem role: the detections).

---

## Why a honeytoken here specifically

The lab already detects Kerberoasting by **volume** — rule 100031 fires when one account requests 3+ service
tickets in 60s ([detection catalog #3](../detection-catalog.md)). That rule documents its own honest gap:

> a targeted attacker who already knows the one or two SPNs worth cracking stays under the threshold and
> evades this rule entirely.

A honeytoken closes precisely that gap. The signal is no longer *how many* tickets an account requests, but
*which SPN* was requested at all. Because the decoy's SPN corresponds to no real service, the **first and
only** TGS request for it is already an incident — no threshold, no correlation window, nothing to slip under.

## The decoy (`dc-01`, managed by the `dc` role)

`svc-sqladmin` is built to be the most attractive target a Kerberoasting sweep would find, and nothing else:

| Property | Value | Why |
|---|---|---|
| Name | `svc-sqladmin` | reads as a privileged production DB service account |
| SPN | `MSSQLSvc/sql-prod.lab.internal:1433` | a juicy, production-looking Kerberoastable SPN |
| Password | strong, random, 24 chars | **uncrackable on purpose** — it's a tripwire, not attack surface; even if roasted, the hash won't crack |
| Usage | never authenticated, no logon | `GetUserSPNs` shows `LastLogon <never>` — the honeytoken tell a careful attacker might notice, and a careless one won't |

It lives in `dc_honeytoken_accounts` (role defaults), created by the same idempotent create/SPN tasks as the
real weak accounts — but deliberately excluded from the DCSync / Backup-Operators over-privilege grants, which
target `svc-backup` only. A decoy must never be a real privilege-escalation path.

## The detections (`siem` role, `local_rules.xml`)

```xml
<!-- Kerberoast tripwire: ANY TGS-REQ for the decoy SPN -->
<rule id="100420" level="14">
  <if_sid>100030</if_sid>                                <!-- Samba KDC TGS-REQ event -->
  <field name="KDC Authorization.serviceDescription" type="pcre2">(?i)MSSQLSvc/sql-prod\.lab\.internal</field>
  <description>HONEYTOKEN TRIPWIRE — TGS-REQ for decoy account svc-sqladmin by $(KDC Authorization.account) ...</description>
  <mitre><id>T1558.003</id></mitre>
  <group>deception,honeytoken,attack,credential_access,</group>
</rule>

<!-- Credential-use tripwire: ANY authentication AS the decoy (success OR failure) -->
<rule id="100421" level="14">
  <decoded_as>json</decoded_as>
  <field name="type">^Authentication$</field>
  <field name="Authentication.clientAccount" type="pcre2">(?i)^svc-sqladmin(@|$)</field>
  <description>HONEYTOKEN TRIPWIRE — authentication attempt AS decoy account svc-sqladmin ($(Authentication.status)) ...</description>
  <mitre><id>T1078</id></mitre>
  <group>deception,honeytoken,attack,credential_access,</group>
</rule>
```

Both key on a field whose value is the *decoy's identity* (the SPN, the account name), so precision is
absolute — no benign traffic carries it. Level 14 encodes that certainty.

## Verify by exercising

**1. Targeted Kerberoast of the decoy** (`atk-01`, as a domain user — a cracked `svc-sql` from the earlier
password-spray). A real roaster (`GetUserSPNs`, Rubeus) and `kvno` send the *same* TGS-REQ; `kvno` is used
here because it produces a clean request Samba logs cleanly (see the honest note below):

```
atk-01$ kinit svc-sql@LAB.INTERNAL
atk-01$ kvno MSSQLSvc/sql-prod.lab.internal:1433
MSSQLSvc/sql-prod.lab.internal:1433@LAB.INTERNAL: kvno = 2
```
→ on `dc-01` the KDC logs `svc-sql -> MSSQLSvc/sql-prod.lab.internal:1433`, and Wazuh fires:
```
Rule: 100420 (level 14) -> 'HONEYTOKEN TRIPWIRE — TGS-REQ for decoy account svc-sqladmin by svc-sql
                            (Kerberoasting against a canary SPN).'   agent dc-01
```
**Crucially, the volume rule 100031 did NOT fire** — this was a single SPN request, under its threshold. The
tripwire caught the exact evasive case the behavioural rule is blind to. That is the whole point of the layer.

**2. Credential use of the decoy** — a wrong-password logon as `svc-sqladmin` (a stolen/guessed canary cred
being tried):
```
atk-01$ kinit svc-sqladmin@LAB.INTERNAL      # wrong password
kinit: Password incorrect while getting initial credentials
```
→ Wazuh fires:
```
Rule: 100421 (level 14) -> 'HONEYTOKEN TRIPWIRE — authentication attempt AS decoy account svc-sqladmin
                            (NT_STATUS_WRONG_PASSWORD) — stolen/guessed canary credential in use.'   agent dc-01
```

**Honest note — impacket vs. Samba.** `impacket-GetUserSPNs -request-user svc-sqladmin` *found* the decoy
(and flagged `LastLogon <never>`) but errored with `KRB_AP_ERR_INAPP_CKSUM` extracting the crackable ticket —
the same Samba-KDC parity gap that stopped AS-REP roasting earlier in this lab. It doesn't matter for
detection: the tripwire fires on the TGS-**request**, which reaches the KDC regardless of whether the tool can
then process the reply. `kvno` issues the identical request without the extraction step, so it's the clean way
to exercise the KDC-side signal this rule watches. A Windows attacker with Rubeus would roast it for real; the
detection is indifferent to which tool sends the request.

## Result

- **New tactic flavour: deception-backed Credential Access.** Rules 100420/100421 (L14), catalog technique
  **#35**. Coverage map gains **T1078** (Valid Accounts, via the credential-use tripwire); the Kerberoast
  tripwire reinforces T1558.003.
- **Closes the documented 100031 evasion** with a detection that has no threshold to evade.
- **As code, converges `changed=0`:** the decoy in the `dc` role (`dc_honeytoken_accounts`), the rules in the
  `siem` role.

## Reproduce

```bash
# deploy (from the ansible dir): decoy account + SPN, then the detections
ansible-playbook dc.yml -l dc-01 && ansible-playbook siem.yml -l siem-01

# exercise from atk-01 (needs krb5-user + /etc/krb5.conf for LAB.INTERNAL)
ssh atk-01 "echo <pw> | kinit svc-sql@LAB.INTERNAL && kvno MSSQLSvc/sql-prod.lab.internal:1433"   # -> 100420 L14
ssh atk-01 "echo wrong | kinit svc-sqladmin@LAB.INTERNAL"                                          # -> 100421 L14

# confirm on the SIEM
ssh siem-01 "sudo grep -aE '\"id\":\"10042[01]\"' /var/ossec/logs/alerts/alerts.json | tail -2"
```

Detections: [`roles/siem/files/local_rules.xml`](../../phase-7-automation/ansible/roles/siem/files/local_rules.xml)
(100420/100421) · decoy: [`roles/dc/defaults/main.yml`](../../phase-7-automation/ansible/roles/dc/defaults/main.yml)
(`dc_honeytoken_accounts`).
