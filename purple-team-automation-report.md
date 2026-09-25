# Purple-Team-Automation: Detection Validation, AD Credential Access Chain

## 1. Objective & Scope

This exercise validates the Sigma rules built in [(detection-as-code-repo)](../detection-as-code-repo) against live, automated attack execution, rather than the manually-run hunt queries they were originally built from.

**Scope:** 5 techniques within the Credential Access tactic (TA0006), chained together as a single adversary profile and executed via Caldera.

**Environment:** Existing Active Directory domain lab, with a Caldera C2 server and a Sandcat agent deployed on a Kali Linux host (`group: red`).

## 2. Adversary Profile & Methodology

**Caldera profile:** `AD Credential Access Chain`

**Ability chain:**

| Order | Technique | Tool |
|---|---|---|
| 1 | Password Spraying (T1110.003) | Kerbrute (custom Caldera ability) |
| 2 | Kerberoasting (T1558.003) | Impacket `GetUserSPNs.py` (custom Caldera ability) |
| 3 | AS-REP Roasting (T1558.004) | Impacket `GetNPUsers.py` (custom Caldera ability) |
| 4 | DCSync (T1003.006) | Impacket `secretsdump.py` (custom Caldera ability) |

**Note on LLMNR/NBT-NS Poisoning (T1557.001):** This technique was deliberately excluded from the Caldera adversary profile, Stockpile's only available ability for it (Inveigh) is Windows-only and the operating agent is Linux-based. It was instead run manually using Responder and is included here as a **known-gap negative control**, carried over from an earlier finding in [elk-siem-lab](../elk-siem-lab) where Sysmon Event 3/22 visibility was confirmed absent.

## 3. Execution Summary

| Technique | Target Account | Target Host | Date |
|---|---|---|---|
| Password Spraying | oscar.martinez | Domain Controller | Sep 22, 2026 |
| Kerberoasting | (SPN-associated service account) | Domain Controller | Sep 22, 2026 |
| AS-REP Roasting | j.jenkins | Domain Controller | Sep 22, 2026 |
| DCSync | (non-DC replication account) | Joshua-Server2022 | Sep 22, 2026 |
| LLMNR Poisoning (manual) | N/A | Broadcast segment | Prior (elk-siem-lab) |

## 4. Detection Results

Full interactive heatmap: `attack-navigator-heatmap.json` (load into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) via "Open Existing Layer").

| Technique | Event ID | Sigma Rule Fired | Hits | Status |
|---|---|---|---|---|
| T1110.003 – Password Spraying | 4771 | Repeated Kerberos pre-auth failures (0x18) across accounts | 28 | 🟢 Detected |
| T1558.003 – Kerberoasting | 4769 | RC4 (etype 0x17) TGS-REQ pattern | 2 | 🟢 Detected |
| T1558.004 – AS-REP Roasting | 4768 | AS-REQ with PreAuthType 0 for UF_DONT_REQUIRE_PREAUTH account | 8 | 🟢 Detected |
| T1003.006 – DCSync | 4662 | Directory Service Access / DS-Replication-Get-Changes-All from non-DC source | 8 | 🟢 Detected |
| T1557.001 – LLMNR Poisoning | N/A | No rule exists | 0 | 🔴 Gap |

**Detail on each finding:**

- **Password Spraying (4771):** 28 hits showing repeated Kerberos pre-authentication failures (Failure Code `0x18`, wrong password) against `oscar.martinez` from source IP `192.168.18.70` (the Kali agent).
- **Kerberoasting (4769):** 2 hits with `TicketEncryptionType: 0x17`, matching the RC4 downgrade signature GetUserSPNs.py produces when requesting service tickets.
- **AS-REP Roasting (4768):** 8 hits with `PreAuthType: 0` for account `j.jenkins`, confirming pre-authentication was skipped, the exact behavior GetNPUsers.py exploits on accounts with `UF_DONT_REQUIRE_PREAUTH` set.
- **DCSync (4662):** 8 hits with `event.action: Directory Service Access` and `event.outcome: success` on host `Joshua-Server2022`, consistent with a DS-Replication-Get-Changes-All request from a non-domain-controller source.
- **LLMNR Poisoning:** No Sigma rule exists in detection-as-code-repo for this technique. Root cause: Sysmon Event ID 3 (Network Connection) and Event ID 22 (DNS Query) are not firing on the endpoint, so there's no telemetry to alert on multicast name-resolution abuse.

## 5. Gap Analysis

LLMNR/NBT-NS poisoning remains a confirmed blind spot. This matters because Responder-style attacks are extremely common in real-world internal penetration tests and are often one of the first techniques attempted by an adversary with initial network access, the fact that this environment could not detect it at all, even manually, represents a materially higher-value gap than the four techniques that were successfully caught.

**Root cause:** Sysmon is not configured to log Event ID 3 (Network Connection) or Event ID 22 (DNS Query) on the monitored endpoint. This same gap was previously identified in elk-siem-lab and is documented there as a blocked dependency for a related network-layer detection effort (Project A).

## 6. Recommendations / Next Steps

1. **Fix Sysmon configuration** to enable Event ID 3 and 22 logging on relevant endpoints.
2. **Write and test a new Sigma rule** for LLMNR/NBT-NS poisoning once that telemetry is available, following the same tuning process (deliberate false-positive testing) used for the Kerberoasting and DCSync rules in Project B.
3. **Re-run the Caldera operation** (or a manual Responder pass) after the fix to confirm detection and update this heatmap to fully green.
4. This gap and its fix feed into the broader [SOC projects roadmap](../soc-projects-roadmap) as a prerequisite item before later phases.

---
*Companion file: `attack-navigator-heatmap.json` (ATT&CK Navigator layer)*
