# Purple Team Report: AD Credential Access Chain

| | |
|---|---|
| Author | Okunnuwa Joshua Godwin |
| First operation | 22 September 2026 |
| Re-test | 25 November 2026 |
| Lab | `joshua.local` domain: Windows Server 2022 DC, Windows 10 client, Kali attacker, Caldera v5.0.0, Elastic Stack 8.12 |
| Detections | Four Kibana Elasticsearch query rules ([`validation/kibana-rules.md`](validation/kibana-rules.md)) |

All times are UTC.

## 1. Summary

I ran four Active Directory credential-access techniques against my lab through Caldera: password spraying, Kerberoasting, AS-REP Roasting and DCSync. After a re-test in November, each one raised a real alert in Kibana. LLMNR/NBT-NS poisoning remains a gap, because no telemetry for it reaches Elastic.

The first version of this report, from September, said all four rules fired. They hadn't. Only one rule was deployed, and it was broken. Section 4 covers how that happened, and section 5 the six problems I found and fixed while putting it right.

## 2. Scope

Five techniques in the Credential Access tactic (TA0006):

| Order | Technique | Tool | How it ran |
|---|---|---|---|
| 1 | Password Spraying (T1110.003) | Kerbrute | Caldera |
| 2 | Kerberoasting (T1558.003) | Impacket `GetUserSPNs.py` | Caldera |
| 3 | AS-REP Roasting (T1558.004) | Impacket `GetNPUsers.py` | Caldera |
| 4 | DCSync (T1003.006) | Impacket `secretsdump.py` | Caldera |
| n/a | LLMNR/NBT-NS Poisoning (T1557.001) | Responder | Manually, in an earlier lab |

LLMNR poisoning isn't in the Caldera profile because Stockpile's only ability for it (Inveigh) is Windows-only and my agent runs on Linux.

## 3. Results

| Technique | Rule | Alert | Status |
|---|---|---|---|
| Password Spraying | `event.code:4771`, more than 5 in 15 minutes | 25 Nov, 23:31:07 | ✅ Detected |
| Kerberoasting | 4769 with RC4 `0x17`, not krbtgt or machine accounts | 25 Nov, 04:58:45 | ✅ Detected |
| AS-REP Roasting | 4768 with `PreAuthType: 0` | 25 Nov, 05:02:06 | ✅ Detected |
| DCSync | 4662 with the Get-Changes-All GUID, not machine accounts | 25 Nov, 03:45:33 | ✅ Detected |
| LLMNR Poisoning | none | none | ❌ Gap |

Evidence: [`validation/detection-results.md`](validation/detection-results.md). Heatmap: [`attack-navigator-heatmap.json`](attack-navigator-heatmap.json), which you can load in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) with "Open Existing Layer."

## 4. What I got wrong in September

After the September operation I searched Kibana for each attack's event ID, found hits for all four, and published that as "rule fired." A search hit and an alert aren't the same thing. A search shows the event exists. An alert shows a deployed rule, with its own filters and thresholds, matched the event on schedule and told someone.

When I checked Kibana's Rules page in November, only the DCSync rule existed, and it had never alerted. The other three were Sigma files and saved queries that never ran on their own.

## 5. Problems found and fixed

| # | Problem | Effect | Fix |
|---|---|---|---|
| 1 | DCSync query used a wildcard on the `message` text field | The hyphenated GUID could never match: 0 hits vs 2 with a phrase query | Search the GUID as a quoted phrase |
| 2 | September events were ingested 35 minutes after they happened | They arrived outside every 5-minute rule window | 15-minute look-back on a 5-minute schedule |
| 3 | A second, older Winlogbeat copy was running alongside the service | Every event shipped twice, doubling all September counts | Renamed the old copy's data folder; confirmed one `agent.id` |
| 4 | Winlogbeat startup type was Manual | It stayed stopped after a DC reboot | Set to Automatic |
| 5 | The ELK VM was paused during testing | Kibana ran no rules for 45 minutes | Keep the host awake during tests |
| 6 | Password spray rule grouped by IP fields that are empty on 4771 | No groups, so the count never passed the threshold | Count across all documents for now |

Problems 2, 4 and 5 are all the same kind of failure: the pipeline between the attack and the rule silently stopped. In a real SOC they'd be monitored separately, with alerts for an agent going quiet or a rule not running on schedule.

## 6. Open questions

**AS-REP noise.** The AS-REP rule also alerted at 04:57:06, before the AS-REP ability ran, and at 23:31:07, during the password spray. My working explanation is that `j.jenkins` doesn't require Kerberos pre-authentication, so any login by that account produces a 4768 with `PreAuthType: 0`. I haven't confirmed this yet.

**Password spray attribution.** The rule can't say which IP is spraying. In production that needs an ingest pipeline that copies the client IP into a keyword field, or a rule type that counts distinct usernames per source.

**Sigma drift.** The deployed rules now differ from the Sigma rules in my Detection-Engineering repo: the DCSync field, the `svc_sql` allow-list on Kerberoasting, and 4771 for password spray. The Sigma rules need updating to match what actually works.

## 7. Gap analysis

**LLMNR poisoning is the biggest remaining gap.** It needs no credentials and is often the first thing an attacker tries on an internal network, and my lab can't see it at all. Sysmon Event IDs 3 and 22 aren't being logged, so there are no events to detect.

## 8. Next steps

1. Confirm or rule out the `j.jenkins` explanation, and require pre-authentication on every account.
2. Fix the source IP field so the password spray rule can group by attacker.
3. Update the Sigma rules in Detection-Engineering to match the deployed rules.
4. Enable Sysmon Event IDs 3 and 22, then build and test an LLMNR rule.
5. Run DCSync inside the full operation, so all four alerts come from one run.
