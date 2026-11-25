# Purple Team Report: AD Credential Access Chain

| | |
|---|---|
| Author | Okunnuwa Joshua Godwin |
| Operation date | 22 September 2026 |
| Report revised | 25 November 2026 (see section 4) |
| Lab | `joshua.local` domain: Windows Server 2022 DC, Windows 10 client, Kali attacker, Caldera v5.0.0, Elastic Stack 8.12 |
| Detections tested | Sigma rules from [Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering) v0.2.0 |

## 1. Summary

I ran four credential-access techniques against my AD lab as one automated Caldera operation: password spraying, Kerberoasting, AS-REP Roasting and DCSync. All four worked. All four left events in Elastic.

No detection rule raised an alert. Only one of my four rules, DCSync, had been deployed as an alerting rule in Kibana, and it raised 0 alerts that day. The other three existed only as Sigma files and queries.

The first version of this report said all four rules fired. That was wrong. Section 4 explains how it happened.

## 2. Scope

Five techniques in the Credential Access tactic (TA0006):

| Order | Technique | Tool | How it ran |
|---|---|---|---|
| 1 | Password Spraying (T1110.003) | Kerbrute | Caldera |
| 2 | Kerberoasting (T1558.003) | Impacket `GetUserSPNs.py` | Caldera |
| 3 | AS-REP Roasting (T1558.004) | Impacket `GetNPUsers.py` | Caldera |
| 4 | DCSync (T1003.006) | Impacket `secretsdump.py` | Caldera |
| n/a | LLMNR/NBT-NS Poisoning (T1557.001) | Responder | Manually, in an earlier lab |

LLMNR poisoning isn't in the Caldera profile because Stockpile's only ability for it (Inveigh) is Windows-only and my agent runs on Linux. I kept it as a known gap from my [AD + ELK lab](https://github.com/joshuagodwin7929/Cybersecurity-Labs/tree/main/03-Active-Directory-ELK-SIEM-Lab).

## 3. Results

| Technique | Attack worked? | Events in Elastic? | Alert raised? | Status |
|---|---|---|---|---|
| Password Spraying | Yes | Yes, 4771 (28) | No | Gap |
| Kerberoasting | Yes | Yes, 4769 RC4 (2) | No | Not validated |
| AS-REP Roasting | Yes | Yes, 4768 PreAuthType 0 (8) | No | Not validated |
| DCSync | Yes | Yes, 4662 (8) | No | Not validated |
| LLMNR Poisoning | Yes | No | No | Gap |

Evidence and screenshots: [`validation/detection-results.md`](validation/detection-results.md). Heatmap: [`attack-navigator-heatmap.json`](attack-navigator-heatmap.json), which you can load in [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) with "Open Existing Layer."

## 4. What I got wrong

In September, after the operation, I searched Kibana for each attack's event ID and found hits for all four. I took that as proof the rules fired and published the results that way, with every technique green on the heatmap.

A search hit and a rule alert aren't the same thing. A search shows the event exists. An alert shows that the rule, with its own filters and thresholds, matched the event and told someone. My searches were also looser than the rules. For DCSync I searched `event.code:4662` with no GUID or account filter.

When I checked Kibana's Rules page in November, I found:

- One deployed rule, "DCSync Detected - Replication Rights Abused," which ran 27 times on 22 September and raised 0 alerts.
- No deployed rules for Kerberoasting, AS-REP Roasting or password spraying.

I also found two problems in the rules themselves that I hadn't noticed:

- **Password spraying:** the Sigma rule counts 4625 failures. Kerbrute produces 4771 instead, so the rule could never match it. My Wazuh lab later hit the same blind spot, and I fixed it there with a 4771 rule.
- **Kerberoasting:** during tuning I allow-listed `svc_sql` to stop false positives from legitimate clients. But `svc_sql` is the account this operation roasts, so the tuned rule would ignore the attack.

## 5. Gap analysis

**Biggest gap: LLMNR poisoning.** It needs no credentials and is often the first technique an attacker tries, and my lab can't see it at all. Sysmon Event IDs 3 and 22 weren't firing on the endpoint, so no events arrive to detect.

**Second gap: detections that exist only on paper.** Three of my four rules were never deployed. This is the main lesson of the exercise for me: a rule isn't coverage until it's running and has raised an alert against the real attack.

**Rule logic gaps:** the password spray event ID mismatch and the Kerberoasting allow-list, both described in section 4.

## 6. Next steps

1. Deploy the Kerberoasting, AS-REP Roasting and password spray detections as alerting rules in Kibana.
2. Add 4771 to the password spray rule.
3. Fix `svc_sql` at the account (AES only) and remove it from the allow-list, or narrow the filter to known legitimate clients.
4. Check the DCSync rule's query, look-back window and first run time to find out why it didn't alert.
5. Enable Sysmon Event IDs 3 and 22, then build an LLMNR rule.
6. Re-run the operation and record alerts, not search hits, as evidence. Update this report and the heatmap with the new results.
