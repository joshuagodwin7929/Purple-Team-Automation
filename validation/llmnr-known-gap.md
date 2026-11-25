# Known Gap: LLMNR/NBT-NS Poisoning (T1557.001)

## Why it isn't in the Caldera operation

Stockpile's only ability for LLMNR/NBT-NS poisoning uses Inveigh, which runs on Windows only. My Sandcat agent runs on Kali Linux, so it can't execute it. Instead of dropping the technique, I kept it as a known gap from an earlier manual test in my [AD + ELK lab](https://github.com/joshuagodwin7929/Cybersecurity-Labs/tree/main/03-Active-Directory-ELK-SIEM-Lab).

## What I found

I ran Responder on the lab network to poison LLMNR and NBT-NS name lookups. It captured NTLMv2 hashes, and nothing showed up in Elastic, because two Sysmon event types weren't firing on the monitored endpoint:

- Event ID 3, network connection
- Event ID 22, DNS query

With no events coming in, there's nothing to write a rule against. That's why my Detection-Engineering repo has no rule for this technique.

## Why it matters

LLMNR poisoning needs no credentials, and it's often the first thing an attacker tries on a flat internal network. Not being able to see it at all is a bigger gap than any of the four Kerberos and AD techniques in this operation.

## How I'll close it

1. Fix the Sysmon configuration so Event IDs 3 and 22 are logged on the endpoints.
2. Re-run Responder, or add an Inveigh ability if I add a Windows agent to the lab.
3. Write a Sigma rule from the events I actually see, and test it against deliberate false positives as I did for the Kerberoasting and DCSync rules.
4. Deploy it as an alerting rule, confirm it raises an alert, and update the heatmap.
