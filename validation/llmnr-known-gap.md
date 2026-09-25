# Known Gap: LLMNR/NBT-NS Poisoning (T1557.001)

## Why this isn't in the Caldera operation

Stockpile's only ability covering LLMNR/NBT-NS poisoning relies on Inveigh,
which is Windows/.NET-only. The Sandcat agent used in this lab runs on a
Kali Linux host, so this ability cannot execute there. Rather than skip the
technique entirely, it's carried into this project as a **known-gap
negative control**, using an earlier manual finding from
[elk-siem-lab](../../elk-siem-lab).

## What was found

Responder was run manually against the lab's broadcast segment to poison
LLMNR/NBT-NS name resolution requests. The attack succeeded in capturing
credentials, but **no corresponding detection fired** — because:

- Sysmon Event ID 3 (Network Connection) is not enabled on the monitored endpoint
- Sysmon Event ID 22 (DNS Query) is not enabled on the monitored endpoint

Without this telemetry, there's no event stream to build a Sigma rule
against, so detection-as-code-repo does not (and cannot yet) include a rule
for this technique.

## Why it matters

LLMNR/NBT-NS poisoning is one of the most commonly exploited techniques in
real internal penetration tests and red team engagements — it requires no
prior credentials and is often the very first foothold technique attempted
on a flat network. A complete inability to detect it is a higher-priority
gap than any of the four Kerberos/AD techniques validated in this project,
all of which fired successfully.

## Remediation path

1. Enable Sysmon Event ID 3 and 22 logging via Sysmon configuration on
   affected endpoints.
2. Re-run the Responder attack (or add a Windows-based Inveigh ability to
   Caldera if a Windows agent becomes available in the lab).
3. Build and tune a new Sigma rule for LLMNR/NBT-NS poisoning detection,
   following the same false-positive testing process used for the
   Kerberoasting and DCSync rules in detection-as-code-repo.
4. Re-score this technique in the ATT&CK Navigator layer once detection is
   confirmed.
