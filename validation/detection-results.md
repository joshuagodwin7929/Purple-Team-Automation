# Detection Validation Results

Each technique below was executed via the `AD Credential Access Chain` Caldera
operation and cross-checked against the Sigma rules in
[detection-as-code-repo](../../detection-as-code-repo), by querying the raw
events in Kibana (`winlogbeat-*`).

| Technique | ATT&CK ID | Event ID | Query | Hits | Result |
|---|---|---|---|---|---|
| Password Spraying | T1110.003 | 4771 | `event.code:4771` | 28 | ✅ Detected |
| Kerberoasting | T1558.003 | 4769 | `event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17"` | 2 | ✅ Detected |
| AS-REP Roasting | T1558.004 | 4768 | `event.code:4768 and winlog.event_data.PreAuthType:"0"` | 8 | ✅ Detected |
| DCSync | T1003.006 | 4662 | `event.code:4662` (Directory Service Access) | 8 | ✅ Detected |
| LLMNR/NBT-NS Poisoning | T1557.001 | N/A | No Sigma rule exists | 0 | ❌ Gap |

## Evidence detail

### Password Spraying (T1110.003)
- **Event:** 4771, Kerberos pre-authentication failed
- **Account targeted:** `oscar.martinez`
- **Failure code:** `0x18` (bad password)
- **Source IP:** `192.168.18.70` (Kali/Sandcat agent)
- **Hits:** 28

### Kerberoasting (T1558.003)
- **Event:** 4769, Kerberos service ticket requested
- **Ticket encryption type:** `0x17` (RC4-HMAC, the downgrade signature GetUserSPNs.py forces)
- **Hits:** 2
  <img width="1274" height="734" alt="01-First Rule event 4769" src="https://github.com/user-attachments/assets/bdc57ac5-82af-4ef1-a8ab-ddd98fbac6da" />


### AS-REP Roasting (T1558.004)
- **Event:** 4768, Kerberos authentication ticket (TGT) requested
- **Account targeted:** `j.jenkins`
- **PreAuthType:** `0` (pre-authentication skipped, `UF_DONT_REQUIRE_PREAUTH` set on account)
- **Hits:** 8
<img width="1273" height="705" alt="Event.Code: 4768" src="https://github.com/user-attachments/assets/2b783da9-982c-4f16-a6cb-bc640e56329f" />

### DCSync (T1003.006)
- **Event:** 4662, Directory Service Access
- **Action:** `Directory Service Access`, outcome `success`
- **Host:** `Joshua-Server2022`
- **Hits:** 8
- **Interpretation:** matches a DS-Replication-Get-Changes-All request originating from a non-domain-controller principal.

- 
<img width="1274" height="736" alt="01-Event-4662" src="https://github.com/user-attachments/assets/df8316de-1361-475b-bc34-bc8ba0363c01" />

<img width="1279" height="737" alt="02-Event-4662" src="https://github.com/user-attachments/assets/e8222212-4476-4da0-858b-b73d7c6eab99" />

### LLMNR/NBT-NS Poisoning (T1557.001), Known Gap
See [`llmnr-known-gap.md`](./llmnr-known-gap.md) for full detail. Run manually with Responder rather than through Caldera (no usable Linux-compatible ability exists in Stockpile). No corresponding Sigma rule exists in detection-as-code-repo, and no detections fired, because Sysmon Event IDs 3 (Network Connection) and 22 (DNS Query) are not enabled on the monitored endpoint.
