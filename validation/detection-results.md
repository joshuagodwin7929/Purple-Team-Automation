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

### AS-REP Roasting (T1558.004)
- **Event:** 4768, Kerberos authentication ticket (TGT) requested
- **Account targeted:** `j.jenkins`
- **PreAuthType:** `0` (pre-authentication skipped, `UF_DONT_REQUIRE_PREAUTH` set on account)
- **Hits:** 8

### DCSync (T1003.006)
- **Event:** 4662, Directory Service Access
- **Action:** `Directory Service Access`, outcome `success`
- **Host:** `Joshua-Server2022`
- **Hits:** 8
- **Interpretation:** matches a DS-Replication-Get-Changes-All request originating from a non-domain-controller principal.

### LLMNR/NBT-NS Poisoning (T1557.001), Known Gap
See [`llmnr-known-gap.md`](./llmnr-known-gap.md) for full detail. Run manually with Responder rather than through Caldera (no usable Linux-compatible ability exists in Stockpile). No corresponding Sigma rule exists in detection-as-code-repo, and no detections fired, because Sysmon Event IDs 3 (Network Connection) and 22 (DNS Query) are not enabled on the monitored endpoint.
