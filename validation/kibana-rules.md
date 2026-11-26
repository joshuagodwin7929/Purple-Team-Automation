# Kibana Alerting Rules Used in the Re-test

These are the four rules as deployed in Kibana for the November 2026 re-test. All four are Elasticsearch query rules, created under **Stack Management > Rules > Create rule > Elasticsearch query > KQL or Lucene**.

## Settings shared by all four

| Setting | Value |
|---|---|
| Data view | `winlogbeat-*` |
| WHEN | `count()` |
| FOR THE LAST | 15 minutes |
| SIZE | 100 |
| Exclude matches from previous runs | On |
| Check every | 5 minutes |
| Action | Server log, for each alert, on status changes, run when query matched |

I use a 15-minute look-back with a 5-minute schedule so a few minutes of ingest delay doesn't cause a miss. See finding 2 in [`detection-results.md`](detection-results.md).

Action message:

```
{{rule.name}} fired.
Matched events: {{context.value}}
Condition: {{context.conditions}} over {{rule.params.timeWindowSize}} {{rule.params.timeWindowUnit}}
Time: {{context.date}}
```

## 1. DCSync Detected - Replication Rights Abused

| Setting | Value |
|---|---|
| Tags | `DCSync`, `T1003.006` |
| OVER | all documents |
| IS ABOVE | 0 |
| Action level | Critical |

```
event.code:4662 and message:"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" and not winlog.event_data.SubjectUserName:*$
```

`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` is the GUID of the DS-Replication-Get-Changes-All extended right. The GUID must be searched as a quoted phrase. A wildcard search like `message:*1131f6ad-...*` never matches, because `message` is a text field and the hyphens split the GUID into separate tokens (finding 1).

## 2. Kerberoasting - RC4 Service Ticket Request

| Setting | Value |
|---|---|
| Tags | `Kerberoasting`, `T1558.003` |
| OVER | all documents |
| IS ABOVE | 0 |
| Action level | Warning |

```
event.code:4769 and winlog.event_data.TicketEncryptionType:"0x17" and not winlog.event_data.ServiceName:(krbtgt or *$)
```

This deployed rule has no allow-list for `svc_sql`. The Sigma rule in Detection-Engineering v0.2.0 does, and that allow-list would hide this exact attack. The Sigma rule needs to be brought in line.

## 3. AS-REP Roasting - No Pre-Authentication

| Setting | Value |
|---|---|
| Tags | `AS-REP-Roasting`, `T1558.004` |
| OVER | all documents |
| IS ABOVE | 0 |
| Action level | Warning |

```
event.code:4768 and winlog.event_data.PreAuthType:"0"
```

## 4. Password Spray - Kerberos Pre-Auth Failures

| Setting | Value |
|---|---|
| Tags | `Password-Spray`, `T1110.003` |
| OVER | all documents |
| IS ABOVE | 5 |
| Action level | Warning |

```
event.code:4771
```

I first grouped this rule by source IP. It never fired, because the fields I could group on (`winlog.event_data.IpAddress`, `source.address`) are empty on these 4771 events, and `source.ip` is an IP-type field that this rule type won't group on (finding 6). Counting across all documents works in a one-attacker lab, but in production it can't name the source and normal mistyped passwords could add up. The proper fix is an ingest pipeline that copies the client IP into a keyword field, or a rule type that can count distinct usernames per IP.
