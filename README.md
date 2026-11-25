# Purple-Team-Automation

By OKUNNUWA JOSHUA GODWIN | [LinkedIn](https://www.linkedin.com/in/okunnuwa-joshua-godwin)

I used [MITRE Caldera](https://github.com/mitre/caldera) to run a chained Active Directory credential-access attack against my own domain lab, then checked whether the detections from my [Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering) repo caught it in Elastic. I also built an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer to show the coverage.

If you only read one file, read the report: [`purple-team-automation-report.md`](purple-team-automation-report.md).

## Correction (25 November 2026)

When I first published this repo, the results table said all four Sigma rules fired. That was wrong, and I want the record to show it.

What I actually checked in September was whether each attack's events reached Elastic, using raw searches like `event.code:4769`. They did. That proves the telemetry was there. It doesn't prove a rule alerted.

In November I went back to Kibana's Rules page to check for real alerts:

- Only one of the four detections had ever been set up as an alerting rule: "DCSync Detected - Replication Rights Abused." The Kerberoasting, AS-REP Roasting and password spray rules existed as Sigma files and KQL queries, but never as rules in Kibana.
- That DCSync rule ran 27 times on 22 September, the day of the operation, and raised 0 alerts.

So no rule alerted during this operation. The tables and heatmap below now say what the evidence supports. The re-test plan is at the bottom of this page.

## What I found

| Technique | Events reached Elastic? | Alerting rule in Kibana? | Alert raised? | Status |
|---|---|---|---|---|
| T1110.003 Password Spraying | Yes, 4771 (28 hits) | No | No | Gap |
| T1558.003 Kerberoasting | Yes, 4769 with RC4 `0x17` (2 hits) | No | No | Not validated |
| T1558.004 AS-REP Roasting | Yes, 4768 with `PreAuthType: 0` (8 hits) | No | No | Not validated |
| T1003.006 DCSync | Yes, 4662 (8 hits) | Yes | No (0 alerts in 27 runs on 22 Sep) | Not validated |
| T1557.001 LLMNR/NBT-NS Poisoning | No | No | No | Gap |

Password spraying is marked as a gap, not just "not validated," because my Sigma rule could not have matched this attack even if it had been deployed. The rule counts failed logons in event 4625. Kerbrute talks Kerberos directly, so a wrong password shows up as event 4771 instead, and 4625 never appears. I found the same blind spot independently in my [Wazuh-SIEM-Lab](https://github.com/joshuagodwin7929/Wazuh-SIEM-Lab), where I fixed it with a 4771 correlation rule.

Full detail and screenshots: [`validation/detection-results.md`](validation/detection-results.md)

## What I can't tell you yet

- Whether my DCSync rule was already enabled when the operation ran, or was created later that day. The rule log shows runs on 22 September but no alerts either way. I still need to check the rule's query and its first run time.
- Whether the other three rules would have caught the attack. They were never running, so this operation says nothing about them.

## What I built

### Infrastructure

I deployed a Caldera server with Docker Compose on its own Ubuntu VM (`caldera-server`, `192.168.18.205`), on the same lab network as the AD domain and separate from the ELK stack. Caldera v5.0.0 came up with 2000 stock abilities and 29 stock adversaries.

Getting there took a few rounds of debugging:

- My first build looked like it finished but produced no image, so I did a clean rebuild.
- The container then crash-looped on a missing compiled Vue frontend (`plugins/magma/dist/assets/`). The cause was a full-directory volume mount in `docker-compose.yml`. It replaced the image's compiled frontend with uncompiled source from the host. Removing that mount fixed it.
- I tried rebuilding the frontend inside the running container. That failed because the Dockerfile deliberately uninstalls `npm` and `nodejs` after the build to keep the image small.
- After login worked, the UI still didn't. The compiled frontend had `localhost:8888` hardcoded as its API address. That value is baked in at build time from `plugins/magma/.env` (`VITE_CALDERA_URL`), and `conf/local.yml` doesn't override it. I set it to the VM's real IP and rebuilt.
- A separate build failed on disk space. The LVM logical volume was only using half the VM's disk. I fixed it with `lvextend -l +100%FREE` and `resize2fs`, then cleared old build layers with `docker system prune -a --volumes`.

### Custom abilities

Caldera's Stockpile plugin only ships a native ability for LSASS credential dumping (T1003.001). Its Kerberoasting abilities (Rubeus, WinPwn) are Windows-only, and my Sandcat agent runs on Kali Linux. So I wrote four custom abilities around Impacket (`GetUserSPNs.py`, `GetNPUsers.py`, `secretsdump.py`) and Kerbrute. They're in [`abilities/`](abilities/).

Two problems came up while writing them:

- I assumed Caldera v5 used a generic regex parser. It doesn't. It uses per-tool parser modules with `source`, `edge` and `target` fields, and my guess caused a silent `TypeError('ParserConfig.__init__()')` on load. There's no built-in parser for raw Impacket output, so I removed the `parsers:` block from all four abilities. Results are captured as raw output.
- Two of the ability files (password spray and DCSync) were saved as 0-byte files after a `nano` paste failed without an error. I caught it by checking every file with `cat` and `wc -l` before restarting the container.

### Agent and operation

I deployed a Sandcat agent on the Kali VM (`192.168.18.70`) in group `red`, running as root under the process name `splunkd`. Then I built the `AD Credential Access Chain` adversary profile ([`adversary-profiles/`](adversary-profiles/)), which runs the four abilities in the order an internal attacker would likely try them:

```
Password Spray (Kerbrute)
  -> Kerberoasting (GetUserSPNs.py)
  -> AS-REP Roasting (GetNPUsers.py)
  -> DCSync (secretsdump.py)
```

I left LLMNR/NBT-NS poisoning (T1557.001) out of the profile. Stockpile's only ability for it uses Inveigh, which is Windows-only. I kept it in the results as a known gap from my earlier manual Responder test. See [`validation/llmnr-known-gap.md`](validation/llmnr-known-gap.md).

## Repo layout

```
abilities/                         The four custom Caldera abilities
adversary-profiles/                The AD Credential Access Chain profile
validation/
  detection-results.md             Per-technique results and evidence
  llmnr-known-gap.md               Why LLMNR poisoning is undetected
  evidence/                        Screenshots, one folder per stage
attack-navigator-heatmap.json      ATT&CK Navigator layer
purple-team-automation-report.md   The full write-up
```

## How to reproduce

> Run this only against a lab you own and are authorised to test.

### Prerequisites

- AD lab: a Windows Server domain controller and a Windows 10 client
- Telemetry: Sysmon and Winlogbeat shipping to Elastic Stack
- Detections: the Sigma rules from [Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering), **deployed as alerting rules in Kibana** (a saved query isn't enough)
- Caldera server: an Ubuntu VM with Docker Compose and Caldera v5.0.0
- Attacker host: a Kali VM with Impacket and Kerbrute

### Steps

1. **Deploy Caldera.** Before building, set `VITE_CALDERA_URL` in `plugins/magma/.env` to the VM's real IP. It's baked in at build time. Don't mount the whole project directory as a volume, or it will overwrite the compiled frontend.
2. **Import the content.** Copy `abilities/` into Caldera's abilities directory and `adversary-profiles/` into its adversaries directory, then restart. Check that AD Credential Access Chain appears under Adversaries.
3. **Deploy the agent.** Deploy a Sandcat (Linux) agent on the Kali VM in group `red`.
4. **Run the operation** with the AD Credential Access Chain adversary against group `red`. Note the start and end time.
5. **Check for alerts, not just events.** In Kibana, open each rule's execution log for the operation window and confirm it raised an alert. Record the alert, not the raw search hit count, in `validation/detection-results.md`. Then update `attack-navigator-heatmap.json`.

## Re-test plan

1. Deploy the Kerberoasting, AS-REP Roasting and password spray detections as alerting rules in Kibana.
2. Fix the password spray rule so it also counts event 4771, not just 4625.
3. Decide what to do about `svc_sql`. The tuned Kerberoasting rule allow-lists it, and it's the account Caldera roasts. Either set the account to AES only and drop the allow-list, or narrow the filter to known legitimate clients.
4. Find out why the DCSync rule raised nothing on 22 September by checking its query, look-back window and first run time.
5. Re-run the operation, screenshot each alert, and update the results and heatmap.

## Credits

Caldera is by MITRE. Impacket is by Fortra. Kerbrute is by ropnop. Everything else in this repo is my own work on my own lab.
