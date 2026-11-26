# Purple-Team-Automation

By OKUNNUWA JOSHUA GODWIN | [LinkedIn](https://www.linkedin.com/in/okunnuwa-joshua-godwin)

I used [MITRE Caldera](https://github.com/mitre/caldera) to run a chained Active Directory credential-access attack against my own domain lab, then checked whether the detections from my [Detection-Engineering](https://github.com/joshuagodwin7929/Detection-Engineering) repo caught it in Elastic. I also built an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer to show the coverage.

If you only read one file, read the report: [`purple-team-automation-report.md`](purple-team-automation-report.md).

## Results

I ran a four-step Active Directory credential-access chain through Caldera and confirmed each step raised a real alert in Kibana:

| Technique | Status | Alert (UTC) |
|---|---|---|
| T1110.003 Password Spraying | ✅ Alert | 25 Nov 2026, 23:31:07 |
| T1558.003 Kerberoasting | ✅ Alert | 25 Nov 2026, 04:58:45 |
| T1558.004 AS-REP Roasting | ✅ Alert | 25 Nov 2026, 05:02:06 |
| T1003.006 DCSync | ✅ Alert | 25 Nov 2026, 03:45:33 |
| T1557.001 LLMNR/NBT-NS Poisoning | ❌ Gap: no telemetry | n/a |

Rule definitions: [`validation/kibana-rules.md`](validation/kibana-rules.md). Evidence and full detail: [`validation/detection-results.md`](validation/detection-results.md).

## What I got wrong first, and how I found it

When I first published this repo in September, it said all four Sigma rules fired. They hadn't. What I'd actually checked was whether each attack's events reached Elastic, using raw searches like `event.code:4769`. That proves the telemetry exists. It doesn't prove a rule alerted.

In November I went back to Kibana's Rules page. Only one detection, DCSync, had ever been deployed as an alerting rule, and it had raised 0 alerts in 57 runs. The other three only existed as Sigma files and saved queries.

Fixing that turned up six separate problems in my lab. Each one alone was enough to stop an alert:

1. **The DCSync query could never match.** It used a wildcard on the `message` field, which Elasticsearch splits into words at every hyphen, so a hyphenated GUID never matches. Old query: 0 hits. Phrase query: 2 hits.
2. **The September events reached Elastic 35 minutes late,** after the rule's 5-minute window had already passed them.
3. **Two copies of Winlogbeat were running,** a service and an older copy from July, so every event was shipped twice.
4. **Winlogbeat was set to Manual,** so it stayed stopped after a reboot.
5. **Kibana stopped running rules for 45 minutes** while the ELK VM was paused.
6. **The password spray rule grouped on a field that's empty on 4771 events,** so it had nothing to count.

I fixed each one and re-ran the attacks until every technique alerted. The detail and evidence for each is in [`validation/detection-results.md`](validation/detection-results.md#what-went-wrong-in-september-and-what-i-fixed).

The main thing I took from this: a detection isn't coverage until it's deployed, running and has alerted on the real attack. A search that finds the events is a hunt, not a detection.

## What I can't tell you yet

- **Whether the tuned AS-REP rule alerts as well as it searches.** The original rule also fired on normal logons by `j.jenkins`, which has pre-authentication disabled on purpose. I confirmed that and found a filter that keeps the attack and drops the noise ([details](validation/detection-results.md#as-rep-roasting-t1558004)), but so far I've only tested it against recorded events in Discover.
- **Which host is spraying.** The password spray rule counts failures across the whole domain, because I couldn't group by source IP (problem 6). That's fine with one attacker in a lab, but not in production.
- **Whether these rules hold up under real traffic.** My lab has a handful of users and almost no background noise.

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
  detection-results.md             Per-technique results, findings and evidence
  kibana-rules.md                  The four Kibana alerting rules
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
- Detections: the four Kibana alerting rules in [`validation/kibana-rules.md`](validation/kibana-rules.md). A saved query isn't enough; it has to be an enabled rule.
- Winlogbeat on the DC running as a service with startup type Automatic, and only one copy running
- Caldera server: an Ubuntu VM with Docker Compose and Caldera v5.0.0
- Attacker host: a Kali VM with Impacket and Kerbrute

### Steps

1. **Deploy Caldera.** Before building, set `VITE_CALDERA_URL` in `plugins/magma/.env` to the VM's real IP. It's baked in at build time. Don't mount the whole project directory as a volume, or it will overwrite the compiled frontend.
2. **Import the content.** Copy `abilities/` into Caldera's abilities directory and `adversary-profiles/` into its adversaries directory, then restart. Check that AD Credential Access Chain appears under Adversaries.
3. **Deploy the agent.** Deploy a Sandcat (Linux) agent on the Kali VM in group `red`.
4. **Run the operation** with the AD Credential Access Chain adversary against group `red`. Note the start and end time.
5. **Check for alerts, not just events.** Wait 10 to 15 minutes, then open the rules Logs tab for the operation window and confirm each rule raised an alert. Keep the host awake the whole time, because a paused ELK VM stops every rule.

## Next steps

1. ~~Confirm the `j.jenkins` explanation for the extra AS-REP alerts.~~ Done: confirmed, and the rule tuned on `SessionKeyEncryptionType` ([details](validation/detection-results.md#as-rep-roasting-t1558004)). Still to do: add the condition to the Kibana rule and get a fresh alert.
2. Fix the source IP field so the password spray rule can group by attacker and count distinct usernames.
3. ~~Bring the Sigma rules in Detection-Engineering in line with the deployed rules.~~ Done in [Detection-Engineering v0.3.0](https://github.com/joshuagodwin7929/Detection-Engineering/blob/main/CHANGELOG.md), which also added CI.
4. Enable Sysmon Event IDs 3 and 22 and build the LLMNR rule.

DCSync ran in the same Caldera operation as the other three, about 70 minutes earlier, as a standalone test. Caldera's planner didn't run it again when the rest of the chain continued, so its alert comes from that first run.

## Credits

Caldera is by MITRE. Impacket is by Fortra. Kerbrute is by ropnop. Everything else in this repo is my own work on my own lab.
