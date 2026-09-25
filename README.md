# Purple-Team-Automation

Automated purple-team validation of the Sigma detection rules built in
[detection-as-code-repo](../detection-as-code-repo), using
[MITRE Caldera](https://github.com/mitre/caldera) to execute a chained
Active Directory credential-access attack path against an existing domain
lab, and an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
heatmap to visualize coverage.

## Why Caldera over Atomic Red Team

Caldera was chosen over Atomic Red Team for this project because it
provides a full C2 framework, with agents, adversary profiles, and chained multi-step operations, rather than single, isolated technique execution.
This matches the goal of this project more closely: not just "did this one
technique get detected," but "does a realistic, ordered attack *chain*
survive our current detection stack, start to finish."

## Repo structure

```
Purple-Team-Automation/
├── abilities/                          Custom Caldera ability YAMLs
├── adversary-profiles/                 The chained adversary profile used in the operation
├── validation/                         Kibana evidence per technique + the LLMNR known-gap writeup
├── attack-navigator-heatmap.json       ATT&CK Navigator layer, load at mitre-attack.github.io/attack-navigator
├── purple-team-automation-report.md                 Full write-up: scope, methodology, results, gap analysis
└── README.md                           This file
```

## What was built

### Infrastructure
I deployed a dedicated Caldera server via Docker Compose on a separate
Ubuntu VM (`caldera-server`, `192.168.18.205`) on the same lab network as
the existing AD domain lab, keeping it isolated from the ELK/SIEM stack.
Caldera v5.0.0 came up with 2000 stock abilities and 29 stock adversaries
out of the box.

**Build issues I root-caused along the way:**
- My initial build appeared to complete but silently produced no image, so
  I had to do a clean rebuild.
- The container crash-looped on a missing pre-built Vue frontend
  (`plugins/magma/dist/assets/`). I traced this to a full-directory Docker
  volume mount in `docker-compose.yml` overwriting the image's compiled
  frontend with uncompiled host source. Fixed by removing the
  full-directory mount.
- I tried rebuilding the frontend at container runtime, but that failed
  because the Dockerfile deliberately uninstalls `npm`/`nodejs` after the
  image build to keep the final image slim.
- After I finally got login working, the UI was still non-functional. The
  compiled frontend had `localhost:8888` hardcoded as its API base, baked
  in at Vue build time via `plugins/magma/.env` (`VITE_CALDERA_URL`), which
  isn't controlled by `conf/local.yml`'s runtime `app.frontend.api_base_url`
  setting. I fixed it by editing `.env` to the VM's real IP and rebuilding.
- I also hit a separate disk-space failure, which I traced to an LVM
  logical volume only using half of the VM's allocated disk. Fixed with
  `lvextend -l +100%FREE` + `resize2fs`, plus reclaiming build-cache layers
  via `docker system prune -a --volumes`.

### Custom abilities
Stockpile only ships a native ability for LSASS/Mimikatz-based credential
dumping (T1003.001). The four techniques I needed for this project,
Kerberoasting, AS-REP Roasting, Password Spraying, and DCSync, all
required custom abilities that I built around Impacket (`GetUserSPNs.py`,
`GetNPUsers.py`, `secretsdump.py`) and Kerbrute, since Stockpile's existing
Kerberoasting abilities (Rubeus, WinPwn) are Windows/.NET-only and
incompatible with this lab's Linux-based Sandcat agent.

I ran into two build issues while authoring these:
- Caldera v5's real ability schema uses purpose-built per-tool parser
  modules (e.g. `plugins.stockpile.app.parsers.katz`) with
  `source`/`edge`/`target` fields, not a generic regex `pattern` parser as
  I'd originally assumed. This caused a silent
  `TypeError('ParserConfig.__init__()')` on load. Since no built-in parser
  exists for raw Impacket output, I dropped the `parsers:` block entirely
  from all four abilities. Results are captured as raw output/hash files
  and validated manually against Kibana (see `/validation`).
- Two of my ability YAMLs (password spray, DCSync) were initially saved as
  0-byte files after a `nano` paste silently failed. I caught this by
  sanity-checking every file with `cat`/`wc -l` before restarting the
  container.

### Agent deployment
I deployed a Sandcat agent (Linux, group `red`) onto the Kali VM
(`192.168.18.70`), using the process name `splunkd` for OPSEC masquerading,
and confirmed it came up alive and trusted, running as root with the
`proc/sh` executor.

### Adversary profile & operation
I built the `AD Credential Access Chain` adversary profile to chain the
four custom abilities in the order an opportunistic internal attacker
would typically attempt them:

```
Password Spray (Kerbrute)
    → Kerberoasting (GetUserSPNs.py)
    → AS-REP Roasting (GetNPUsers.py)
    → DCSync (secretsdump.py)
```

LLMNR/NBT-NS poisoning (T1557.001) was deliberately excluded from the
Caldera profile. See [`validation/llmnr-known-gap.md`](validation/llmnr-known-gap.md)
for why, and how it's still included as a known-gap negative control.

## Results

All four executed techniques were confirmed detected against
detection-as-code-repo's Sigma rules, cross-checked directly in Kibana.
LLMNR/NBT-NS poisoning remains an open, documented gap.

| Technique | Status |
|---|---|
| T1110.003 – Password Spraying | 🟢 Detected |
| T1558.003 – Kerberoasting | 🟢 Detected |
| T1558.004 – AS-REP Roasting | 🟢 Detected |
| T1003.006 – DCSync | 🟢 Detected |
| T1557.001 – LLMNR/NBT-NS Poisoning | 🔴 Gap |

Full detail: [`validation/detection-results.md`](validation/detection-results.md)
Full write-up: [`purple-team-automation-report.md`](purple-team-automation-report.md)
Interactive heatmap: [`attack-navigator-heatmap.json`](attack-navigator-heatmap.json)

## Next steps

1. Fix Sysmon configuration (enable Event ID 3 and 22) to close the LLMNR gap.
2. Write and tune a new Sigma rule for LLMNR/NBT-NS poisoning.
3. Re-run this operation to confirm the fix and update the heatmap.
4. Feeds into the broader SOC projects roadmap (Project D and beyond).
