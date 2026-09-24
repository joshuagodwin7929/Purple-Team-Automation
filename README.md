# Purple-Team-Automation (Project C)

Automated purple-team validation of the Sigma detection rules built in
[detection-as-code-repo](../detection-as-code-repo), using
[MITRE Caldera](https://github.com/mitre/caldera) to execute a chained
Active Directory credential-access attack path against an existing domain
lab, and an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
heatmap to visualize coverage.

## Why Caldera over Atomic Red Team

Caldera was chosen over Atomic Red Team for this project because it
provides a full C2 framework — agents, adversary profiles, and chained
multi-step operations — rather than single, isolated technique execution.
This matches the goal of this project more closely: not just "did this one
technique get detected," but "does a realistic, ordered attack *chain*
survive our current detection stack, start to finish."

## Repo structure

```
Purple-Team-Automation/
├── abilities/                          Custom Caldera ability YAMLs
├── adversary-profiles/                 The chained adversary profile used in the operation
├── validation/                         Kibana evidence per technique + the LLMNR known-gap writeup
├── attack-navigator-heatmap.json       ATT&CK Navigator layer — load at mitre-attack.github.io/attack-navigator
├── project-c-report.md                 Full write-up: scope, methodology, results, gap analysis
└── README.md                           This file
```

## What was built

### Infrastructure
A dedicated Caldera server was deployed via Docker Compose on a separate
Ubuntu VM (`caldera-server`, `192.168.18.205`) on the same lab network as
the existing AD domain lab, kept isolated from the ELK/SIEM stack. Caldera
v5.0.0 was deployed with 2000 stock abilities and 29 stock adversaries out
of the box.

**Build issues root-caused along the way:**
- An initial build appeared to complete but silently produced no image,
  requiring a clean rebuild.
- The container crash-looped on a missing pre-built Vue frontend
  (`plugins/magma/dist/assets/`) — caused by a full-directory Docker volume
  mount in `docker-compose.yml` overwriting the image's compiled frontend
  with uncompiled host source. Fixed by removing the full-directory mount.
- Rebuilding the frontend at container runtime failed, because the
  Dockerfile deliberately uninstalls `npm`/`nodejs` after the image build
  to keep the final image slim.
- After login succeeded, the UI was non-functional because the compiled
  frontend had `localhost:8888` hardcoded as its API base — baked in at
  Vue build time via `plugins/magma/.env` (`VITE_CALDERA_URL`), which is
  **not** controlled by `conf/local.yml`'s runtime `app.frontend.api_base_url`
  setting. Fixed by editing `.env` to the VM's real IP and rebuilding.
- A separate disk-space failure was traced to an LVM logical volume only
  using half of the VM's allocated disk (`lvextend -l +100%FREE` +
  `resize2fs`), plus reclaiming build-cache layers via
  `docker system prune -a --volumes`.

### Custom abilities
Stockpile only ships a native ability for LSASS/Mimikatz-based credential
dumping (T1003.001). The four techniques this project needed —
Kerberoasting, AS-REP Roasting, Password Spraying, and DCSync — all
required custom abilities built around Impacket (`GetUserSPNs.py`,
`GetNPUsers.py`, `secretsdump.py`) and Kerbrute, since Stockpile's existing
Kerberoasting abilities (Rubeus, WinPwn) are Windows/.NET-only and
incompatible with this lab's Linux-based Sandcat agent.

Two build issues came up while authoring these:
- Caldera v5's real ability schema uses purpose-built per-tool parser
  modules (e.g. `plugins.stockpile.app.parsers.katz`) with
  `source`/`edge`/`target` fields — not a generic regex `pattern` parser as
  initially assumed. This caused a silent `TypeError('ParserConfig.__init__()')`
  on load. Since no built-in parser exists for raw Impacket output, the
  `parsers:` block is omitted entirely from all four abilities — results
  are captured as raw output/hash files and validated manually against
  Kibana (see `/validation`).
- Two ability YAMLs (password spray, DCSync) were initially saved as
  0-byte files after a `nano` paste silently failed. Caught by
  `cat`/`wc -l` sanity-checking every file before restarting the container.

### Agent deployment
A Sandcat agent (Linux, group `red`) was deployed onto the Kali VM
(`192.168.18.70`) using process name `splunkd` for OPSEC masquerading, and
confirmed alive/trusted, running as root with the `proc/sh` executor.

### Adversary profile & operation
The `AD Credential Access Chain` adversary profile chains the four custom
abilities in the order an opportunistic internal attacker would typically
attempt them:

```
Password Spray (Kerbrute)
    → Kerberoasting (GetUserSPNs.py)
    → AS-REP Roasting (GetNPUsers.py)
    → DCSync (secretsdump.py)
```

LLMNR/NBT-NS poisoning (T1557.001) was deliberately excluded from the
Caldera profile — see [`validation/llmnr-known-gap.md`](validation/llmnr-known-gap.md)
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
Full write-up: [`project-c-report.md`](project-c-report.md)
Interactive heatmap: [`attack-navigator-heatmap.json`](attack-navigator-heatmap.json)

## Next steps

1. Fix Sysmon configuration (enable Event ID 3 and 22) to close the LLMNR gap.
2. Write and tune a new Sigma rule for LLMNR/NBT-NS poisoning.
3. Re-run this operation to confirm the fix and update the heatmap.
4. Feeds into the broader SOC projects roadmap (Project D and beyond).
