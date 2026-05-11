# SOC Lab 

![Wazuh](https://img.shields.io/badge/Wazuh-4.14.5-blue?style=flat-square)
![TheHive](https://img.shields.io/badge/TheHive-5.2-orange?style=flat-square)
![Cortex](https://img.shields.io/badge/Cortex-3.1-orange?style=flat-square)
![Shuffle](https://img.shields.io/badge/Shuffle-SOAR-red?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)
![Sysmon](https://img.shields.io/badge/Sysmon-Windows-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

A local, hands-on Security Operations Centre lab built on VirtualBox. Built from the ground up — starting with raw log collection and working up through detection engineering, correlation, noise reduction, reporting, and full SOAR automation.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Host: Windows 11 (MSI)                      │
│                     32GB RAM, VirtualBox                        │
│                                                                 │
│   ┌──────────────────────┐      ┌──────────────────────┐        │
│   │    Ubuntu 24.04      │      │     Kali Linux       │        │
│   │  Wazuh + TheHive     │      │  Attacker / Analyst  │        │
│   │  Cortex + Shuffle    │      │                      │        │
│   │  192.168.56.10       │      │  192.168.56.20       │        │
│   │  15GB RAM            │      │  6GB RAM             │        │
│   └──────────┬───────────┘      └──────────┬───────────┘        │
│              │                             │                    │
│              └──────────────┬──────────────┘                    │
│                             │  Host-Only Network                │
│                    192.168.56.0/24                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                    Bridged Adapter
                              │
              ┌───────────────┴───────────────┐
              │     Windows 11 (MSI Laptop)   │
              │     Wazuh Agent + Sysmon      │
              │     192.168.0.25              │
              │     Physical Machine          │
              └───────────────────────────────┘
```

| Machine | Role | IP | RAM | Network |
|---|---|---|---|---|
| Ubuntu 24.04 (VM) | Wazuh + TheHive + Cortex + Shuffle | 192.168.56.10 | 15GB | Host-Only |
| Kali Linux (VM) | Attacker / Analyst workstation | 192.168.56.20 | 6GB | Host-Only |
| Windows 10 (VM) | Victim endpoint — Wazuh agent | 192.168.56.30 | 4GB | Host-Only |
| Windows 11 MSI (Physical) | Second victim — Wazuh agent | 192.168.0.25 | — | Bridged |

---

## Phases

| # | Phase | Summary | Doc |
|---|---|---|---|
| 1 | **Infrastructure** | Wazuh all-in-one, agents, Sysmon, log channels | [phase1-setup.md](docs/phase1-setup.md) |
| 2 | **Normalisation** | 12 custom detection rules mapped to MITRE ATT&CK | [phase2-normalisation.md](docs/phase2-normalisation.md) |
| 3 | **Correlation** | Frequency rules — brute force, recon chain, persistence chain | [phase3-correlation.md](docs/phase3-correlation.md) |
| 4 | **Aggregation** | Noise suppression — false positive investigation and surgical suppression | [phase4-aggregation.md](docs/phase4-aggregation.md) |
| 5 | **Reporting** | OpenSearch dashboards — attack overview and security posture | [phase5-reporting.md](docs/phase5-reporting.md) |
| 6 | **SOAR** | Wazuh → Shuffle → TheHive pipeline with Cortex enrichment | [phase6-soar.md](docs/phase6-soar.md) |

---

## Phase 1 — Infrastructure

### What was built

- Ubuntu 24.04 VM running Wazuh 4.14.5 all-in-one (manager + indexer + dashboard)
- Kali Linux as the analyst workstation — accesses the dashboard at `https://192.168.56.10`
- Windows 10 VM with Wazuh agent pointing at the manager
- Sysmon installed with SwiftOnSecurity config — deep telemetry across process creation, network connections, registry modifications, file drops
- Log collection configured: Security, System, Application, and Sysmon/Operational channels
- Agent verified Active with events flowing into the dashboard

### What is Sysmon?

Sysmon (System Monitor) is a free Microsoft tool that logs what every process does after it starts — command lines, network connections, registry changes, DLL loads, file drops. Standard Windows Event Logs tell you who logged in. Sysmon tells you what happened next.

![Wazuh Dashboard](assets/wazuh.png)

![Agent Active](assets/WazuhAgentActivate.png)

→ Full setup guide: [docs/phase1-setup.md](docs/phase1-setup.md)

---

## Phase 2 — Normalisation

### How detection works

Every log flowing into Wazuh goes through two stages:

1. **Decoder** — parses the raw log and extracts structured fields (`win.eventdata.image`, `win.eventdata.commandLine`, etc.)
2. **Rules engine** — checks every rule against those fields and fires alerts on matches

Rules are written in XML and stored in `/var/ossec/etc/rules/local_rules.xml`.

**Key gotcha:** The dashboard shows fields with a `data.` prefix (`data.win.eventdata.image`). Rules reference the same fields **without** the prefix (`win.eventdata.image`). Wrong prefix = silent failure — the rule loads but never fires.

### Custom rules written

| Rule ID | Category | Detects | MITRE |
|---|---|---|---|
| 100001 | Execution | PowerShell encoded commands | T1059.001 |
| 100002 | Execution | LOLBins loading remote content | T1218 |
| 100003 | Execution | WMI execution | T1047 |
| 100004 | Execution | Shell spawned from Office | T1204.002 |
| 100100 | Persistence | Service ImagePath registry modification | T1031, T1050 |
| 100101 | Persistence | Registry Run key modification | T1547.001 |
| 100102 | Persistence | Scheduled task creation | T1053.005 |
| 100200 | Credential Access | LSASS process access | T1003.001 |
| 100300 | Discovery | Recon commands (whoami, net, ipconfig) | T1082, T1033 |
| 100301 | Discovery | Outbound connections to attack ports | T1046 |
| 100400 | Defense Evasion | CreateRemoteThread injection | T1055 |
| 100401 | Defense Evasion | PowerShell evasion flags | T1059.001 |

Rules source: [config/wazuh/local_rules.xml](config/wazuh/local_rules.xml)

![Custom Rule Alert Firing](assets/LocalRuleAlert.png)

![Local Rules XML](assets/LocalRules.png)

→ Full breakdown: [docs/phase2-normalisation.md](docs/phase2-normalisation.md)

---

## Phase 3 — Correlation

### How correlation works

Phase 2 rules fire on individual events. Phase 3 rules fire on **patterns** — bursts and chains of events that individually look benign but together signal an attack.

Wazuh frequency rules count how many times a parent rule fires within a time window. When the threshold is hit, a single high-severity correlation alert fires.

Key XML elements:
- `frequency` + `timeframe` — N hits within T seconds
- `if_matched_sid` — chain off one specific rule
- `if_matched_group` — chain off any rule in a named group
- `same_field` — scope the count to one attacker or user

### Correlation rules written

| Rule | Level | Detects | MITRE |
|---|---|---|---|
| 100500 | 14 | 10+ failed logons from same IP in 60s | T1110.001 |
| 100600 | 12 | 3+ recon commands by same user in 60s | T1082, T1033 |
| 100601 | 14 | 2+ persistence techniques by same user in 120s | T1053.005, T1547.001 |

### Full kill chain test

All three chains confirmed firing in a single session:

```
Brute Force  →  Kali (Metasploit smb_login) → Windows 10:445    → rule 100500 [level 14]
Recon        →  whoami, ipconfig, net user, systeminfo            → rule 100600 [level 12]
Persistence  →  schtasks /create + reg add Run key               → rule 100601 [level 14]
```

![Brute Force Running](assets/BruteForce.png)

![Correlation Rule Firing](assets/CorrelationRuleTrigger.png)

![Recon Chain Alert](assets/ReconAlert.png)

→ Full breakdown: [docs/phase3-correlation.md](docs/phase3-correlation.md)

---

## Phase 4 — Aggregation

### How aggregation works

Aggregation cuts alert volume so analysts only see what is actionable. The approach: identify the highest-volume rules, investigate what's actually triggering them, then suppress known-good activity surgically — not with blanket silencing.

Core technique: `level="0"` + `<options>no_log</options>` — the alert is completely discarded before it reaches the dashboard or logs.

### Key finding — level 15 false positive storm

Rule 92213 ("Executable file dropped in folder commonly used by malware") fired **112 times at level 15 (critical)**. Every hit came from `cleanmgr.exe` — Windows Disk Cleanup extracts 20+ DLLs into Temp each run. An analyst seeing 112 critical alerts would spend hours investigating Disk Cleanup, or start ignoring level 15 entirely.

### Suppression rules written

| Rule | Suppresses | Type |
|---|---|---|
| 100700 | cleanmgr.exe / OneDrivePatcher.exe dropping in Temp (rule 92213) | Selective |
| 100701 | All Ubuntu dpkg package installs (rule 2902) | Blanket |
| 100702 | All Ubuntu dpkg half-configured events (rule 2904) | Blanket |
| 100703 | svchost.exe DLL activity in Windows root (rule 92219) | Selective |
| 100704 | OneDrive outbound connections on common ports (rule 100301) | Selective |

Rule 100704 fixed a false positive in our own Phase 2 rule — 100301 was detecting outbound connections to attack ports, but firing on OneDrive syncing to port 443. Fixed with a CDB list of trusted processes at `/var/ossec/etc/lists/trusted-outbound-processes`.

![False Positive Investigation](assets/FalsePositive.png)

![Trusted Processes CDB List](assets/TrustedProcessesList.png)

→ Full breakdown: [docs/phase4-aggregation.md](docs/phase4-aggregation.md)

---

## Phase 5 — Reporting

### Dashboards built

**Attack Overview** — what happened, when, and which MITRE techniques were used
- Alert timeline by severity (date histogram)
- MITRE tactics distribution (pie chart)
- Total alerts and correlation rule hits (metrics)
- Top rules by alert count (data table)

**Security Posture** — vulnerability exposure and compliance failures
- Active CVEs on Windows 10 (data table)
- Total CVE count and SCA failure count (metrics)
- Top SCA compliance failures (horizontal bar)
- SCA pass/fail distribution (pie chart)

### Key findings

- **324 total alerts** over the lab period with **12 correlation rule hits**
- **457 high severity CVEs** on unpatched Windows 10 — all CVE-2025-* series
- **420 SCA compliance failures** — primarily SSH configuration gaps on the Ubuntu manager
- Defense Evasion is the dominant MITRE tactic across all lab activity

![Attack Overview Dashboard](assets/Dashboard.png)

![Security Posture Dashboard](assets/Dashboard2.png)

→ Full breakdown: [docs/phase5-reporting.md](docs/phase5-reporting.md)

---

## Phase 6 — SOAR

### What was built

- Wazuh webhook integration forwards alerts to Shuffle in real time
- Shuffle workflow filters low-severity noise, maps Wazuh severity (0–3) to TheHive severity (1–4), and creates enriched alerts in TheHive automatically
- TheHive 5 with a dedicated SOCLab organisation and `analyst@soclab.local` as the Shuffle service account
- Cortex 3 connected to TheHive — VirusTotal and Abuse_Finder analyzers running as Docker containers, callable with one click from any case observable
- Second victim endpoint: Windows 11 MSI laptop (physical machine, bridged adapter) enrolled as a Wazuh agent

### The pipeline

```
Attack on endpoint
      ↓
Wazuh detects (rule fires)
      ↓
Shuffle receives webhook
      ↓  filter: severity < 2 → skip
      ↓  enrich: map severity, build description, tag rule ID
TheHive alert created (201)
      ↓
Analyst triages in TheHive
      ↓
Promote alert → Case
      ↓
Add observable → Run Cortex analyzer
      ↓
VirusTotal / Abuse_Finder results inline
```

### Severity mapping

| Wazuh severity | TheHive severity | Label |
|---|---|---|
| 0 | 1 | Low |
| 1 | 2 | Medium |
| 2 | 3 | High |
| 3 | 4 | Critical |

![SOAR Workflow — Webhook → Build Alert → TheHive](assets/Workflow2.png)

![TheHive — Enriched Critical Alerts with Rule Tags](assets/HiveSevereAlert.png)

![Cortex Analyzer Results on Observable](assets/AnalyserReport.png)

→ Full breakdown: [docs/phase6-soar.md](docs/phase6-soar.md)

---

## Quick Start

```powershell
# Start the lab (from Windows host)
python automation/start_lab.py

# Stop the lab
python automation/stop_lab.py
```

See [automation/README.md](automation/README.md) for full details.

---

## Tech Stack

| Tool | Version | Purpose |
|---|---|---|
| Wazuh | 4.14.5 | SIEM — detection, correlation, alerting |
| Sysmon | Latest | Deep Windows endpoint telemetry |
| SwiftOnSecurity Sysmon Config | Latest | Tuned Sysmon ruleset |
| Shuffle | Latest | SOAR — automated alert routing |
| TheHive | 5.2.x | Case management and analyst workspace |
| Cortex | 3.1.x | Observable enrichment engine |
| VirtualBox | 7.x | Hypervisor |
| Ubuntu | 24.04 LTS | Server OS |
| Kali Linux | Latest | Attacker / analyst workstation |
| Windows 10 | Pro | Victim endpoint (VM) |
| Windows 11 | Home | Second victim endpoint (physical) |

---

## References

- [Sigma Rules](https://github.com/SigmaHQ/sigma) — detection rules used as reference when writing custom Wazuh rules
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) — tuned Sysmon ruleset
- [Wazuh Documentation](https://documentation.wazuh.com) — official docs
- [MITRE ATT&CK](https://attack.mitre.org) — threat framework used to tag all custom rules
