# SOC Lab V2

A local, hands-on Security Operations Centre lab built on VirtualBox. The focus is on going deep on Wazuh — log collection, normalisation, correlation, aggregation, and reporting — before layering SOAR and case management on top.

This is the successor to [SOC-Automation-Lab](https://github.com/Rameez-03/SOC-Automation-Lab), which was cloud-hosted with Shuffle + TheHive. This version is local-first and prioritises SIEM depth over breadth.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Host: Windows 11                   │
│                  32GB RAM, VirtualBox               │
│                                                     │
│  ┌─────────────────┐      ┌─────────────────┐       │
│  │  Ubuntu 24.04   │      │   Kali Linux    │       │
│  │  Wazuh Manager  │      │ Attacker/Analyst│       │
│  │  192.168.56.10  │      │  192.168.56.20  │       │
│  │  8GB RAM        │      │  6GB RAM        │       │
│  └────────┬────────┘      └────────┬────────┘       │
│           │                        │                │
│           └──────────┬─────────────┘                │
│                      │ Host-Only Network            │
│              192.168.56.0/24                        │
│                      │                              │
│           ┌──────────┘                              │
│           │                                         │
│  ┌────────┴────────┐                                │
│  │   Windows 10    │                                │
│  │  Wazuh Agent    │                                │
│  │    + Sysmon     │                                │
│  │  192.168.56.30  │                                │
│  │  4GB RAM        │                                │
│  └─────────────────┘                                │
└─────────────────────────────────────────────────────┘
```

| VM | Role | IP | RAM |
|---|---|---|---|
| Ubuntu 24.04 | Wazuh Manager + Indexer + Dashboard | 192.168.56.10 | 8GB |
| Kali Linux | Attacker / Analyst workstation | 192.168.56.20 | 6GB |
| Windows 10 | Victim / Wazuh Agent | 192.168.56.30 | 4GB |

**Network:** VirtualBox Host-Only (`192.168.56.0/24`)
**Dashboard:** `https://192.168.56.10` (accessed from Kali browser)

---

## Phases

| Phase | Focus | Status |
|---|---|---|
| 1 | Infrastructure — Wazuh + agent + Sysmon | ✅ Complete |
| 2 | Normalisation — custom detection rules | ✅ Complete |
| 3 | Correlation — multi-event attack chains | ✅ Complete |
| 4 | Aggregation — noise reduction | ✅ Complete |
| 5 | Reporting — attack scenario dashboards | ✅ Complete |
| 6 | SOAR — Wazuh → Shuffle → TheHive + Cortex enrichment | ✅ Complete |

---

## Quick Start

```powershell
# Start the lab (Windows host)
python automation/start_lab.py

# Stop the lab
python automation/stop_lab.py
```

Starts Ubuntu headless → waits for Wazuh → starts Windows 10 → starts Kali. Full details in [automation/README.md](automation/README.md).

---

## Phase 1 — Infrastructure

See [docs/phase1-setup.md](docs/phase1-setup.md) for the full setup guide.

### What was built

- Ubuntu 24.04 VM running Wazuh 4.14.5 all-in-one (manager + indexer + dashboard)
- Kali Linux as the analyst workstation — accesses the dashboard at `https://192.168.56.10`
- Windows 10 VM with Wazuh agent pointing at the manager
- Sysmon installed on Windows 10 with SwiftOnSecurity config
- Log collection configured: Security, System, Application, and Sysmon/Operational channels
- Agent verified Active with events flowing into the dashboard

### What is Sysmon?

Sysmon (System Monitor) is a free Microsoft tool that provides deep visibility into Windows activity. Standard Windows Event Logs tell you who logged in. Sysmon tells you what every process did after that — process creation with full command lines, network connections, registry modifications, file drops, DLL loads, and more.

The SwiftOnSecurity config suppresses known-good Windows noise and keeps the security-relevant events.

### Screenshots

**Wazuh Dashboard**
![Wazuh Dashboard](assets/wazuh.png)

**Agent Active**
![Agent Active](assets/WazuhAgentActivate.png)

**Agents Overview**
![Agents](assets/WazuhAgents.png)

**Wazuh Configured**
![Wazuh Configured](assets/WazuhConfigured.png)

**Agent Config (ossec.conf)**
![Agent Config](assets/AgentConfig.png)

---

## Phase 2 — Normalisation

See [docs/phase2-normalisation.md](docs/phase2-normalisation.md) for the full breakdown.

### How detection works

Every log that flows into Wazuh goes through two stages:

1. **Decoder** — parses the raw log and extracts structured fields (`win.eventdata.image`, `win.eventdata.commandLine`, etc.)
2. **Rules engine** — checks every rule against those fields and fires alerts on matches

Rules are written in XML and stored in `/var/ossec/etc/rules/local_rules.xml`. Any agent can trigger any rule — rules are global, not per-machine.

### Key lesson learned

The dashboard shows fields with a `data.` prefix (`data.win.eventdata.image`). Rules reference the same fields **without** the `data.` prefix (`win.eventdata.image`). Using the wrong prefix causes silent rule failures — the rule loads but never fires.

Always verify field names by reading the built-in rules:
```bash
sudo grep -r "field name" /var/ossec/ruleset/rules/0800-sysmon_id_1.xml | head -20
```

### How to write rules (analyst workflow)

```
1. Identify the attack technique
2. Find the Sigma rule → github.com/SigmaHQ/sigma
3. Run the attack in the lab, find the raw log in Wazuh
4. Confirm field names by reading built-in rules
5. Write the Wazuh rule (strip data. prefix from field names)
6. Test with: sudo /var/ossec/bin/wazuh-logtest
7. Trigger the attack again — confirm the alert fires
```

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

### Screenshots

**Nmap scan from Kali against Windows 10**
![Scan](assets/Scan.png)

**Threat Hunting — events from agent**
![Agent Threat](assets/AgentThreat.png)

**Expanded event showing decoded fields**
![Event Data](assets/EventData.png)

**local_rules.xml — custom rules**
![Local Rules](assets/LocalRules.png)

**wazuh-logtest — rule validation**
![Rule Test](assets/RuleTest.png)

**Custom rule firing in dashboard**
![New Rule Trigger](assets/NewRuleTrigger.png)

**Custom rule alert — rule 100300**
![Local Rule Alert](assets/LocalRuleAlert.png)

### Verified working

Rule 100300 confirmed firing on live events from Windows 10:

```
Discovery: Recon command executed - C:\Windows\System32\whoami.exe  [rule:100300, level:6]
Discovery: Recon command executed - C:\Windows\System32\net.exe     [rule:100300, level:6]
Discovery: Recon command executed - C:\Windows\System32\net1.exe    [rule:100300, level:6]
```

---

## Phase 3 — Correlation

See [docs/phase3-correlation.md](docs/phase3-correlation.md) for the full breakdown.

### How correlation works

Phase 2 rules fire on individual events. Phase 3 rules fire on **patterns** — bursts and chains of events that individually look benign but together signal an attack in progress.

Wazuh frequency rules count how many times a parent rule fires within a time window. When the threshold is hit, a single high-severity correlation alert fires.

Key elements:
- `frequency` + `timeframe` — N hits within T seconds
- `if_matched_sid` — chain off one specific rule
- `if_matched_group` — chain off any rule in a named group (catches technique combinations)
- `same_field` — scope the count to one attacker or user, preventing false positives

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

### Screenshots

**Metasploit brute force running**
![Brute Force](assets/BruteForce.png)

**4625 events flowing into Wazuh**
![Metasploit Alert](assets/MetasploitAlert.png)

**Rule 100500 — Brute Force correlation firing**
![Correlation Rule Trigger](assets/CorrelationRuleTrigger.png)

**Rule 100600 — Recon chain firing**
![Recon Alert](assets/ReconAlert.png)

**Persistence commands on Windows 10**
![Persistence Attack](assets/PersistenceAttack.png)

**Rule 100601 — Persistence chain firing**
![Persistence Alert](assets/PersistenceAlert.png)

---

## Phase 4 — Aggregation

See [docs/phase4-aggregation.md](docs/phase4-aggregation.md) for the full breakdown.

### How aggregation works

Aggregation cuts alert volume so analysts only see what is actionable. The approach is to identify the highest-volume rules, investigate what's actually triggering them, and suppress known-good activity — surgically, not with blanket silencing.

The core technique: `level="0"` + `<options>no_log</options>` — the alert is completely discarded before it reaches the dashboard or logs.

### Key finding — alert fatigue from level 15 false positive

Rule 92213 ("Executable file dropped in folder commonly used by malware") fired **112 times at level 15 (critical)**. Every single hit came from `cleanmgr.exe` — Windows Disk Cleanup extracts 20+ DLLs into Temp each run, each triggering a separate critical alert. An analyst investigating these would waste hours on Disk Cleanup, or start ignoring level 15 alerts entirely.

### Suppression rules written

| Rule | Suppresses | Type |
|---|---|---|
| 100700 | cleanmgr.exe / OneDrivePatcher.exe dropping in Temp (rule 92213) | Selective |
| 100701 | All Ubuntu dpkg package installs (rule 2902) | Blanket |
| 100702 | All Ubuntu dpkg half-configured events (rule 2904) | Blanket |
| 100703 | svchost.exe DLL activity in Windows root (rule 92219) | Selective |
| 100704 | OneDrive outbound connections on common ports (rule 100301) | Selective |

Rule 100704 fixed a false positive in our own Phase 2 rule — 100301 was correctly detecting outbound connections to attack ports, but firing on OneDrive syncing to port 443. Fixed with a CDB list of trusted processes at `/var/ossec/etc/lists/trusted-outbound-processes`.

### Screenshots

**Full alert count across all logs — identifying noise targets**
![Noisy Alert Count](assets/NoisyAlert.png)

**Identifying the offending processes behind level 15 false positive**
![False Positive Investigation](assets/FalsePositive.png)

**OneDrive processes causing false positives on rule 100301**
![OneDrive False Positive](assets/ODFalsePositive.png)

**CDB list of trusted outbound processes**
![Trusted Processes List](assets/TrustedProcessesList.png)

### What was kept (not noise)

- **Rule 23505** — 229 high severity CVEs on Windows 10 — real vulnerability data for Phase 5 dashboards
- **Rule 19007** — SCA compliance failures — real security posture data
- **Rule 60122** — Logon failures — expected from brute force simulations

---

## Phase 5 — Reporting

See [docs/phase5-reporting.md](docs/phase5-reporting.md) for the full breakdown.

### Dashboards built

**Attack Overview** — alert timeline by severity, MITRE tactics distribution, total alerts, correlation rules fired, top rules by count

**Security Posture** — active CVEs on Windows 10, total CVE count, top SCA compliance failures, SCA pass/fail distribution

### Screenshots

**Attack Overview Dashboard**
![Attack Overview](assets/Dashboard.png)

**Security Posture Dashboard**
![Security Posture](assets/Dashboard2.png)

### Key findings from the data
- **324 total alerts** over the lab period with **12 correlation rule hits**
- **457 high severity CVEs** on unpatched Windows 10 — all CVE-2025-* series
- **420 SCA compliance failures** — primarily SSH configuration gaps on the Ubuntu manager
- Defense Evasion is the dominant MITRE tactic across all lab activity

---

## Phase 6 — SOAR

See [docs/phase6-soar.md](docs/phase6-soar.md) for the full breakdown.

### What was built

- Wazuh webhook integration forwards alerts to Shuffle in real time
- Shuffle workflow filters noise (severity < 2 skipped), maps Wazuh severity (0–3) to TheHive severity (1–4), and creates enriched alerts in TheHive automatically
- TheHive 5 SOCLab organisation with `analyst@soclab.local` as the Shuffle service account
- Cortex 3 connected to TheHive with VirusTotal and Abuse_Finder analyzers running as Docker containers
- Second victim endpoint added: Windows 11 laptop (MSI) with Wazuh agent

### The pipeline

```
Wazuh (detect) → Shuffle (filter + enrich) → TheHive (triage) → Cortex (enrich observables)
```

### Screenshots

**Shuffle workflow — Webhook 1 → Build Alert → TheHive 1**
![SOAR Workflow](assets/Workflow2.png)

**Shuffle receiving a live Wazuh alert**
![Webhook Execution](assets/ShuffleWebhookAlert.png)

**TheHive — first alerts arriving from Shuffle**
![TheHive Alerts](assets/AnalystHiveAlert.png)

**TheHive — enriched alerts with Rule tags and Critical severity**
![Enriched Alerts](assets/HiveSevereAlert.png)

**TheHive alert created — Shuffle returned 201**
![TheHive Alert Created](assets/TheHiveAlert.png)

**TheHive case — promoted from alert**
![Case](assets/Case.png)

**Observable with Cortex analyzers**
![Case Analyser](assets/CaseAnalyser.png)

**Analyzer results — VirusTotal 0/92 + Abuse_Finder contact**
![Analyser Report](assets/AnalyserReport.png)

**Cortex — SOC-Lab org with thehive service user**
![Cortex User](assets/SOCCortexUser.png)

**Cortex — Abuse_Finder and VirusTotal enabled**
![Analysers](assets/Analysers.png)

**TheHive — SOCLab org with analyst user**
![TheHive User](assets/SOCHiveUser.png)

---

## Tech Stack

| Tool | Version | Purpose |
|---|---|---|
| Wazuh | 4.14.5 | SIEM — log collection, correlation, alerting |
| Sysmon | Latest | Deep Windows telemetry |
| SwiftOnSecurity Sysmon Config | Latest | Tuned Sysmon ruleset |
| Shuffle | Latest | SOAR — automated alert routing |
| TheHive | 5.2.x | Case management and analyst workspace |
| Cortex | 3.1.x | Observable enrichment and analyzer engine |
| VirtualBox | 7.x | Hypervisor |
| Ubuntu | 24.04 LTS | Wazuh server OS |
| Kali Linux | Latest | Attacker / analyst |
| Windows 10 | Pro | Victim endpoint |
| Windows 11 | Home (MSI laptop) | Second victim endpoint |

---

## References

- [Sigma Rules](https://github.com/SigmaHQ/sigma) — vendor-neutral detection rules used as reference for writing custom Wazuh rules
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config) — tuned Sysmon ruleset
- [Wazuh Documentation](https://documentation.wazuh.com) — official Wazuh docs
- [MITRE ATT&CK](https://attack.mitre.org) — threat framework used for tagging all custom rules
