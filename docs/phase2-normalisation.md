# Phase 2 — Normalisation

## Overview

Normalisation is the process of turning raw log blobs into structured, queryable fields — and then writing rules that detect suspicious behaviour against those fields.

Two components handle this in Wazuh:

- **Decoders** — parse the raw log and extract named fields
- **Rules** — check those fields and fire alerts on matches

Wazuh ships with built-in decoders and rules that handle Sysmon, Windows Event Logs, and hundreds of other sources. Phase 2 builds on top of those with custom rules tailored to the attack scenarios in this lab.

---

## The Full Pipeline

```
Windows 10 runs whoami.exe
        │
        ▼
Sysmon captures Event ID 1 (Process Creation)
        │
        ▼
Wazuh Agent ships the raw JSON log to the manager (port 1514)
        │
        ▼
Decoder reads the raw log → extracts structured fields:
    win.eventdata.image       = C:\Windows\System32\whoami.exe
    win.eventdata.commandLine = whoami
    win.system.eventID        = 1
    win.system.channel        = Microsoft-Windows-Sysmon/Operational
        │
        ▼
Rules engine checks decoded fields against all loaded rules
        │
        ├── Built-in rule 92031 matches → "Discovery activity executed"
        └── Our rule 100300 matches    → "Discovery: Recon command executed"
        │
        ▼
Alerts stored in indexer → visible in dashboard
```

---

## Rule Anatomy

```xml
<rule id="100300" level="6">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)(whoami|net|net1)\.exe</field>
    <description>Discovery: Recon command executed - $(win.eventdata.image)</description>
    <mitre>
        <id>T1082</id>
    </mitre>
</rule>
```

| Component | Purpose |
|---|---|
| `id` | Unique rule number. Custom rules must start at **100000+** |
| `level` | Severity 1–15. 1–6 info, 7–10 suspicious, 11–14 likely malicious, 15 critical |
| `if_group` | Pre-filter — only check this rule against logs already in this group. Assigned by the decoder |
| `field` | Detection condition — the decoded field must match the regex |
| `type="pcre2"` | Use PCRE2 regex. `(?i)` makes it case-insensitive |
| `description` | Alert text shown in dashboard. `$(field.name)` injects the live value |
| `mitre` | Tags the alert with a MITRE ATT&CK technique ID |

Multiple `<field>` conditions in one rule = **AND logic** (all must match).

---

## Rule ID Namespace

```
100001 - 100099  →  Execution
100100 - 100199  →  Persistence
100200 - 100299  →  Credential Access
100300 - 100399  →  Discovery
100400 - 100499  →  Defense Evasion
100500 - 100599  →  C2 / Network
```

---

## Sysmon Group Names

Wazuh assigns a group to each Sysmon event based on its Event ID. Use these exact names in `<if_group>`:

| Event ID | What it captures | if_group |
|---|---|---|
| 1 | Process creation | `sysmon_event1` |
| 3 | Network connection | `sysmon_event3` |
| 7 | Image/DLL loaded | `sysmon_event7` |
| 8 | CreateRemoteThread | `sysmon_event8` |
| 10 | Process access (LSASS) | `sysmon_event_10` |
| 11 | File created | `sysmon_event_11` |
| 13 | Registry value set | `sysmon_event_13` |

**Pattern:** single-digit IDs have no underscore before the number. Double-digit IDs do.

To verify group names on your system:
```bash
sudo grep -r "if_group" /var/ossec/ruleset/rules/ | grep sysmon | sort -u
```

---

## Critical Lesson: Field Names in Rules vs Dashboard

The dashboard displays fields with a `data.` prefix:
```
data.win.eventdata.image
data.win.eventdata.commandLine
```

**Rules do NOT use the `data.` prefix:**
```xml
<field name="win.eventdata.image" ...>
<field name="win.eventdata.commandLine" ...>
```

Using `data.win.eventdata.*` in rules causes silent failures — the rule loads without error but never matches. Always verify field names by reading the built-in rules in `/var/ossec/ruleset/rules/`.

---

## How to Find the Right Field Names

### 1. Read real events in the dashboard
Expand any alert → every field shown is a field you can write a rule against. Strip the `data.` prefix when writing the rule.

### 2. Read the built-in rules
```bash
sudo grep -r "field name" /var/ossec/ruleset/rules/0800-sysmon_id_1.xml | head -20
```
The built-in rules show exactly which field names Wazuh uses internally.

### 3. Use wazuh-logtest
```bash
sudo /var/ossec/bin/wazuh-logtest
```
Paste a raw log and it shows Phase 1 (pre-decoding), Phase 2 (decoded fields), and Phase 3 (which rules matched). Use this to test rules before deploying.

### 4. Use Sigma rules as a reference
The [Sigma repository](https://github.com/SigmaHQ/sigma) contains vendor-neutral detection rules for almost every known attack technique. Use them to understand what fields to check, then translate into Wazuh XML.

**Sigma → Wazuh translation workflow:**
```
1. Identify attack technique (e.g. LSASS credential dumping)
2. Find the Sigma rule: github.com/SigmaHQ/sigma → rules/windows/process_access/
3. Run the attack in the lab, find the raw log in Wazuh
4. Confirm the fields match the Sigma detection logic
5. Translate the Sigma condition into a Wazuh <field> rule
6. Test with wazuh-logtest
7. Trigger the attack again — confirm the alert fires
```

---

## Custom Rules Written (local_rules.xml)

### Execution
| Rule | Detects | MITRE |
|---|---|---|
| 100001 | PowerShell encoded commands (`-enc`, `-EncodedCommand`) | T1059.001 |
| 100002 | LOLBins (certutil, mshta, regsvr32) loading remote content | T1218 |
| 100003 | WMI used for execution | T1047 |
| 100004 | Shell spawned from Office application | T1204.002 |

### Persistence
| Rule | Detects | MITRE |
|---|---|---|
| 100100 | Registry `Services\*\ImagePath` modified | T1031, T1050 |
| 100101 | Registry `CurrentVersion\Run` key modified | T1547.001 |
| 100102 | Scheduled task created via schtasks.exe | T1053.005 |

### Credential Access
| Rule | Detects | MITRE |
|---|---|---|
| 100200 | Process accessing LSASS (credential dumping) | T1003.001 |

### Discovery
| Rule | Detects | MITRE |
|---|---|---|
| 100300 | Recon commands: whoami, net, ipconfig, systeminfo | T1082, T1033 |
| 100301 | Outbound connections to common attack ports | T1046 |

### Defense Evasion
| Rule | Detects | MITRE |
|---|---|---|
| 100400 | CreateRemoteThread (process injection) | T1055 |
| 100401 | PowerShell launched with evasion flags (bypass, hidden) | T1059.001 |

---

## Verified Working

Rule 100300 confirmed firing on live events:

```
Apr 30, 2026 @ 00:44:45  DESKTOP-2M08GVE  Discovery: Recon command executed - C:\Windows\System32\whoami.exe   level:6  rule:100300
Apr 30, 2026 @ 00:44:46  DESKTOP-2M08GVE  Discovery: Recon command executed - C:\Windows\System32\net.exe      level:6  rule:100300
Apr 30, 2026 @ 00:44:46  DESKTOP-2M08GVE  Discovery: Recon command executed - C:\Windows\System32\net1.exe     level:6  rule:100300
```

---

## Useful Commands

```bash
# Test a rule against a raw log
sudo /var/ossec/bin/wazuh-logtest

# Edit custom rules
sudo nano /var/ossec/etc/rules/local_rules.xml

# Restart manager after rule changes
sudo systemctl restart wazuh-manager

# Check for rule load errors
sudo grep -i "error\|warning" /var/ossec/logs/ossec.log | grep "100"

# View recent alerts
sudo tail -50 /var/ossec/logs/alerts/alerts.log

# List all Sysmon rule files
sudo find /var/ossec/ruleset/rules -name "*sysmon*"
```
