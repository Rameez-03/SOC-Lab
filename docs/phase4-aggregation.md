# Phase 4 — Aggregation

## Overview

Aggregation is the process of reducing alert volume so analysts only see what is actionable. In a real SOC, alert fatigue is one of the leading causes of missed detections — analysts stop engaging with a dashboard that fires hundreds of low-quality alerts per day.

Phase 4 addresses this by:
1. **Identifying** which rules fire most frequently and why
2. **Suppressing** known-good activity that generates false positives
3. **Preserving** real detections by making suppressions surgical, not blanket

---

## Methodology

### Step 1 — Identify the noise

Query all alert log files and rank rules by fire count:

```bash
sudo find /var/ossec/logs/alerts/ -name "*.log" -exec grep "^Rule:" {} \; | awk '{print $2}' | sort | uniq -c | sort -rn | head -20
```

This searches every archived log file, not just the current one. The full 7-day count reveals the true noise picture:

| Count | Rule | Description |
|---|---|---|
| 415 | 60122 | Logon failure — expected from brute force simulations |
| 400 | 2904 | Dpkg package half-configured (Ubuntu) |
| 260 | 2902 | Dpkg package installed (Ubuntu) |
| 229 | 23505 | High severity CVE detected (vulnerability scanner) |
| 214 | 92219 | svchost.exe DLL activity in Windows root |
| 118 | 19007 | SCA compliance check failed |
| 112 | 92213 | Executable dropped in Temp folder — **level 15** |
| 46 | 100301 | Outbound connection to attack port (our rule) |

### Step 2 — Investigate before suppressing

Not every high-volume rule is noise. Before suppressing, identify what's actually triggering it:

```bash
# Find which processes triggered a specific rule
sudo cat /var/ossec/logs/alerts/alerts.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        a = json.loads(line)
        if a.get('rule', {}).get('id') == 'RULE_ID':
            img = a.get('data', {}).get('win', {}).get('eventdata', {}).get('image', 'unknown')
            print(img)
    except: pass
" | sort | uniq -c | sort -rn | head -20
```

---

## Key Finding — Alert Fatigue from Level 15 False Positive

**Rule 92213** — "Executable file dropped in folder commonly used by malware" — fired **112 times** at **level 15 (critical)** over the lab's lifetime.

Investigation revealed every single hit came from `C:\Windows\system32\cleanmgr.exe` — Windows Disk Cleanup. When Disk Cleanup runs, it extracts 20+ DLL files into a temp folder, each one triggering a separate level 15 critical alert.

```
cleanmgr.exe → AppData\Local\Temp\{GUID}\WimProvider.dll        → rule 92213 [level 15]
cleanmgr.exe → AppData\Local\Temp\{GUID}\VhdProvider.dll        → rule 92213 [level 15]
cleanmgr.exe → AppData\Local\Temp\{GUID}\UnattendProvider.dll   → rule 92213 [level 15]
... (20+ more per Disk Cleanup run)
```

**The real-world impact:** An analyst seeing 112 critical alerts would either spend hours investigating Disk Cleanup runs, or — more likely — start ignoring level 15 alerts entirely. The second outcome is how real breaches get missed.

**The fix:** A surgical suppression rule targeting only the known-good processes, leaving any unknown process still firing at level 15.

---

## Suppression Rules Written

All suppressions use `level="0"` + `<options>no_log</options>` — the alert is completely discarded, never stored, never shown in the dashboard.

### Rule 100700 — cleanmgr.exe / OneDrivePatcher.exe temp file drops

**Finding:** `cleanmgr.exe` generated 112 level 15 critical alerts. `OneDrivePatcher.exe` generated 1. Both are legitimate Windows processes dropping DLLs in Temp.

**Approach:** Selective suppression — only suppress when the dropping process is known-good. Any unknown process still fires at level 15.

```xml
<rule id="100700" level="0">
  <if_sid>92213</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)(cleanmgr|OneDrivePatcher)\.exe</field>
  <description>Suppressed: Known-good process dropping temp file - $(win.eventdata.image)</description>
  <options>no_log</options>
</rule>
```

---

### Rules 100701 / 100702 — Ubuntu dpkg noise

**Finding:** 400 hits of "New dpkg package installed" and 400 hits of "Dpkg package half-configured" — Ubuntu's package manager firing during lab setup and background updates.

**Approach:** Blanket suppression — all dpkg activity in this lab is noise. No field condition needed.

```xml
<rule id="100701" level="0">
  <if_sid>2902</if_sid>
  <description>Suppressed: Ubuntu dpkg package installed</description>
  <options>no_log</options>
</rule>

<rule id="100702" level="0">
  <if_sid>2904</if_sid>
  <description>Suppressed: Ubuntu dpkg package half-configured</description>
  <options>no_log</options>
</rule>
```

---

### Rule 100703 — svchost.exe DLL activity

**Finding:** Rule 92219 ("Possible DLL search order hijack") fired on `svchost.exe` creating DLLs in the Windows root during normal Windows Update activity.

**Approach:** Selective suppression on svchost.exe only — other processes triggering DLL search order hijack detection still alert.

```xml
<rule id="100703" level="0">
  <if_sid>92219</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)svchost\.exe</field>
  <description>Suppressed: svchost.exe DLL activity in Windows root - known-good</description>
  <options>no_log</options>
</rule>
```

---

### Rule 100704 — OneDrive outbound connections (false positive in our own rule)

**Finding:** Rule 100301 (our Phase 2 outbound connection rule) fired 46 times — entirely from OneDrive processes connecting to Microsoft's servers on ports 80 and 443.

```
443 - C:\Users\Rameez\AppData\Local\Microsoft\OneDrive\OneDrive.exe           (9 hits)
443 - C:\Users\Rameez\AppData\Local\Microsoft\OneDrive\OneDriveSetup.exe      (3 hits)
443 - OneDrive.Sync.Service.exe                                                (3 hits)
 80 - OneDrive.exe                                                              (1 hit)
443 - OneDriveStandaloneUpdater.exe                                            (1 hit)
443 - OneDrivePatcher.exe                                                      (1 hit)
```

This is a false positive we introduced — rule 100301 correctly detects outbound connections to common attack ports, but doesn't distinguish between a port scanner and OneDrive syncing to port 443.

**Approach:** CDB list of trusted processes + selective suppression rule.

CDB list at `/var/ossec/etc/lists/trusted-outbound-processes`:
```
onedrive.exe:
onedrivesetup.exe:
onedrive.sync.service.exe:
onedrivestandaloneupdater.exe:
onedrivepatcher.exe:
```

Suppression rule:
```xml
<rule id="100704" level="0">
  <if_sid>100301</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)OneDrive</field>
  <description>Suppressed: OneDrive outbound connection - known-good</description>
  <options>no_log</options>
</rule>
```

**Why both a CDB list and a rule?** The list is the living registry of trusted processes — analysts add to it over time without touching rule XML. As new trusted processes are identified, they go in the list. The rule just references it.

---

## What Was Not Suppressed

| Rule | Why kept |
|---|---|
| 23505 | 229 high severity CVEs on Windows 10 — real vulnerability data for Phase 5 dashboards |
| 19007 | SCA compliance failures — real security posture data |
| 60122 | Logon failures — expected from brute force simulations, not noise |

---

## Suppression Design Principles

**Selective over blanket:** When a rule detects something genuinely suspicious, suppress only the known-good subset. Leave unknown variants firing at full severity. This is the difference between rule 100700 (suppresses only cleanmgr.exe from 92213) and rule 100701 (suppresses all of 2902).

**Investigate before suppressing:** Every suppression in this phase was preceded by identifying exactly what was triggering the rule. Never suppress based on rule description alone — verify the actual events first.

**Verify real detections still fire:** After every suppression, test that the underlying detection still works for unknown processes. A suppression that silences real attacks is worse than the noise it was meant to fix.

---

## Testing

| Suppression | Test | Expected |
|---|---|---|
| 100700 | Run `cleanmgr.exe` on Windows 10 | No 92213 alert |
| 100701/702 | `sudo apt install -y curl` on Ubuntu | No 2902/2904 alert |
| 100704 | Wait for OneDrive sync | No 100301 alert |
| Verify real detection | `echo test > $env:TEMP\test.exe` on Windows 10 | 92213 still fires at level 15 |

All four tests confirmed working.

---

## Useful Commands

```bash
# Count all rules by frequency across all log files
sudo find /var/ossec/logs/alerts/ -name "*.log" -exec grep "^Rule:" {} \; | awk '{print $2}' | sort | uniq -c | sort -rn | head -20

# Find what processes triggered a specific rule
sudo cat /var/ossec/logs/alerts/alerts.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        a = json.loads(line)
        if a.get('rule', {}).get('id') == 'RULE_ID':
            print(a.get('data', {}).get('win', {}).get('eventdata', {}).get('image', 'unknown'))
    except: pass
" | sort | uniq -c | sort -rn

# Search archived compressed logs
sudo find /var/ossec/logs/alerts/ -name "ossec-alerts*.log.gz" -exec zcat {} \; 2>/dev/null | grep -A 15 "Rule: RULE_ID"

# Verify CDB list is loaded
sudo /var/ossec/bin/wazuh-logtest

# Restart after rule changes
sudo systemctl restart wazuh-manager
```
