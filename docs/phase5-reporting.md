# Phase 5 — Reporting

## Overview

Reporting turns raw alert data into actionable intelligence. A SOC analyst doesn't just detect — they communicate findings to stakeholders, track security posture over time, and provide evidence for remediation decisions.

Phase 5 builds two dashboards in OpenSearch Dashboards (Wazuh's built-in visualisation layer):

1. **Attack Overview** — what happened, when, and which MITRE techniques were used
2. **Security Posture** — vulnerability exposure and compliance failures on the victim machine

---

## How Dashboards Work in Wazuh

Wazuh stores all alerts in OpenSearch indices (`wazuh-alerts-*`). OpenSearch Dashboards provides a visualisation layer on top — the same engine as Kibana. Every field in an alert is queryable and aggregatable.

Dashboards are built from individual **visualisations** — charts, tables, and metrics that each query the index independently. Multiple visualisations are pinned to a canvas and share a time range filter.

**Key concepts:**
- **DQL filter** — scopes a visualisation to specific rules, agents, or field values
- **Terms aggregation** — groups results by field value (e.g. rule.id, MITRE tactic)
- **Date histogram** — plots events over time
- **Time range** — all visualisations on a dashboard share the same window

---

## Dashboard 1 — Attack Overview

**Purpose:** Show the full attack picture — when attacks occurred, which MITRE tactics were used, total alert volume, and which rules fired most.

![Attack Overview Dashboard](../assets/dashboard.png)

### Panels

**Attack Timeline — Alerts by Severity**
- Type: Vertical Bar
- X-axis: Date Histogram on `timestamp` (hourly)
- Split series: `rule.level` (coloured by severity)
- The spike at 2026-05-05 00:00 is the full kill chain test — brute force, recon, and persistence running in sequence. Attack sessions are clearly visible as spikes against a flat baseline.

**MITRE Tactics Distribution**
- Type: Pie / Donut
- Split slices: `rule.mitre.tactic`
- Shows Defense Evasion as the dominant tactic, followed by Privilege Escalation, Initial Access, and Persistence — directly reflecting the attack scenarios run in Phase 3.

**Total Alerts — 324**
- Type: Metric
- Count of all alerts in the time window
- Gives the analyst a headline number for the reporting period

**Correlation Rules Fired — 12**
- Type: Metric
- Filter: `rule.id: 100500 or rule.id: 100600 or rule.id: 100601`
- Counts only the high-confidence correlation alerts — brute force, recon chain, persistence chain. Separates signal from noise.

**Top Rules by Alert Count**
- Type: Data Table
- Split rows: `rule.id` → `rule.description`
- Shows which rules fired most frequently — useful for identifying both attack patterns and remaining noise

---

## Dashboard 2 — Security Posture

**Purpose:** Show the security health of the victim machine — how many vulnerabilities exist and which compliance checks are failing.

![Security Posture Dashboard](../assets/dashboard2.png)

### Panels

**Active CVEs — Windows 10**
- Type: Data Table
- Filter: `rule.id: 23505`, Last 7 days
- Split rows: `data.vulnerability.cve`
- Lists all active high-severity CVEs on Windows 10 with links to the Microsoft Security Response Center (MSRC) — directly actionable for patch management

**Total CVEs Detected — 457**
- Type: Metric
- Filter: `rule.id: 23505`
- 457 high severity CVEs on an unpatched Windows 10 VM — the headline number for a vulnerability report

**Top SCA Failures**
- Type: Horizontal Bar
- Filter: `rule.id: 19007`
- Field: `data.sca.check.title`
- Shows the top failing compliance checks — all SSH-related configuration failures (PermitEmptyPasswords, PermitUserEnvironment, UsePAM, ClientAliveInterval etc.)
- In a real environment these would feed directly into a hardening backlog

**SCA Failed Checks — 420**
- Type: Metric
- Filter: `rule.id: 19007`
- 420 Security Configuration Assessment failures — compliance gaps across all monitored policies

**SCA Check Results Distribution**
- Type: Pie
- Field: `data.sca.check.result`
- Shows the split between failed, passed, and not-applicable checks — gives the overall compliance score as a proportion rather than a raw number

---

## What the Data Shows

### Attack posture
- 324 total alerts over the lab period
- 12 high-confidence correlation alerts (brute force + recon + persistence chains)
- Defense Evasion is the dominant MITRE tactic — reflecting PowerShell evasion flags and process injection attempts

### Vulnerability posture
- 457 high severity CVEs on Windows 10
- All CVE-2025-* series — recent Microsoft vulnerabilities on an unpatched machine
- Remediation priority: apply Windows updates

### Compliance posture
- 420 SCA check failures
- Top failures are SSH configuration checks — the Ubuntu Wazuh manager has misconfigured SSH settings
- These feed into a hardening checklist for the server

---

## Building These Dashboards

Navigate to `https://192.168.56.10/app/dashboards` and click **Create new dashboard**.

Each visualisation is created via **Create new** → select type → configure Data tab → save → add to canvas.

### Useful DQL filters

```
# Attack correlation rules only
rule.id: 100500 or rule.id: 100600 or rule.id: 100601

# Vulnerability scanner hits
rule.id: 23505

# SCA compliance failures
rule.id: 19007

# Specific agent only
agent.name: DESKTOP-2M08GVE

# High severity only
rule.level >= 10
```

### Time range note
Vulnerability (23505) and SCA (19007) data was generated during initial lab setup. Set the time range to **Last 7 days** or **Last 30 days** to capture it — the default Last 24 hours will return no results.
