import json, sys

severity_wazuh = int("$exec.severity") if "$exec.severity" != "" else 0

if severity_wazuh < 2:
    print(json.dumps({"skip": True, "severity": 1, "description": ""}))
    sys.exit(0)

thehive_severity = severity_wazuh + 1

title = "$exec.title"
desc = "Rule: $exec.rule_id (Wazuh Severity: " + str(severity_wazuh) + ")\n\n$exec.title"

print(json.dumps({"skip": False, "severity": thehive_severity, "title": title, "description": desc}))
