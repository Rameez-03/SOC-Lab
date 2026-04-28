# Automation

Scripts to manage the lab environment. Run all scripts from the Windows host.

## start_lab.py

Starts all VMs in the correct order and waits for Wazuh to initialise before launching Kali.

```powershell
python automation/start_lab.py
```

**Sequence:**
1. Starts Ubuntu 24.04 in headless mode
2. Waits 90 seconds for Wazuh services to come up
3. Starts Kali with a GUI

**Requirements:** Python 3, VirtualBox installed at default path.

## Planned

- `stop_lab.py` — graceful shutdown of all VMs
- `snapshot.py` — take snapshots before attack scenarios
- `reset_windows.py` — restore Windows 10 to clean snapshot post-attack
