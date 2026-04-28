# Phase 1 — Infrastructure Setup

## Overview

Build the base lab: three VMs on a Host-Only network, Wazuh all-in-one on Ubuntu, agent + Sysmon on Windows 10, verified end-to-end.

---

## 1. VirtualBox Network

Create the Host-Only adapter (run on Windows host in PowerShell as Administrator):

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif create
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" hostonlyif ipconfig "VirtualBox Host-Only Ethernet Adapter #2" --ip 192.168.56.1 --netmask 255.255.255.0
```

Assign `VirtualBox Host-Only Ethernet Adapter #2` as a second network adapter on all three VMs.

---

## 2. Ubuntu VM Setup

**Specs:** 8GB RAM, 100GB disk, 10 vCPUs  
**Adapters:** Adapter 1 = Host-Only (`192.168.56.10`), Adapter 2 = Bridged (internet for install)

### Static IP (Netplan)

```yaml
# /etc/netplan/50-cloud-init.yaml
network:
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [192.168.56.10/24]
    enp0s8:
      dhcp4: true
  version: 2
```

Disable cloud-init network management so it persists:

```bash
sudo bash -c 'echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg'
sudo netplan apply
```

### Wazuh Install

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

Takes 10-20 minutes. Credentials are printed at the end — save them.

### Fix wazuh-manager startup timeout

```bash
sudo systemctl edit wazuh-manager
```

Add:

```ini
[Unit]
After=wazuh-indexer.service

[Service]
TimeoutStartSec=300
Restart=on-failure
RestartSec=15
```

```bash
sudo systemctl daemon-reload
```

---

## 3. Kali Linux Setup

**Adapter 2:** Host-Only → `192.168.56.20`

```bash
sudo nmcli con add type ethernet ifname eth1 con-name host-only ip4 192.168.56.20/24
sudo nmcli con modify host-only connection.autoconnect yes
sudo nmcli con up host-only
```

Access the Wazuh dashboard from Kali: `https://192.168.56.10`

---

## 4. Windows 10 Agent Setup

**Adapter 2:** Host-Only → `192.168.56.30` (set manually in IPv4 settings, no gateway)

### Install Wazuh Agent

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi" -OutFile "C:\wazuh-agent.msi"
msiexec /i C:\wazuh-agent.msi WAZUH_MANAGER="192.168.56.10" /q
NET START WazuhSvc
```

### Install Sysmon

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive C:\Sysmon.zip -DestinationPath C:\Sysmon
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml"
C:\Sysmon\Sysmon64.exe -accepteula -i C:\Sysmon\sysmonconfig.xml
```

### Log Collection Config

Add to `C:\Program Files (x86)\ossec-agent\ossec.conf` inside `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Security, System, and Application channels are included by default.

```powershell
NET STOP WazuhSvc
NET START WazuhSvc
```

---

## 5. Verification

- Agent shows **Active** in dashboard: Menu → Agents
- Events flowing: click agent → Events tab
- MITRE ATT&CK tactics populating from baseline Windows activity
