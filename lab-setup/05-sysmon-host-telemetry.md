#  Module 05: Sysmon Advanced Host Telemetry & Threat Detection

![Sysmon](https://img.shields.io/badge/Component-Microsoft_Sysinternals_Sysmon-0078D6?style=flat-square&logo=windows)
![Configuration](https://img.shields.io/badge/Config-SwiftOnSecurity_Baseline-red?style=flat-square)
![Integration](https://img.shields.io/badge/Ingestion-Wazuh_Logcollector-00A4E4?style=flat-square&logo=wazuh)
![MITRE](https://img.shields.io/badge/Framework-MITRE_ATT%26CK-orange?style=flat-square)

> **Document Scope:** Deployment of Microsoft System Monitor (Sysmon), schema optimization via SwiftOnSecurity configuration, kernel-level behavioral monitoring, Windows event pipeline hardening, and agent log ingestion into the Wazuh SIEM collector.

---

## 1. Architectural Role in Endpoint Detection & Response (EDR)

Standard Windows Security Event Logs (`Security.evtx`) are insufficient for deep forensic investigations because they lack crucial process context (such as parent-child lineage, hash validation, and command-line execution parameters). Sysmon runs as a persistent background device driver (`SysmonDrv`) and user-mode service monitoring low-level system activity directly at the kernel boundary.

```text
                                  +--------------------------------------------------------------+
                                  |             Operating System Kernel Layer                    |
                                  |  - Process Execution, Memory Access, Raw Sockets, Threads    |
                                  +------------------------------+-------------------------------+
                                                                 |
                                                                 | (Driver Hooking: SysmonDrv.sys)
                                                                 v
                                  +--------------------------------------------------------------+
                                  |            Sysmon Service (SwiftOnSecurity Schema)           |
                                  |  - SHA256 Hashes, Process Lineage, Network Sockets           |
                                  |  - Target Channel: Microsoft-Windows-Sysmon/Operational      |
                                  +------------------------------+-------------------------------+
                                                                 |
                                                                 | (Channel Ingestion: localfile)
                                                                 v
                                  +--------------------------------------------------------------+
                                  |                  Wazuh Agent Subsystem                       |
                                  |  - Encrypted Transport over TCP/1514                         |
                                  +------------------------------+-------------------------------+
                                                                 |
                                                                 v
                                  +--------------------------------------------------------------+
                                  |         Wazuh Manager / Analysis Engine (192.168.1.102)      |
                                  |  - Rule Matching: Ruleset 0800 - Sysmon Decoding             |
                                  +--------------------------------------------------------------+
```

---

## 2. High-Value Sysmon Event ID Detection Matrix

The laboratory uses Sysmon tuned to capture adversary techniques mapped directly against the MITRE ATT&CK matrix:

| Event ID | Event Classification | Forensic & SOC Triage Value | MITRE Technique Mapping |
| :---: | :--- | :--- | :--- |
| **EID 1** | **Process Creation** | Captures full command-line arguments, hashes (`SHA256`, `IMPHASH`), user context, and parent process tree (`ParentCommandLine`). | **T1059** (Command and Scripting Interpreter) |
| **EID 3** | **Network Connection** | Maps outbound TCP/UDP socket creation to the exact executable path and process ID (PID). | **T1071** (Application Layer Protocol) |
| **EID 7** | **Image Loaded (DLLs)** | Identifies unsigned modules, unexpected library directories, and DLL search-order hijacking. | **T1574.002** (DLL Side-Loading) |
| **EID 8** | **CreateRemoteThread** | High-confidence alert for process injection when a binary spawns execution threads inside a remote PID. | **T1055** (Process Injection) |
| **EID 10** | **ProcessAccess** | Detects memory reading or dumping attempts against sensitive system processes (specifically `lsass.exe`). | **T1003.001** (LSASS Memory Credential Dumping) |
| **EID 11** | **FileCreate** | Tracks file drops, payload staging, and malicious script placement inside `\AppData\Local\Temp\` or `C:\Users\Public\`. | **T1105** (Ingress Tool Transfer) |
| **EID 12 / 13** | **RegistryEvent** | Detects unauthorized persistence keys placed into `Run` / `RunOnce` hives. | **T1547.001** (Registry Run Keys / Startup Folder) |
| **EID 22** | **DNSEvent** | Logs DNS lookups issued by specific executables, exposing C2 domains and tunneling. | **T1071.004** (DNS Protocol C2) |

---

## 3. Provisioning & Deployment Procedures

### 3.1 Fetching Sysinternals Suite & Baseline Schema
On both `WinServer-AD` (`192.168.1.10`) and `Win-Workstation` (`192.168.1.150`), execute administrative PowerShell to fetch the binaries and the community-standard SwiftOnSecurity configuration file:

```powershell
# Create dedicated staging directory
New-Item -ItemType Directory -Path "C:\Tools\Sysmon" -Force
Set-Location "C:\Tools\Sysmon"

# Download Sysmon from Microsoft Sysinternals
Invoke-WebRequest -Uri "[https://download.sysinternals.com/files/Sysmon.zip](https://download.sysinternals.com/files/Sysmon.zip)" -OutFile "Sysmon.zip"
Expand-Archive -Path "Sysmon.zip" -DestinationPath "." -Force

# Fetch community-standard SwiftOnSecurity configuration profile
Invoke-WebRequest -Uri "[https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml](https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml)" -OutFile "sysmonconfig-export.xml"
```

### 3.2 Installation with Custom Driver Name
Install Sysmon as a persistent Windows service with the loaded configuration schema:

```cmd
cd C:\Tools\Sysmon
Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### 3.3 Verifying Service & Driver State
Verify that both the user-mode service and the kernel altitude driver are properly running:

```powershell
# Verify user-space service
Get-Service -Name "Sysmon64" | Select-Object Name, Status, StartType

# Verify active kernel filter driver
fltmc.exe instances -v "SysmonDrv"
```

---

## 4. Pipeline Integration: Shipping Sysmon Telemetry to Wazuh

To ensure Sysmon operational logs are forwarded from Windows nodes to the Wazuh SIEM collector (`192.168.1.102`), the local agent configuration must be instructed to monitor the channel.

### 4.1 Agent Configuration Update
Append the following XML configuration block to `C:\Program Files (x86)\ossec-agent\ossec.conf` on each Windows host:

```xml
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

### 4.2 Restarting Agent Service
Restart the Wazuh Agent daemon to commit the channel subscriber:

```powershell
Restart-Service -Name "Wazuh"
```

---

## 5. Verification & Live Triage Scenarios

### Diagnostic 1: Generating Test Telemetry (Process Creation & Network Sockets)
Execute an anomalous CLI call on the Windows workstation to confirm EID 1 and EID 3 logging:

```cmd
cmd.exe /c powershell.exe -NoProfile -Command "Resolve-DnsName testmyids.com"
```

### Diagnostic 2: Querying the Local Sysmon Event Log
Inspect the latest operational events directly using PowerShell:

```powershell
# Retrieve the 5 most recent Process Creation events (EID 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 5 | 
  Select-Object TimeCreated, Id, @{Name="CommandLine"; Expression={$_.Properties[10].Value}} | 
  Format-Table -Wrap
```

### Diagnostic 3: Validating Ingestion on the Wazuh SIEM Node
From the Ubuntu terminal (or via Windows SSH to `192.168.1.102`), tail the active alerts log to confirm decoded Sysmon events:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -i "sysmon"
```
---

## 🔗 Official References & Vendor Documentation

* [Microsoft Sysinternals Sysmon Official Download & Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
* [SwiftOnSecurity sysmon-config Official GitHub Repository](https://github.com/SwiftOnSecurity/sysmon-config)
* [Wazuh Documentation: Monitoring Windows Event Channels](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/how-to-collect-wincfg.html)
* [MITRE ATT&CK Framework for Enterprise Techniques](https://attack.mitre.org/)
