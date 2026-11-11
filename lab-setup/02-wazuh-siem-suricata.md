#  Module 02: Wazuh SIEM & Suricata NIDS Central Engine

![Ubuntu](https://img.shields.io/badge/OS-Ubuntu_22.10_(Kinetic_Kudu)-E95420?style=flat-square&logo=ubuntu)
![Wazuh](https://img.shields.io/badge/SIEM-Wazuh_Manager-00A4E4?style=flat-square&logo=wazuh)
![Suricata](https://img.shields.io/badge/NIDS-Suricata_Engine-EF3B24?style=flat-square)
![Hypervisor](https://img.shields.io/badge/Hypervisor-Oracle_VirtualBox-blue?style=flat-square&logo=virtualbox)
![Network](https://img.shields.io/badge/Segment-intnet_(Internal)-green?style=flat-square)

> **Document Scope:** Architecture breakdown, packet sniffing mechanisms, Suricata rule integration, Wazuh event correlation pipelines, real-world LVM storage failure troubleshooting, and Windows SSH workflow configuration.

---

## 1. Component Role & Distinction (Wazuh vs. Suricata)

In a Security Operations Center (SOC), separating network packet visibility from host behavioral analysis is essential:

* **Suricata (Network Intrusion Detection System - NIDS):**
  * Operates at the network layer (Layers 3, 4, and 7).
  * Analyzes raw traffic traversing the virtual switch in real time.
  * Matches packet signatures (e.g., suspicious HTTP headers, known malicious IPs, command injection patterns) without needing access to target machines.
  * Emits alerts and metadata into a high-speed JSON stream: `/var/log/suricata/eve.json`.

* **Wazuh (Security Information & Event Management - SIEM / XDR):**
  * Acts as the central correlation brain.
  * Gathers data from multiple sources: host agents, Windows event logs, Sysmon, and Suricata's `eve.json`.
  * Runs correlation rules to map activity against the **MITRE ATT&CK** framework, detects anomalous behavior, tracks file integrity (FIM), and maintains asset inventories.

Suricata acts as the **sensor** observing the wire, while Wazuh is the **analyst dashboard and correlation engine** turning raw alerts into prioritized security incidents.

---

## 2. Network Topology & Ingestion Pipeline

```text
                                +--------------------------------------------------------------+
                                |                  pfSense Perimeter Gateway                   |
                                |                  IP: 192.168.1.1 (Gateway)                   |
                                +------------------------------+-------------------------------+
                                                               |
                                                               | (Internal Segment: intnet)
                                                               v
                                +--------------------------------------------------------------+
                                |              Wazuh_Server (Central SOC Collector)            |
                                |                                                              |
                                |       - Hostname: Wazuh_Server                               |
                                |       - IP: 192.168.1.102/24 (Static / Reserved)             |
                                |       - Layer 1/2: Promiscuous raw frame capture (Suricata)  |
                                |       - Suricata Pipeline: /var/log/suricata/eve.json        |
                                |       - Wazuh Collector: wazuh-analysisd / wazuh-remoted     |
                                |       - Daemon State: wazuh-manager.service (Active)         |
                                |                                                              |
                                +------------------------------+-------------------------------+
                                                               ^
                                                               | (TCP 1514 / Host Agent Logs)
                                                               |
                                +------------------------------+-------------------------------+
                                |          Monitored Lab Endpoints (Agents / Sysmon)           |
                                |                                                              |
                                |       - WinServer-AD (Domain Controller - 192.168.1.10)      |
                                |       - Windows Analyst Node / Workstations                  |
                                |                                                              |
                                +--------------------------------------------------------------+
```

---

## 3. Virtual Machine Hardware Profile

| Specification Parameter | Value / Allocation | Operational Context |
| :--- | :--- | :--- |
| **Virtual Machine Name** | `Wazuh_Server` | Hypervisor identifier |
| **Guest OS Profile** | Ubuntu 22.10 (Kinetic Kudu) (64-bit) | Dedicated Linux telemetry node |
| **Processor Allocation** | **2 vCPUs** | Multithreaded rule matching and daemon workers |
| **Base Memory (RAM)** | **4096 MB** | Dedicated pool for Wazuh indexing and Suricata buffers |
| **Storage Capacity** | **50.00 GB** (SATA Port 0, Dynamic VDI) | Partition for OS, databases, and log retention |
| **Network Adapter** | Intel PRO/1000 MT Desktop | Bound directly to Internal Network (`intnet`) |
| **Paravirtualization** | KVM Paravirtualization | Kernel-level performance optimization |

---

## 4. Suricata NIDS Deployment & Configuration

### 4.1 Interface Binding & Promiscuous Mode
Suricata inspects Layer 2 frames directly from the local interface `enp0s3` (or equivalent Intel NIC identifier):

(Note: enp0s3 corresponds to the primary VirtualBox virtual adapter emulated under Ubuntu).

```bash
# Enable promiscuous packet capture on the internal interface
sudo ip link set enp0s3 promisc on
```

### 4.2 Key Ruleset Integration
Suricata operates with the Emerging Threats (ET Open) ruleset. The configuration file `/etc/suricata/suricata.yaml` was hardened:
- Configured `$HOME_NET` variable: `[192.168.1.0/24]`.
- Configured `$EXTERNAL_NET`: `!$HOME_NET`.
- Enabled fast JSON logging:
  ```yaml
  outputs:
    - eve-log:
        enabled: yes
        type: file
        filename: /var/log/suricata/eve.json
        types:
          - alert:
              payload: yes
              payload-buffer: yes
              http: yes
          - http
          - dns
          - tls
  ```

---

## 5. Wazuh Manager Telemetry Pipeline

### 5.1 Ingesting Suricata Alerts into Wazuh
To correlate network-level alerts with host-level endpoint actions, the Suricata `eve.json` output is monitored directly by the Wazuh Logcollector. The following block was appended to `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
</ossec_config>
```

### 5.2 Core Subsystem Daemons
The Wazuh Manager architecture processes events through dedicated modules:
- `wazuh-remoted`: Listens on TCP/UDP port `1514` for encrypted log traffic from Wazuh Agents.
- `wazuh-analysisd`: The central correlation engine comparing incoming JSON with detection rules.
- `wazuh-db`: Stores agent metadata and hardware inventory in SQLite databases.
- `wazuh-syscheckd`: Manages File Integrity Monitoring (FIM).
- `wazuh-logcollector`: Reads local logs (including `eve.json`) and submits them to the analysis queue.
- `wazuh-monitord`: Monitors agent connectivity and daemon health status.
- `wazuh-execd`: Handles active responses and automated mitigations.
- `wazuh-modulesd`: Coordinates vulnerability detection, CIS-CAT scans, and system integration tasks.

---

## 6. Troubleshooting Case: LVM Storage Saturation & Service Crash

During continuous traffic generation and raw packet ingestion, telemetry services can experience catastrophic crashes due to partition exhaustion.

### 6.1 Symptoms & Root Cause
* Running `systemctl status wazuh-manager` indicated daemon failure (`exit code 1/FAILURE`).
* Wazuh SQLite databases (`wazuh-db`) could not obtain lock files.
* Diagnostic check `df -h` revealed **0 bytes free (100% used)** on the root logical volume (`/dev/mapper/ubuntu--vg-ubuntu--lv`).
* Standard log deletion attempts failed to reclaim space because unclosed file descriptors held deleted files in memory.

### 6.2 Recovery & Stabilization Steps

1. **Locate and Kill Locked File Descriptors:**
   Identify processes writing to deleted or unlinked log files holding disk space hostage:
   ```bash
   sudo lsof +L1
   ```

2. **Truncate Systemd Journal Buffers:**
   Clear old system journals that accumulated during boot loops:
   ```bash
   sudo journalctl --vacuum-time=1d
   sudo journalctl --vacuum-size=200M
   ```

3. **Reclaim Suricata Log Footprint:**
   Truncate the JSON alert stream without corrupting file sockets:
   ```bash
   sudo truncate -s 0 /var/log/suricata/eve.json
   ```

4. **Reset Database Permissions & Restart Daemons:**
   Wazuh requires strict ownership on internal SQLite sockets:
   ```bash
   sudo chown -R wazuh:wazuh /var/ossec/queue/db/
   sudo systemctl daemon-reload
   sudo systemctl restart wazuh-manager
   sudo systemctl restart suricata
   ```

5. **Verification:**
   Check that all core worker processes report `active (running)`:
   ```bash
   sudo systemctl status wazuh-manager
   sudo systemctl status suricata
   ```

---

## 7. Operations & Usability: Remote SSH Access from Windows

The native VirtualBox console does not support bi-directional clipboard copy-pasting out of the box (especially in server/headless environments). To make terminal management efficient and allow pasting scripts and commands, an SSH bridge was configured from the Windows analyst machine.

### 7.1 Host Setup (Ubuntu Server)
Ensure the OpenSSH server daemon is listening on port 22:

```bash
# Install and verify OpenSSH
sudo apt update && sudo apt install openssh-server -y
sudo systemctl enable --now ssh
sudo ufw allow 22/tcp
```

### 7.2 Client Setup (Windows Workstation / PowerShell)
On the Windows node inside the `intnet` segment (or through port forwarding):

1. **Verify Native SSH Client:**
   Windows 10/11 and Windows Server include OpenSSH natively. Open PowerShell and verify:
   ```powershell
   Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Client*'
   ```
   If not installed:
   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
   ```

2. **Connect via Terminal:**
   Launch **Windows Terminal** or standard **PowerShell** and establish the session:
   ```powershell
   ssh user@192.168.1.102
   ```

3. **Benefits for SOC Analysis:**
   * **Native Clipboard:** Full support for `Ctrl + C` and `Ctrl + V` across systems.
   * **Large Scrollback Buffer:** Full visibility into multi-line JSON logs (`eve.json`) and Suricata outputs.
   * **Multi-Tab Workflows:** Run `tail -f` in one tab while executing attack triggers or triage scripts in another.

---

## 8. Service Verification & Live Triage Scenarios

### Diagnostic 1: Real-time Alert Stream Inspection
To observe incoming alerts in real time directly from the CLI:

```bash
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

### Diagnostic 2: Wazuh Processing Pipeline Validation
To verify that alerts from Suricata are being decoded and matched by the Wazuh engine:

```bash


# Check Wazuh alert log directly
sudo tail -f /var/ossec/logs/alerts/alerts.log
```
---

---

## 🔗 Official References & Vendor Documentation

* [Wazuh SIEM/XDR Official Documentation](https://documentation.wazuh.com/current/index.html)
* [Wazuh & Suricata NIDS Integration Guide](https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html)
* [Suricata Official User Guide & Rule Syntax](https://docs.suricata.io/en/latest/)
* [Ubuntu Official Server Releases](https://releases.ubuntu.com/)
