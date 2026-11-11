#  Module 03: Windows Analyst Node & Workstation Deployment

![Windows](https://img.shields.io/badge/OS-Windows_10%2F11-0078D6?style=flat-square&logo=windows)
![Role](https://img.shields.io/badge/Role-Analyst_Workstation_%26_Domain_Member-blue?style=flat-square)
![Hypervisor](https://img.shields.io/badge/Hypervisor-Oracle_VirtualBox-blue?style=flat-square&logo=virtualbox)
![Network](https://img.shields.io/badge/Segment-intnet_(Internal)-green?style=flat-square)

> **Document Scope:** Provisioning of the tier-1 analyst workstation, base OS installation parameters, network adaptation for internal segmentation, Active Directory domain join procedures, endpoint telemetry agent deployment, and forensic utility configuration.

---

## 1. Architectural Role in the SOC Lab

The Windows Analyst Workstation fulfills a dual purpose within the laboratory environment:

1. **Analyst Management Station:** Acts as the primary operations console for accessing the pfSense WebConfigurator, running native Windows Terminal SSH sessions to the Wazuh SIEM collector, and inspecting packet captures in Wireshark.
2. **Telemetry Generation & Attack Target:** Configured as an authenticated domain member of `lab.local` to produce legitimate workstation telemetry (user logons, process trees, network sockets) and serve as a safe target for simulated endpoint attacks and execution tests.

---

## 2. Virtual Machine Hardware Profile

| Specification Parameter | Value / Allocation | Operational Context |
| :--- | :--- | :--- |
| **Virtual Machine Name** | `Win-Workstation` | Hypervisor-level identifier |
| **Guest OS Profile** | Windows 10 / 11 (64-bit) | Standard client platform profile |
| **Processor Allocation** | **2 vCPUs** | Smooth local GUI execution and tooling |
| **Base Memory (RAM)** | **4096 MB** | Handles analysis tools (Wireshark, browser, terminals) simultaneously |
| **Storage Capacity** | **50.00 GB** (VDI, Dynamic Allocation) | Workspace for OS, logs, capture artifacts, and tool suites |
| **Storage Controller** | AHCI SATA Controller | Optimized disk I/O performance |
| **Optical Drive** | `VBoxGuestAdditions.iso` | Driver guest additions for resolution and clipboard sharing |
| **Network Adapter** | Intel PRO/1000 MT Desktop | Bound directly to Internal Network (`intnet`) |
| **Paravirtualization** | Hyper-V Paravirtualization | Native hypervisor acceleration for Windows guests |

---

## 3. Operating System Installation Step-by-Step

### 3.1 Initial Setup & OOBE Bypass
1. Mounted the official Windows installation ISO to the virtual optical drive and booted the machine.
2. Selected language preferences, keyboard mapping, and chose **Custom: Install Windows only (advanced)**.
3. Allocated the unallocated 50.00 GB virtual drive without manual partitioning (installer creates default EFI, MSR, and NTFS partitions automatically).
4. During Out-of-Box Experience (OOBE):
   * Selected **Set up for work or school** or **Domain join instead** (offline local account creation) to prevent mandatory Microsoft Account requirement.
   * Created a local provisioning account: `analyst_local`.

### 3.2 Guest Additions Installation
To optimize display drivers and mouse integration inside VirtualBox:
1. Navigated to VirtualBox menu: `Devices -> Insert Guest Additions CD image...`.
2. Opened `D:\VBoxWindowsAdditions.exe` and completed the standard driver wizard.
3. Rebooted the workstation.

---

## 4. Network Adapter & DNS Configuration

Because the node resides on the isolated `intnet` virtual bus, its network settings must strictly align with both the pfSense gateway and the Active Directory Domain Controller (`WinServer-AD`).

### 4.1 Interface Parameters Matrix

| Setting | Configuration Mode | Assigned Value | Operational Purpose |
| :--- | :---: | :--- | :--- |
| **IP Allocation** | Static or DHCP Reservation | `192.168.1.150/24` | Stable address within `intnet` subnet |
| **Subnet Mask** | Fixed | `255.255.255.0` | Matches internal segment netmask |
| **Default Gateway** | Fixed | `192.168.1.1` | Points to pfSense LAN interface for outbound access |
| **Preferred DNS** | **Mandatory Static** | **`192.168.1.10`** | **Points to WinServer-AD (AD DS DNS)** |
| **Alternate DNS** | Optional Fallback | `192.168.1.1` | pfSense Unbound resolver |

> **Critical DNS Requirement:** To join the Active Directory domain `lab.local`, the primary DNS **must** point to the Domain Controller (`192.168.1.10`). Pointing DNS to pfSense or public resolvers will prevent discovery of the domain SRV records.

### 4.2 Configuring Network via Administrative PowerShell
```powershell
# Identify interface index
Get-NetAdapter

# Apply static IP, subnet mask, and gateway
New-NetIPAddress -InterfaceIndex 1 -IPAddress 192.168.1.150 -PrefixLength 24 -DefaultGateway 192.168.1.1

# Point primary DNS directly to Domain Controller
Set-DnsClientServerAddress -InterfaceIndex 1 -ServerAddresses ("192.168.1.10", "192.168.1.1")
```

---

## 5. Active Directory Domain Join Workflow

### 5.1 Verification of Domain Controller Reachability
Before initiating the join operation, verify that the workstation can locate the domain controller via Kerberos SRV records and ICMP:

```powershell
# Verify gateway connectivity
Test-Connection 192.168.1.1 -Count 2

# Verify Domain Controller reachability
Test-Connection 192.168.1.10 -Count 2

# Resolve authoritative Kerberos SRV records
Resolve-DnsName -Name _ldap._tcp.dc._msdcs.lab.local
```

### 5.2 Executing Domain Join
Join the machine to `lab.local` using domain administrator credentials:

```powershell
Add-Computer -DomainName "lab.local" -Restart
```

Upon system reboot, the node authenticates using domain credentials:
* **Logon Format:** `LAB\analyst` or `LAB\Administrator`
* **Kerberos Ticket Verification:**
  ```cmd
  klist
  ```

---

## 6. Telemetry Agent & Tooling Deployment

### 6.1 Wazuh Endpoint Agent Installation
To forward Windows Security events, System logs, and operational telemetry to `Wazuh_Server` (`192.168.1.102`):

```powershell
# Download Wazuh Windows Agent installer
Invoke-WebRequest -Uri [https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.msi](https://packages.wazuh.com/4.x/windows/wazuh-agent-4.x.msi) -OutFile wazuh-agent.msi

# Perform headless installation pointed to Wazuh Manager
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="192.168.1.102" WAZUH_REGISTRATION_SERVER="192.168.1.102" WAZUH_AGENT_NAME="Win-Workstation"

# Start the agent service
Start-Service -Name "Wazuh"
```

Verify agent connectivity status:
```powershell
Get-Service -Name "Wazuh" | Select-Object Name, Status, StartType
```

### 6.2 Analyst Forensic Utility Suite
Installed essential defensive investigation tools:
* **Wireshark & Npcap:** For deep packet inspection and PCAP analysis directly within the internal segment.
* **Windows Terminal:** Multi-tab console management for executing concurrent SSH connections to `Wazuh_Server` (`192.168.1.102`).
* **Sysinternals Suite:** Local process monitoring via `Process Hacker` / `Process Explorer` and `TCPView` to observe socket states in real time.

---

## 7. Verification & Operational Health Check

```powershell
# 1. Verify Domain Membership
(Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain
# Expected output: True

# 2. Verify Outbound Network Routing via pfSense
Test-NetConnection -ComputerName 8.8.8.8 -Port 53

# 3. Verify Active Telemetry Socket to Wazuh SIEM
Test-NetConnection -ComputerName 192.168.1.102 -Port 1514
# Expected output: TcpTestSucceeded : True
```
---

## 🔗 Official References & Vendor Documentation

* [Microsoft Evaluation Center (Windows Enterprise ISO)](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-10-enterprise)
* [Wazuh Windows Agent Installation & Configuration Guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
* [Microsoft Sysinternals Utilities Suite Download](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
* [Microsoft Learn: Join a Computer to an Active Directory Domain](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/join-a-computer-to-a-domain)
