#  Module 04: Active Directory Domain Services (AD DS) Deployment

![Windows Server](https://img.shields.io/badge/OS-Windows_Server-0078D6?style=flat-square&logo=windows)
![Role](https://img.shields.io/badge/Role-Domain_Controller_(AD_DS)-red?style=flat-square)
![Hypervisor](https://img.shields.io/badge/Hypervisor-Oracle_VirtualBox-blue?style=flat-square&logo=virtualbox)
![Network](https://img.shields.io/badge/Segment-intnet_(Internal)-green?style=flat-square)

> **Document Scope:** Provisioning of primary Identity Provider (IdP), Kerberos authentication mechanisms, Active Directory Domain Services (AD DS), DNS namespace delegation, and security audit log generation for the SOC environment.

---

## 1. Network Topology & Identity Plane

The Domain Controller operates as the core identity boundary inside the isolated virtual network segment (`intnet`). It provides centralized identity resolution, group policy enforcement, and authentication telemetry for analysis nodes.

```text
                              +--------------------------------------------------------------+
                              |                   pfSense Perimeter Gateway                  |
                              |                   IP: 192.168.1.1 (Gateway)                  |
                              +------------------------------+-------------------------------+
                                                             |
                                                             | (Internal Bus: intnet)
                                                             v
                              +--------------------------------------------------------------+
                              |           WinServer-AD (Domain Controller Node)              |
                              |  - Hostname: WinServer-AD                                    |
                              |  - IP: 192.168.1.10/24 (Static)                              |
                              |  - Primary DNS: 127.0.0.1 (Loopback / Local AD DNS)          |
                              |  - Forwarder: 192.168.1.1 (pfSense Unbound Resolver)         |
                              |  - Managed Realm: corp.local (Kerberos KDC / LDAP)           |
                              +------------------------------+-------------------------------+
                                                             ^
                                                             | (Domain Authentication & Telemetry)
                                                             |
                              +------------------------------+-------------------------------+
                              |                 Domain Member Workstations                   |
                              |  - Windows Workstation / Analyst Endpoints                   |
                              |  - DHCP Leased Addresses (192.168.1.10 - .200)               |
                              +--------------------------------------------------------------+
```

---

## 2. Virtual Machine Hardware Profile

Parameters provisioned within Oracle VirtualBox according to laboratory specifications:

| Specification Parameter | Value / Allocation | Operational Context |
| :--- | :--- | :--- |
| **Virtual Machine Name** | `WinServer-AD` | Hypervisor-level identifier |
| **Guest OS Profile** | Windows 10 / Server (64-bit) | Base architecture hosting Windows Server core services |
| **Processor Allocation** | **2 vCPUs** | Handles multithreaded directory queries and audit logging |
| **Base Memory (RAM)** | **2048 MB** | Minimum allocation for AD DS and local DNS caches |
| **Storage Capacity** | **50.00 GB** (SATA Port 0, Dynamic VDI) | Space for NTDS.dit database, SYSVOL, and event logs |
| **Storage Controller** | AHCI SATA Controller | High-performance disk subsystem |
| **Optical Drive** | `VBoxGuestAdditions.iso` (SATA Port 1) | Shared folder and display integration utilities |
| **Network Adapter** | Intel PRO/1000 MT Desktop | Bound directly to Internal Network (`intnet`) |
| **Paravirtualization** | Hyper-V Paravirtualization | Optimized interface handling under Windows kernels |

---

## 3. Network Configuration & Static IP Schema

Because Active Directory relies entirely on authoritative DNS resolution, dynamic IP allocation is disabled on this node:

| Interface Parameter | Value | Technical Justification |
| :--- | :--- | :--- |
| **IPv4 Address** | `192.168.1.10` | Static lease reserved outside default DHCP dynamic pool |
| **Subnet Mask** | `255.255.255.0` (`/24`) | Matches `intnet` subnet definition |
| **Default Gateway** | `192.168.1.1` | Points to pfSense LAN interface for WAN routing |
| **Preferred DNS Server**| `127.0.0.1` (or `192.168.1.10`) | Points to local DNS for SRV record registration |
| **Alternate DNS Server**| `192.168.1.1` | Upstream fallback resolver on pfSense |

---

## 4. Role Deployment & Forest Promotion

### 4.1 Installing Server Roles via PowerShell
The required roles and administrative tools were installed via administrative PowerShell:

```powershell
Install-WindowsFeature -Name AD-Domain-Services, DNS -IncludeManagementTools -Verbose
```

### 4.2 Forest Promotion Execution
The server was promoted to the primary Domain Controller of a new forest using the deployment wizard:
* **Deployment Operation:** Add a new forest
* **Root Domain Name:** `corp.local`
* **Forest Functional Level:** Windows Server 2016 / 2019
* **Domain Functional Level:** Windows Server 2016 / 2019
* **Additional Options:** Integrated DNS Server checked, Global Catalog (GC) enabled.
* **SYSVOL / NTDS Path:** Default `C:\Windows\NTDS` and `C:\Windows\SYSVOL`.

---

## 5. Security Auditing & Advanced GPO Configuration

Standard Windows installations do not log high-fidelity forensic data. To prepare the lab for SOC attack simulations, the Advanced Audit Policy was configured under `Default Domain Controllers Policy`:

| Audit Category | Policy Subcategory | Setting | Monitored Security Event IDs |
| :--- | :--- | :---: | :--- |
| **Account Logon** | Audit Kerberos Authentication Service | Success & Failure | **EID 4768** (TGT Request), **EID 4771** (Pre-auth failed) |
| **Account Logon** | Audit Kerberos Service Ticket Operations | Success & Failure | **EID 4769** (Service Ticket / Kerberoasting indicator) |
| **Logon/Logoff** | Audit Logon | Success & Failure | **EID 4624** (Successful Logon), **EID 4625** (Failed Logon) |
| **Logon/Logoff** | Audit Special Logon | Success | **EID 4672** (Administrator privilege assigned) |
| **Detailed Tracking**| Audit Process Creation | Success | **EID 4688** (Process launch with CommandLine metadata) |
| **Account Management**| Audit User Account Management | Success & Failure | **EID 4720** (User created), **EID 4726** (User deleted) |

---

## 6. Directory Object Staging (Lab Users & OUs)

To simulate enterprise directory structure and enable credential attacks (e.g., Kerberoasting, AS-REP Roasting), standard Organizational Units (OUs) and service accounts were populated:

```powershell
# Create Organizational Units
New-ADOrganizationalUnit -Name "SOC_Users" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Service_Accounts" -Path "DC=corp,DC=local"

# Create a vulnerable Service Principal Name (SPN) account for Kerberoasting tests
New-ADUser -Name "svc_sqlservice" `
           -AccountPassword(ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
           -Enabled $true `
           -Path "OU=Service_Accounts,DC=lab,DC=local"

# Assign Service Principal Name (SPN)
Set-ADUser -Identity "svc_sqlservice" -ServicePrincipalNames @{Add="MSSQLSvc/db01.corp.local:1433"}
```

---

## 7. Verification & Health Diagnostic Procedures

### Diagnostic 1: Active Directory Web Services & SRV Record Check
Verify that directory services and DNS records for Kerberos are resolving correctly:

```powershell
# Check Directory Service operational state
Get-Service adws, ntds, kdc, dns | Select-Object Name, Status, StartType

# Query authoritative SRV record for Kerberos Key Distribution Center (KDC)
nslookup -type=srv _kerberos._tcp.lab.local
```

### Diagnostic 2: Testing Domain Functionality & Replication State
Run standard diagnostic checks from command line:

```cmd
dcdiag /v
netdom query fsmo
```
---

## 🔗 Official References & Vendor Documentation

* [Microsoft Evaluation Center (Windows Server ISO)](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server)
* [Active Directory Domain Services Overview & Architecture](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services)
* [Microsoft Security Guidance: Advanced Security Audit Policies](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policies)
* [Kerberos Authentication Technical Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
