<div align="center">

# DEFENSIVE SECURITY OPERATIONS & DETECTION ENGINEERING LAB
### Enterprise SOC • Threat Hunting • Detection Engineering • Virtual Range

[![VirtualBox](https://img.shields.io/badge/Hypervisor-Oracle_VirtualBox-21416d?style=for-the-badge&logo=virtualbox&logoColor=white)](https://www.virtualbox.org/)
[![pfSense](https://img.shields.io/badge/Gateway-pfSense_CE_v2.7-eb5e28?style=for-the-badge&logo=pfsense&logoColor=white)](https://www.pfsense.org/)
[![Active Directory](https://img.shields.io/badge/Identity-Active_Directory_DS-0078d4?style=for-the-badge&logo=windows&logoColor=white)](https://learn.microsoft.com/)
[![Wazuh](https://img.shields.io/badge/SIEM%2FXDR-Wazuh_v4.x-00a4e4?style=for-the-badge&logo=wazuh&logoColor=white)](https://wazuh.com/)
[![Suricata](https://img.shields.io/badge/NIDS-Suricata_Engine-ef3b24?style=for-the-badge)](https://suricata.io/)
[![CrowdSec](https://img.shields.io/badge/Threat_Intel-CrowdSec_LAPI-ff6f00?style=for-the-badge&logo=crowdsec&logoColor=white)](https://crowdsec.net/)
[![Wireshark](https://img.shields.io/badge/Packet_Forensics-Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)](https://www.wireshark.org/)

<p align="center">
  <b>Segmented Enterprise Cyber Range reproducing real-world enterprise infrastructure, end-to-end telemetry pipelines, and hands-on offensive threat simulations.</b>
</p>

---

</div>

##  Executive Summary

This repository documents the architecture, implementation, and operational workflows of a private **Security Operations Center (SOC) & Adversary Simulation Laboratory** built natively on **Oracle VirtualBox**.

The objective of this range is not merely running security tools, but engineering the entire **Detection & Response Lifecycle**:
* Deploying zero-trust perimeter segmentation via a virtualized stateful firewall.
* Collecting kernel-level host artifacts (`Sysmon`) and raw wire payloads (`Suricata`).
* Correlating endpoint behavior with Active Directory Kerberos identity planes inside `Wazuh SIEM`.
* Simulating real-world intrusion vectors, staging attacks, and authoring actionable detection signatures.

---


##  Threat Simulation & Incident Response Portfolio

Every attack conducted in this range is systematically documented through triage logs, packet traces, and detection logic:

```text
[ Threat Ingestion ] ──> [ Wire/Host Detection ] ──> [ SIEM Alert Triaged ] ──> [ Mitigation Engineered ]
```


| ID | Incident / Attack Scenario | Threat Actor Profile | MITRE ATT&CK Tactic | Investigation Report |
| :---: | :--- | :--- | :--- | :---: |
| `SIM-01` | BlackSun RCE & C2 Staging | Commodity Ransomware / Initial Access | `T1059.001` (PowerShell)<br>`T1071.001` (Web Protocols) | [📄 View Incident Report](./simulations/SIM-01-blacksun-rce/README.md) |
| `SIM-02` | Active Directory SMB Brute-Force | Credential Access / Lateral Movement | `T1110.001` (Password Guessing)<br>`T1531` (Account Lockout) | [📄 View Incident Report](./simulations/SIM-02-smb-bruteforce/README.md) |
| `SIM-03` | Active Directory Kerberoasting (RC4 Downgrade) | Credential Access / Offline Hash Cracking | `T1558.003` (Kerberoasting)<br>`T1087.002` (Domain Account Discovery) | [📄 View Incident Report](./simulations/SIM-03-kerberoasting/README.md) |

---
##  Defense-in-Depth Architecture

```text
                      ================================== [ PERIMETER / WAN ] ==================================
                                                                  │
                                                        [ NAT Gateway Adapter ]
                                                                  ▼
                                          ┌───────────────────────────────────────────────┐
                                          │            pfSense Virtual Firewall           │
                                          │   WAN: 10.0.2.15/24  |  LAN: 192.168.1.1/24   │
                                          │   Anti-Lockout • DNS Resolver • ISC DHCP      │
                                          └───────────────────────┬───────────────────────┘
                                                                  │
                      ================================ [ ISOLATED BUS: intnet ] ================================
                                                                  │
                                ┌─────────────────────────────────┼─────────────────────────────────┐
                                ▼                                 ▼                                 ▼
                      ┌──────────────────┐              ┌──────────────────┐              ┌──────────────────┐
                      │   WinServer-AD   │              │   Wazuh_Server   │              │  Win-Workstation │
                      │ 192.168.1.10/24  │              │ 192.168.1.102/24 │              │ 192.168.1.150/24 │
                      │ Active Directory │              │ Wazuh SIEM / XDR │              │ Analyst Console  │
                      │ Kerberos KDC     │              │ Suricata NIDS    │              │ Sysmon Monitored │
                      │ Advanced Auditing│              │ CrowdSec LAPI    │              │ Attack Surface   │
                      └─────────┬────────┘              └─────────▲────────┘              └─────────┬────────┘
                                │                                 │                                 │
                                └────────────────────[ Agent Logs / TCP 1514 ] ─────────────────────┘
```

---

##  Laboratory Blueprint & Node Breakdown

Click any module badge to jump into the technical build specifications, command runbooks, and failure-mode recovery guides:

<details open>
<summary><b>🔹 Core Infrastructure & Security Nodes</b></summary>
<br>

* **[ Module 01: pfSense Virtual Gateway](./lab-setup/01-pfsense-firewall.md)**
  * **Role:** Perimeter Boundary, DHCP Pool (`.10–.200`), NAT Routing, Stateful Packet Filtering.
  * **Highlights:** Out-of-band serial recovery console cheat sheet, triage procedures, and firewall rule matrix.

* **[ Module 02: Wazuh SIEM & Suricata NIDS Engine](./lab-setup/02-wazuh-siem-suricata.md)**
  * **Role:** Central Ingestion Hub, Promiscuous Sniffing, Threat Correlation Engine.
  * **Highlights:** Suricata `eve.json` bridge, LVM root partition exhaustion triage, and Windows-to-Linux remote SSH configuration.

* **[ Module 03: Windows Analyst Node & Workstation](./lab-setup/03-windows-analyst-node.md)**
  * **Role:** Primary Triage Workstation, Domain Member, Attack Testbed.
  * **Highlights:** Domain join verification, native Windows Terminal setup, Wireshark and Sysinternals suite integration.

* **[ Module 04: Active Directory Domain Services](./lab-setup/04-active-directory-domain-services.md)**
  * **Role:** Identity Provider (`corp.local`), Kerberos KDC, Authoritative DNS, Forest Root.
  * **Highlights:** Advanced Security Audit GPO policies (EID 4688 with CommandLine, 4768, 4769), vulnerable SPN service accounts for Kerberoasting tests.

* **[ Module 05: Sysmon Advanced Host Telemetry](./lab-setup/05-sysmon-host-telemetry.md)**
  * **Role:** Kernel-Level Process & Socket Telemetry Provider.
  * **Highlights:** SwiftOnSecurity baseline tuning, Event Channel forwarding to Wazuh, and MITRE-mapped EID tracking.

* **[ Module 06: CrowdSec IPS & Threat Intelligence](./lab-setup/06-crowdsec-ips-threat-intelligence.md)**
  * **Role:** Behavioral Remediation & Community Consensus Reputation.
  * **Highlights:** Local API (LAPI) orchestration, automated firewall bouncer bans, and custom acquisition parsing.

* **[ Module 07: Wireshark Network Forensics](./lab-setup/07-wireshark-network-forensics.md)**
  * **Role:** Deep Packet Inspection (DPI), Npcap driver acquisition, PCAP artifact extraction.
  * **Highlights:** High-value SOC display filter matrix, Kerberos/DNS C2 triage, and automated CLI workflows with `tshark`.

</details>

---
