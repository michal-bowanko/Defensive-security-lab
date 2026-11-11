#  Module 01: pfSense Virtual Gateway & Network Segmentation

![pfSense](https://img.shields.io/badge/pfSense-2.7.0--RELEASE-orange?style=flat-square&logo=pfsense)
![VirtualBox](https://img.shields.io/badge/Hypervisor-Oracle_VirtualBox-blue?style=flat-square&logo=virtualbox)
![Architecture](https://img.shields.io/badge/Architecture-Internal_Segmented_Lab-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Operational-brightgreen?style=flat-square)

> **Document Scope:** Gateway orchestration, network boundary enforcement, stateful packet filtering, and out-of-band serial recovery for the defensive SOC lab.

---

## 1. Network Topology & Traffic Routing

The laboratory uses strict Layer 2 and Layer 3 boundary isolation. All telemetry nodes, controllers, and analyst endpoints communicate exclusively over a host-isolated virtual bus (`intnet`), while pfSense acts as the sole routing gateway, DNS resolver, and outbound NAT provider.

```text
                                  +--------------------------------------------------------------+
                                  |                     External / Host Network                  |
                                  |                   Host Default Gateway & WAN                 |
                                  +------------------------------+-------------------------------+
                                                                 |
                                                                 | (NAT - Adapter 1: em0)
                                                                 v
                                  +--------------------------------------------------------------+
                                  |                   pfSense Perimeter Gateway                  |
                                  |  - IP: 10.0.2.15/24 (WAN DHCP)                               |
                                  |  - IP: 192.168.1.1/24 (LAN Static Gateway)                   |
                                  |  - Core Daemons: pf Packet Filter, Unbound DNS, ISC DHCP     |
                                  +------------------------------+-------------------------------+
                                                                 |
                                                                 | (Internal Bus: intnet - em1)
                                                                 v
                                  +--------------------------------------------------------------+
                                  |                 Isolated SOC Subnet (192.168.1.0/24)         |
                                  |                                                              |
                                  |  [ SIEM / NIDS Node ]      [ Active Directory DC ]           |
                                  |  Ubuntu Server (Wazuh)     Windows Server                    |
                                  |  IP: 192.168.1.102         IP: 192.168.1.10                  |
                                  |                                                              |
                                  |  [ Analyst Workstation ]                                     |
                                  |  Windows Server / Client                                     |
                                  |  DHCP Lease Scope: 192.168.1.10 - 192.168.1.200              |
                                  +--------------------------------------------------------------+
```

---

## 2. Interface Addressing Schema

| Interface Designation | Hardware Identifier | Hypervisor Adapter Mode | IP Allocation | Subnet Role |
| :--- | :---: | :--- | :--- | :--- |
| **WAN** | `em0` | NAT | `10.0.2.15/24` (DHCP) | Outbound routing and upstream package repository updates |
| **LAN** | `em1` | Internal Network (`intnet`) | `192.168.1.1/24` (Static) | Lab default gateway, authoritative DNS resolver, DHCP pool |

---

## 3. Virtual Machine Hardware Profile

| Specification Parameter | Value / Allocation | Operational Context |
| :--- | :--- | :--- |
| **Virtual Machine Name** | `pfSense-Lab` | Hypervisor-level identifier |
| **Guest OS Profile** | FreeBSD (64-bit) | Baseline platform for pfSense Community Edition |
| **Base Memory (RAM)** | **2048 MB** | Accommodates state tables and packet buffer overhead |
| **Storage Capacity** | **20.00 GB** (VDI, IDE Controller) | Dynamic partition for package caching and filter logs |
| **Network Controller Type** | Intel PRO/1000 MT Desktop | Native driver compatibility across FreeBSD kernels |
| **Boot Sequence** | Hard Disk -> Optical | Optimized startup without installation media dependency |

---

## 4. Firewall Rule Matrix & Policy Enforcement

Traffic flow across interfaces adheres to standard least-privilege security postures. The table below represents the baseline rule deployment verified via the WebConfigurator:

| Protocol | Source | Port | Destination | Port | Gateway | Action | Description |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **IPv4 TCP** | `LAN net` | Any | `192.168.1.1` | `80, 443` | `*` | **PASS** | Anti-Lockout Rule: WebConfigurator access from trusted segment |
| **IPv4 UDP** | `LAN net` | Any | `192.168.1.1` | `53` | `*` | **PASS** | Internal DNS Resolution via Unbound daemon |
| **IPv4 UDP** | `LAN net` | Any | `192.168.1.1` | `67, 68` | `*` | **PASS** | Local DHCP requests and lease renewals |
| **IPv4 TCP/UDP** | `LAN net` | Any | `*` | `80, 443` | Default | **PASS** | Outbound Web Traffic (Threat intelligence feeds, OS updates) |
| **IPv4 ICMP** | `LAN net` | Any | `*` | Echo Request | Default | **PASS** | Diagnostic ping verification for reachability tests |
| **ALL** | `*` | Any | `*` | Any | `*` | **BLOCK** | Default Deny: All non-explicitly matched ingress/transit traffic |

---

## 5. Provisioning & Bootstrapping Steps

### 5.1 Serial/Text Console Setup
During the initial appliance bootstrap:
1. Interfaced with the serial bootstrap console to complete NIC mapping:
   - WAN Interface -> `em0`
   - LAN Interface -> `em1`
2. Applied static IPv4 assignment on `em1`: `192.168.1.1/24`.
3. Initialized the integrated ISC DHCP Server engine:
   - **Range:** `192.168.1.10` to `192.168.1.200`
   - **Gateway & DNS Option:** Seeded automatically as `192.168.1.1`

### 5.2 Initial WebConfigurator Hardening
1. Established baseline management session via `https://192.168.1.1` from an internal workstation.
2. Overrode factory administrator authentication keys with high-entropy passphrases.
3. Disabled HTTP-to-HTTPS redirect bypasses and verified TLS certificate warnings.
4. Validated Outbound NAT (Automatic Rules Generation) verifying internal endpoints correctly translate behind `10.0.2.15`.

---

## 6. Operational Guide: pfSense Console Menu Navigation

The serial/text console serves as the primary out-of-band recovery interface in the event of GUI daemon lockouts, rule misconfigurations, or network disconnects.

```text
*** Welcome to pfSense 2.7.0-RELEASE (amd64) on pfSense ***

  WAN (wan) -> em0 -> v4/DHCP4: 10.0.2.15/24
  LAN (lan) -> em1 -> v4: 192.168.1.1/24

 0) Logout / Disconnect SSH          9) pfTop
 1) Assign Interfaces               10) Filter Logs
 2) Set interface(s) IP address     11) Restart GUI
 3) Reset admin account and pass    12) PHP shell + pfSense tools
 4) Reset to factory defaults       13) Update from console
 5) Reboot system                   14) Enable Secure Shell (sshd)
 6) Halt system                     15) Restore recent configuration
 7) Ping host                       16) Restart PHP-FPM
 8) Shell
```

### 6.1 Administrator Command Matrix

| Option | Command Action | Practical Triage Purpose |
| :---: | :--- | :--- |
| **`1`** | **Assign Interfaces** | Re-bind virtual NICs if adapter indices change inside VirtualBox. |
| **`2`** | **Set interface(s) IP address** | Recover gateway addressing or expand DHCP scopes without GUI access. |
| **`3`** | **Reset admin credentials** | Restores root access when administrative keys are lost. |
| **`4`** | **Reset to factory defaults** | Resets system to vanilla state when recovering from unrecoverable misconfigurations. |
| **`5` / `6`** | **Reboot / Halt system** | Clean state unmounting and disk synchronization. |
| **`7`** | **Ping host** | Direct ICMP path verification from the gateway outward (e.g., `8.8.8.8`). |
| **`8`** | **Shell** | Invokes root FreeBSD `tcsh` shell for raw forensic commands (`tcpdump`, `sockstat`, `netstat`). |
| **`9`** | **pfTop** | Real-time CLI socket and state table monitor (similar to `top` for packet flows). |
| **`10`** | **Filter Logs** | Live stream of dropped/passed traffic directly from the `pf` engine. |
| **`11` / `16`** | **Restart GUI / PHP-FPM** | Recycles the web stack if the WebConfigurator becomes unresponsive. |
| **`14`** | **Enable SSH** | Opens secure terminal transport on port 22 for headless management. |

---

## 7. Verification & Diagnostic Scenarios

### Diagnostic 1: Outbound Routing & DNS Resolution Check
To verify that pfSense routes traffic correctly to the external network, execute from Option `8` (Shell):

```bash
# Verify ICMP transit
ping -c 3 8.8.8.8

# Verify DNS resolution pipeline via root servers
drill cloudflare.com @127.0.0.1
```

### Diagnostic 2: Live Traffic Monitoring on Isolated Bus
To inspect live packets flowing through the internal segment without opening Wireshark:

```bash
# Capture first 10 ICMP or HTTP packets on LAN interface
tcpdump -i em1 -nn "icmp or port 80" -c 10
```
---

## 🔗 Official References & Vendor Documentation

* [Netgate pfSense Official Download (Community Edition)](https://www.pfsense.org/download/)
* [pfSense Official Documentation & Administration Manual](https://docs.netgate.com/pfsense/en/latest/)
* [Virtualizing pfSense on Oracle VirtualBox Guide](https://docs.netgate.com/pfsense/en/latest/recipes/virtualize-virtualbox.html)
