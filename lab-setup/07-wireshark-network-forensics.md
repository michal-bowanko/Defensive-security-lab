# Module 07: Wireshark Network Forensics & Deep Packet Inspection

![Wireshark](https://img.shields.io/badge/Tool-Wireshark_v4.x-1679A7?style=flat-square&logo=wireshark&logoColor=white)
![Driver](https://img.shields.io/badge/Capture_Engine-Npcap_OEM-informational?style=flat-square)
![Scope](https://img.shields.io/badge/Analysis-Layer_2_to_7_Forensics-green?style=flat-square)
![Role](https://img.shields.io/badge/SOC_Workflow-PCAP_Triage_%26_Deobfuscation-blue?style=flat-square)

> **Document Scope:** Deployment of Wireshark on the Windows Analyst Node, promiscuous frame acquisition over VirtualBox `intnet`, Berkeley Packet Filters (BPF), protocol analysis matrices, and malware extraction workflows during incident triage.

---

## 1. Role in the SOC Lab & Packet Pipeline

While Suricata monitors the wire in real time to generate automated alerts (`eve.json`), **Wireshark** provides deep, interactive packet-level reconstruction. When an incident occurs (such as a simulated C2 beacon or Kerberos ticket harvest), raw PCAP analysis enables the analyst to reconstruct session streams, inspect malformed payloads, and validate IDS signatures.

```text
                            +--------------------------------------------------------------+
                            |             Virtual Hypervisor Bus ('intnet')                |
                            |  - Raw Layer 2 Ethernet Frames, Broadcasts, Transit Packets  |
                            +------------------------------+-------------------------------+
                                                           |
                                                           | (Promiscuous Acquisition)
                                                           v
                            +--------------------------------------------------------------+
                            |               Npcap Kernel Filter Driver                     |
                            |  - WinPcap Compatibility Mode, Loopback Support              |
                            +------------------------------+-------------------------------+
                                                           |
                                                           | (BPF Capture Filtering)
                                                           v
                            +--------------------------------------------------------------+
                            |             Wireshark Dissector Engine (GUI/CLI)             |
                            |  - Flow Reconstruction (TCP Stream Follow)                   |
                            |  - TLS Handshake & Certificate Inspection                    |
                            |  - Payload Extraction & Decryption Secrets Mapping           |
                            +--------------------------------------------------------------+
```

---

## 2. Installation & Hypervisor Capture Requirements

### 2.1 Npcap Driver Deployment Parameters
During the Wireshark setup on the **Windows Analyst Workstation** (`192.168.1.150`):
1. Execute the installer with administrative privileges.
2. Select **Install Npcap in WinPcap API-compatible Mode** (ensures interoperability with legacy CLI tools like `tshark` and `WinDump`).
3. Check **Support raw 802.11 traffic** and **Restrict Npcap driver's access to Administrators only** for forensic hardening.

### 2.2 VirtualBox Promiscuous Mode Settings
To ensure the analyst node can inspect packets between other hosts (e.g., traffic passing between `WinServer-AD` and `Wazuh_Server`):
* In VirtualBox: `Settings -> Network -> Advanced -> Promiscuous Mode`.
* Change mode from *Deny* to **Allow All** or **Allow VMs**.

---

## 3. High-Value SOC Display Filter Cheat Sheet

During active triage, an analyst filters through hundreds of thousands of frames using specific display queries:

| Investigative Goal | Wireshark Display Filter Syntax | Threat Hunting / Forensic Value |
| :--- | :--- | :--- |
| **Detect Kerberoasting** | `kerberos.msg_type == 12 && kerberos.ticket.etype == 23` | Identifies TGS-REQ packets requesting weak `RC4-HMAC` (etype 23) ticket ciphers. |
| **Identify Cleartext Logins** | `http.request.method == "POST" || ftp || telnet` | Identifies exposed passwords, internal credential passing, or unencrypted web auth. |
| **DNS C2 Tunneling / Beaconing** | `dns.flags.response == 0 && (dns.qry.name.len > 40)` | Flags unusually long subdomains commonly used to exfiltrate data via DNS queries. |
| **Suspicious Executable Transfer** | `http.response.code == 200 && http contains "MZ"` | Identifies active Windows PE binaries transferred over plain HTTP connections. |
| **Detect SYN Port Scans** | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Isolates high-frequency connection attempts originating from port scanning activity. |
| **SMB Lateral Movement** | `smb2.cmd == 5 && smb2.tree contains "C$"` | Tracks administrative share access (`C$`, `ADMIN$`) indicative of PsExec or remote staging. |

---

## 4. Operational Forensic Workflows

### 4.1 Reconstructing Staged Payloads (HTTP/TCP Stream Following)
When triaging payload drops (such as PowerShell stagers or file transfers):
1. Locate the suspicious session frame via:
   ```text
   http.request.method == "GET" || http.request.method == "POST"
   ```
2. Right-click the packet -> **Follow -> TCP Stream**.
3. Toggle data view to **Raw** or **ASCII** to inspect scripts, obfuscated Base64 blobs, or C2 response parameters.
4. Export payload bytes directly: `File -> Export Objects -> HTTP...`.

### 4.2 Automated Batch Analysis via `tshark`
Wireshark includes the `tshark` CLI utility, ideal for scripted analysis without launching the heavy GUI:

```powershell
# Extract all unique DNS queries made by lab endpoints
tshark -r capture.pcap -T fields -e dns.qry.name -Y "dns.flags.response == 0" | Sort-Object -Unique

# Isolate all HTTP GET requests and source IPs
tshark -r capture.pcap -Y "http.request.method == GET" -T fields -e ip.src -e http.host -e http.request.uri
```

---

## 5. Verification & Capture Diagnostic Test

To confirm that the analyst workstation captures live network activity across the virtual segment:

```powershell
# 1. Start a 5-second capture on the primary interface via tshark
tshark -i 1 -a duration:5 -f "icmp" -w ping_test.pcap

# 2. In another prompt, trigger ICMP transit to pfSense
ping -n 2 192.168.1.1

# 3. Read back packet counts
tshark -r ping_test.pcap
```
---

## 🔗 Official References & Vendor Documentation

* [Wireshark Official Download & Release Notes](https://www.wireshark.org/download.html)
* [Npcap Packet Capture Library for Windows](https://npcap.com/)
* [Wireshark User's Guide & Display Filter Reference](https://www.wireshark.org/docs/wsug_html_chunked/)
* [Wireshark Sample Captures Repository](https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures)
