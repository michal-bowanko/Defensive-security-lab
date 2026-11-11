#  Module 06: CrowdSec IPS & Collaborative Threat Intelligence

![CrowdSec](https://img.shields.io/badge/Component-CrowdSec_Security_Engine-FF6F00?style=flat-square&logo=crowdsec)
![Role](https://img.shields.io/badge/Role-Behavioral_IPS_%26_Threat_Intel-blueviolet?style=flat-square)
![Integration](https://img.shields.io/badge/Remediation-Firewall_Bouncer-blue?style=flat-square)
![Telemetry](https://img.shields.io/badge/Intelligence-CrowdSec_Community_Network-success?style=flat-square)

> **Document Scope:** Deployment of the modern behavioral Intrusion Prevention System (IPS), log acquisition parsing, local alert management (LAPI), remediation bouncer integration, and collaborative community threat intelligence synchronization within the SOC lab.

---

## 1. Architectural Role in the Defensive Stack

While Suricata monitors raw packet payloads for static CVE signatures and Wazuh analyzes internal system logs, **CrowdSec** introduces modern, behavioral detection and real-time community-driven IP reputation:

* **Behavioral Analysis:** Detects attack scenarios regardless of payload obfuscation (e.g., HTTP brute force, credential stuffing, aggressive scanning, crawlers).
* **Decoupled Architecture:** Separates detection (Security Engine) from enforcement (Bouncers / Remediation Components).
* **Consensus Threat Intelligence:** Subscribes to a global consensus feed of validated malicious IPs while sharing anonymized signals back to the community defense network.

```text
                                  +--------------------------------------------------------------+
                                  |                  Log Acquisition Pipeline                    |
                                  |  - /var/log/auth.log, web logs, pfSense syslog, eve.json     |
                                  +------------------------------+-------------------------------+
                                                                 |
                                                                 | (Acquisition Engine)
                                                                 v
                                  +--------------------------------------------------------------+
                                  |             CrowdSec Engine (Parsers & Scenarios)            |
                                  |  - CrowdSec Parsers (syslog, ssh, nginx, http)               |
                                  |  - Scenario Matching (e.g., ssh-bf, http-crawl)              |
                                  +------------------------------+-------------------------------+
                                                                 |
                                                                 | (Alerts & Decisions)
                                                                 v
                                  +--------------------------------------------------------------+
                                  |             CrowdSec Local API Engine (LAPI)                 |
                                  |  - Local Decision Storage (Bans, Captchas)                   |
                                  |  - Bi-directional Community Blocklist Synchronization        |
                                  +------------------------------+-------------------------------+
                                                                 |
                                                                 | (API Decision Polling)
                                                                 v
                                  +--------------------------------------------------------------+
                                  |             Remediation Component (Bouncer)                  |
                                  |  - Firewall Bouncer (nftables / iptables / pfSense)          |
                                  |  - Dropping / Rejecting Packets at Network Boundary          |
                                  +--------------------------------------------------------------+
```

---

## 2. Core Subsystems & Components

| Component | Operational Layer | Functional Role in the SOC Lab |
| :--- | :--- | :--- |
| **Security Engine (`crowdsec`)** | Host / Container | Ingests raw logs, normalizes lines via grok patterns, and passes events to behavioral scenario state machines. |
| **Local API (LAPI)** | Controller Layer | Stores active remediation decisions in an internal SQLite database and exposes an authenticated REST API for bouncers. |
| **Central API (CAPI)** | Cloud Service | Synchronizes threat intelligence: downloads consensus blocklists and reports locally validated aggressors. |
| **Remediation Bouncer** | Network / Kernel | Queries LAPI periodically and programs firewall tables (`pf` on FreeBSD or `nftables` on Linux) to drop malicious traffic. |

---

## 3. Provisioning & Engine Installation (Ubuntu SIEM Node)

The CrowdSec Security Engine was installed directly on `Wazuh_Server` (`192.168.1.102`), co-located with the central logging pipelines.

### 3.1 Repository Onboarding & Package Installation
```bash
# Add official CrowdSec package repository
curl -s [https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh] | sudo bash

# Install the CrowdSec Security Engine
sudo apt install crowdsec -y
```

### 3.2 Service Initialization & Health Verification
Verify that the CrowdSec daemon and its local API server are active:

```bash
sudo systemctl status crowdsec
```

---

## 4. Collection Acquisition & Hub Configuration

CrowdSec utilizes modular "Collections" (packaged sets of parsers and scenarios) managed through the `cscli` CLI interface.

### 4.1 Installing Base Detection Collections
```bash
# Update community hub index
sudo cscli hub update

# Install essential protection collections
sudo cscli collections install crowdsecurity/linux
sudo cscli collections install crowdsecurity/sshd
sudo cscli collections install crowdsecurity/http-cve

# Restart engine to activate parsers
sudo systemctl restart crowdsec
```

### 4.2 Configuring Custom Log Acquisition (`acquis.yaml`)
To monitor SSH and authentication logs across the Linux environment, configure `/etc/crowdsec/acquis.yaml`:

```yaml
filenames:
  - /var/log/auth.log
  - /var/log/syslog
labels:
  type: syslog
---
filenames:
  - /var/log/suricata/eve.json
labels:
  type: json
```

Reload acquisition settings:
```bash
sudo systemctl reload crowdsec
```

---

## 5. Remediation Bouncer Setup (Firewall Enforcement)

To automatically drop packets matching active decisions, deploy the firewall bouncer:

```bash
# Install the nftables/iptables firewall remediation bouncer
sudo apt install crowdsec-firewall-bouncer-nftables -y

# Verify bouncer registration against LAPI
sudo cscli bouncers list
```

Expected output:
```text
----------------------------------------------------------------------------------------------------------------
 Name                                 IP Address  Valid  Last API Pull         Type             Version
----------------------------------------------------------------------------------------------------------------
 cs-firewall-bouncer-1718000000       127.0.0.1   ✔      2026-10-28T12:00:00Z  crowdsec-firewall-bouncer  v0.0.28
----------------------------------------------------------------------------------------------------------------
```

---

## 6. Threat Intelligence & Community Consensus Feeds

Enroll the engine with the CrowdSec Central API to enable bidirectional threat intelligence:

```bash
# Register instance and retrieve community blocklist
sudo cscli capi register
sudo cscli capi status
```

CrowdSec automatically downloads lists of confirmed malicious IPs, which the firewall bouncer loads into memory sets to preemptively block attacks before local detection triggers.

---

## 7. Verification & Diagnostic Scenarios

### Diagnostic 1: Simulating an Inbound Attack & Inspecting Decision Creation
Simulate a manual ban decision against an untrusted test IP:

```bash
# Manually add a 4-hour ban decision
sudo cscli decisions add --ip 198.51.100.23 --reason "SOC Lab Manual Triage Test" --duration 4h

# Inspect active remediation decisions
sudo cscli decisions list
```

### Diagnostic 2: Checking Real-time Log Stream & Parsing Metrics
Verify how many lines the acquisition engine processes:

```bash
sudo cscli metrics
```

### Diagnostic 3: Removing Triage Test Decisions
Clean up test telemetry decisions after verification:

```bash
# Delete the simulated decision
sudo cscli decisions delete --ip 198.51.100.23
```
---

## 🔗 Official References & Vendor Documentation

* [CrowdSec Official Architecture & Documentation](https://docs.crowdsec.net/)
* [CrowdSec Hub (Parsers, Scenarios, & Collections Directory)](https://hub.crowdsec.net/)
* [CrowdSec Remediation Components (Bouncers) Overview](https://docs.crowdsec.net/u/bouncers/intro)
* [CrowdSec Community Console](https://app.crowdsec.net/)
