# WikiRecon 📡

A modular, multi-threaded CLI network reconnaissance framework written in Python for Linux systems.

WikiRecon provides an interactive CLI interface for fast local network discovery, TCP port scanning, service banner grabbing, and ICMP route discovery. It features a shared in-memory pipeline (`memory.py`) that stores discovered targets across modules to enable smooth, chainable security assessments.

---

## 🏗️ Project Architecture

```text
.
├── main.py                     # Primary Application Entry Point
├── confs.py                    # Configuration & Network Interface Handler
├── memory.py                   # In-Memory Session Pipeline for Targets & Results
└── scanners/                   # Core Reconnaissance Modules
    ├── scanning.py             # Scanning Orchestrator & CLI Sub-Menu
    ├── arp_scanner.py          # Fast Multi-threaded ARP Subnet Discovery
    ├── portscanner.py          # TCP Port Enumeration Engine
    ├── banner_grabber.py       # Service Banner Grabbing & Version Detector
    ├── traceroute.py           # ICMP Network Hop & Route Discovery
    └── automated_full_scan.py  # Full Automated Reconnaissance Pipeline
```

## ✨ Key Features

* **ARP Subnet Discovery:** Scans local subnets (`/24`) using multi-threaded ARP request/reply handling.
* **TCP Port Enumeration:** Fast TCP scanning to identify open ports and map standard services.
* **Service Banner Grabbing:** Banner extraction on open ports for precise service version fingerprinting.
* **ICMP Route Discovery:** Custom traceroute engine tracking network packet hops.
* **Session Memory Pipeline:** Passes active hosts and open ports automatically between scanning modules.
* **Automated Full Pipeline:** Sequential discovery, port scanning, and banner grabbing in one automated run.

## 🚀 Installation & Prerequisites

### Prerequisites

* **Operating System:** Linux
* **Python:** Python 3.8+
* **Permissions:** Root privileges (`sudo`) required for socket operations and ARP frame manipulation.

### Installation

```bash
# 1. Clone the Repository
git clone https://github.com/y1hng/WikiRecon.git
cd WikiRecon

# 2. Install Required Dependencies
pip install colorama scapy

# 3. Launch WikiRecon
sudo python3 main.py
```

## ⚙️ Usage Overview

1. Run `main.py` as root.
2. Go to **`02. CONFS`** to review or set network interface and gateway parameters.
3. Access **`01. SCANNERS`** to choose your module:

   * **ARP Scanning:** Discover live hosts on the local network.
   * **Port Scanning:** Scan saved target IPs or enter custom ones.
   * **Banner Grabber:** Grabs versions of open ports saved in memory.
   * **Traceroute:** Trace packet hops to a target IP.
   * **Full Nmapping:** Run an automated end-to-end recon scan.

## ⚠️ Legal Disclaimer

WikiRecon is developed strictly for educational, security research, and authorized testing purposes on networks you own or have explicit permission to audit. The author assumes no responsibility for unauthorized use.

## 📜 License

Distributed under the MIT License.
