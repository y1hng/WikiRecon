<div style="font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.7; color: #d4d4d4; background: #1e1e1e; padding: 2rem; border-radius: 12px; max-width: 900px; margin: auto;">

# <span style="color: #4fc3f7; border-bottom: 2px solid #4fc3f7; padding-bottom: 6px;">WikiRecon</span>

A recon framework written in Python for Linux OS.

WikiRecon provides a simple interactive CLI interface for LAN discovery.

## <span style="color: #81c784;">Features</span>

* **ARP SCANNER**
* **PORT SCANNER**
* **BANNER GRABBER**
* **TRACEROUTE**
* **Automated Full Scan**

In full scan, you can just run it and it scans the route of packets to `8.8.8.8` (and you can change it for a custom IP in `scanners/automated_full_scan.py`). It scans the LAN searching for active devices, then scans the top 1000 ports in every device across all discovered devices, and finally gets the version of open services.

After that, it generates **JSON**, **HTML**, and **CSV** files of the results.

---

## <span style="color: #81c784;">Output Example (JSON)</span>

JSON file looks like this:

```json
{
    "timestamp": "2026-09-27 14:42:34",
    "traceroute": [
        "10.0.0.1",
        "192.168.1.1",
        "XX.XX.XX.1",
        "10.XX.XX.XX",
        "XX.20.XX.XX",
        "XX.XX.174.XX",
        "8.8.8.8"
    ],
    "network_devices": [
        {
            "ip": "10.0.0.1",
            "mac": "XX:XX:XX:XX:XX:XX"
        },
        {
            "ip": "10.0.0.109",
            "mac": "XX:XX:XX:XX:XX:XX"
        }
    ],
    "port_scan_results": {
        "10.0.0.1": [
            {
                "port": 22,
                "service": "SSH"
            },
            {
                "port": 80,
                "service": "HTTP"
            }
        ],
        "10.0.0.109": []
    },
    "banner_results": {
        "10.0.0.1": {
            "22": {
                "service": "ssh",
                "version": "SSH-2.0-OpenSSH_10.0"
            },
            "80": {
                "service": "http",
                "version": "Router Webserver"
            }
        }
    }
}
```

## <span style="color: #81c784;">Architecture</span>

In code, I use a memory file to share information (IPs, PORTS, VERSIONS...) with other modules.

Variables of memory file:

`ACTIVE_devices = []` — for registering IPs and MACs of active devices.

`ips = []` — for only IPs of active devices.

`PACKETS_ROUTE = []` — for IPs of servers and routers (switches) in your route to the internet (8.8.8.8).

`DEVICE_PORTS = dict()` — for devices and their open ports.

`device_version = {}` — for devices, ports, and versions of services on those ports.

## <span style="color: #81c784;">Prerequisites</span>

**Operating System:** Linux

**Python:** Python 3.8+

**Permissions:** Root privileges (sudo) required for packet crafting operations.

**Note:** This project is a personal project, not a stable code for all uses and environments.

## <span style="color: #81c784;">Installation & Usage</span>

**Bash**

```bash
# 1. Clone the Repository
git clone https://github.com/y1hng/WikiRecon.git https://github.com/y1hng/WikiRecon.git
cd WikiRecon

# 2. Install Required Dependencies
pip install colorama scapy

# 3. Launch WikiRecon
sudo python3 main.py
```

## <span style="color: #ffb74d;">⚠️ Legal Disclaimer</span>

WikiRecon is developed strictly for educational, security research, and authorized testing purposes on networks you own or have explicit permission to audit. The author assumes no responsibility for unauthorized use.

## <span style="color: #ffb74d;">📜 License</span>

Distributed under the MIT License.

</div>
