import os
import json
import csv
import time
import math
import html as html_lib
from datetime import datetime
from confs import configs as confs
from scanners.traceroute import tracerouter as tracer
import scanners.arp_scanner as arp_scanner
from scanners.portscanner import portscanner, COMMON_PORTS
import scanners.banner_grabber as banner_grabber
from colorama import Fore, Style, init

init(autoreset=True)

IP, gateway, interface, threads, user_agent, Timeout = confs()

scan_data = {
    "timestamp": "",
    "traceroute": [],
    "network_devices": [],
    "port_scan_results": {},
    "banner_results": {}
}

def print_banner():
    print(f"{Fore.CYAN}{'='*65}")
    print(f"{Fore.CYAN}{'NETWORK RECONNAISSANCE & AUDIT REPORT':^65}")
    print(f"{Fore.CYAN}{'='*65}{Style.RESET_ALL}\n")

def tracerouting():
    print(f"{Fore.BLUE}[*] Running Traceroute to 8.8.8.8...{Style.RESET_ALL}")
    results = tracer('8.8.8.8')
    if not results:
        print(f"{Fore.RED}[!] No routing results returned.{Style.RESET_ALL}\n")
        return
    
    scan_data["traceroute"] = [str(ip) for ip in results]
    header = f"{'Hop':<6} {'IP Address':<20}"
    print(f"{Fore.GREEN}{header}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'-'*30}{Style.RESET_ALL}")
    for idx, ip in enumerate(results, 1):
        print(f"{Fore.CYAN}{idx:<6} {str(ip):<20}{Style.RESET_ALL}")
    print()

def discover():
    Gateway = gateway
    print(f"{Fore.BLUE}[*] Performing ARP Scan on {Gateway}/24...{Style.RESET_ALL}")
    results = arp_scanner.scan(f'{Gateway}/24', threads, Timeout)
    if not results:
        print(f"{Fore.YELLOW}[-] No active hosts found.{Style.RESET_ALL}\n")
        time.sleep(1)
        return
    
    scan_data["network_devices"] = results
    header = f"{'IP Address':<20} {'MAC Address':<20}"
    print(f"{Fore.GREEN}{header}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'-'*40}{Style.RESET_ALL}")
    for device in results:
        print(f"{Fore.CYAN}{device['ip']:<20}{Style.RESET_ALL} {Fore.WHITE}{device['mac']:<20}{Style.RESET_ALL}")
    print()

def scan_ports():
    print(f"{Fore.BLUE}[*] Scanning Ports on Discovered Hosts...{Style.RESET_ALL}")
    for device in scan_data["network_devices"]:
        ip = device['ip']
        scan_data["port_scan_results"][ip] = []
        print(f"\n{Fore.YELLOW}[+] Target IP: {ip}{Style.RESET_ALL}")
        results = portscanner(ip)
        
        if not results:
            print(f"    {Fore.WHITE}No open ports found.{Style.RESET_ALL}")
            continue
            
        header = f"    {'PORT':<12} {'SERVICE':<18}"
        print(f"{Fore.GREEN}{header}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    {'-'*30}{Style.RESET_ALL}")
        for port in results:
            service = COMMON_PORTS.get(port, 'Unknown')
            print(f"    {Fore.LIGHTGREEN_EX}{port:<12} {service:<18}{Style.RESET_ALL}")
            scan_data["port_scan_results"][ip].append({"port": port, "service": service})
    print()

def bannergrabb():
    print(f"{Fore.BLUE}[*] Grabbing Service Banners...{Style.RESET_ALL}")
    device_ports_map = {}
    for ip, ports in scan_data["port_scan_results"].items():
        device_ports_map[ip] = [p["port"] for p in ports]
        
    results = banner_grabber.grab_multiple_hosts(device_ports_map, timeout=Timeout)
    scan_data["banner_results"] = results
    
    header = f"{'IP Address':<18} {'PORT':<8} {'SERVICE':<14} {'VERSION':<25}"
    print(f"\n{Fore.GREEN}{header}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'-'*65}{Style.RESET_ALL}")
    
    for ip, ports_data in results.items():
        for port, info in ports_data.items():
            service_str = str(info.get('service', 'Unknown'))
            version_str = str(info.get('version', 'Unknown'))
            print(f"{Fore.CYAN}{ip:<18}{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}{str(port):<8}{Style.RESET_ALL} {Fore.WHITE}{service_str:<14}{Style.RESET_ALL} {Fore.YELLOW}{version_str:<25}{Style.RESET_ALL}")
    print()


_PORT_COLORS = {
    "21": "#f97316", "22": "#22c55e", "23": "#ef4444", "25": "#eab308",
    "53": "#a855f7", "80": "#38bdf8", "110": "#eab308", "143": "#eab308",
    "443": "#0ea5e9", "445": "#f43f5e", "3306": "#f59e0b", "3389": "#f43f5e",
    "5432": "#f59e0b", "8080": "#38bdf8", "8443": "#0ea5e9",
}
_DEFAULT_PORT_COLOR = "#818cf8"


def _esc(value) -> str:
    return html_lib.escape(str(value), quote=True)


def _port_color(port) -> str:
    return _PORT_COLORS.get(str(port), _DEFAULT_PORT_COLOR)


def _build_traceroute_path(hops: list) -> str:
    if not hops:
        return '<div class="empty-state">No traceroute path was recorded for this scan.</div>'

    nodes_html = []
    for i, ip in enumerate(hops):
        is_first = i == 0
        is_last = i == len(hops) - 1
        role = "Source" if is_first else ("Target" if is_last else f"Hop {i}")
        node_class = "hop-node origin" if is_first else ("hop-node target" if is_last else "hop-node")

        nodes_html.append(f'''
        <div class="hop-wrap">
            <div class="{node_class}">
                <span class="hop-index">{i + 1}</span>
                <span class="hop-ip">{_esc(ip)}</span>
                <span class="hop-role">{_esc(role)}</span>
            </div>
        </div>''')

        if not is_last:
            nodes_html.append('''
        <div class="hop-arrow">
            <svg viewBox="0 0 60 20" preserveAspectRatio="none">
                <line x1="0" y1="10" x2="46" y2="10" class="flow-line" />
                <polygon points="46,3 60,10 46,17" class="flow-arrow" />
            </svg>
        </div>''')

    return f'<div class="traceroute-path">{"".join(nodes_html)}</div>'


def _build_network_topology(devices: list, hops: list, banner_results: dict) -> str:
    if not devices and not hops:
        return '<div class="empty-state">No topology data available to visualize.</div>'

    nodes = []
    edges = []

    prev_hop = None
    for i, ip in enumerate(hops):
        node_id = f"hop_{i}"
        nodes.append({
            "id": node_id,
            "label": f"Hop {i+1}\n{ip}",
            "shape": "diamond",
            "color": {"background": "#f97316", "border": "#ea580c"},
            "font": {"color": "#e2e8f0"}
        })
        if prev_hop:
            edges.append({"from": prev_hop, "to": node_id})
        prev_hop = node_id

    gateway_id = prev_hop if prev_hop else "gateway"
    if not prev_hop:
        nodes.append({
            "id": gateway_id,
            "label": "Gateway",
            "shape": "diamond",
            "color": {"background": "#38bdf8", "border": "#0284c7"},
            "font": {"color": "#e2e8f0"}
        })

    for device in devices:
        ip = device.get("ip", "N/A")
        mac = device.get("mac", "N/A")
        dev_id = f"dev_{ip}"
        
        nodes.append({
            "id": dev_id,
            "label": f"{ip}\n{mac}",
            "shape": "dot",
            "size": 20,
            "color": {"background": "#312e81", "border": "#818cf8"},
            "font": {"color": "#e2e8f0"}
        })
        
        edges.append({"from": gateway_id, "to": dev_id})
        
        ports = banner_results.get(ip, {})
        for port, info in ports.items():
            port_id = f"port_{ip}_{port}"
            nodes.append({
                "id": port_id,
                "label": f"Port {port}",
                "shape": "box",
                "color": {"background": _port_color(port), "border": "#1e293b"},
                "font": {"color": "#ffffff", "size": 11}
            })
            edges.append({"from": dev_id, "to": port_id})

    topology_data = json.dumps({"nodes": nodes, "edges": edges})

    html_out = f'''
    <div id="network-topology"></div>
    <script>
        var topologyData = {topology_data};
        var container = document.getElementById('network-topology');
        var data = {{
            nodes: new vis.DataSet(topologyData.nodes),
            edges: new vis.DataSet(topologyData.edges)
        }};
        var options = {{
            nodes: {{
                borderWidth: 2,
                shadow: true,
                font: {{ face: 'Segoe UI' }}
            }},
            edges: {{
                width: 2,
                color: {{ color: '#475569', highlight: '#38bdf8' }},
                smooth: {{ type: 'continuous' }}
            }},
            physics: {{
                enabled: true,
                barnesHut: {{
                    gravitationalConstant: -2000,
                    centralGravity: 0.3,
                    springLength: 95,
                    springConstant: 0.04
                }},
                stabilization: {{ iterations: 150 }}
            }},
            interaction: {{
                hover: true,
                dragNodes: true,
                zoomView: true,
                dragView: true
            }}
        }};
        new vis.Network(container, data, options);
    </script>
    '''
    return html_out


def _build_ports_section(banner_results: dict) -> str:
    if not banner_results:
        return '<div class="empty-state">No port scan / banner results are available.</div>'

    cards = []
    for ip, ports in banner_results.items():
        if not ports:
            continue
        chips = "".join(
            f'''<span class="port-chip" style="--chip-color:{_port_color(port)}">
                    <b>{_esc(port)}</b> &middot; {_esc(info.get('service', 'N/A'))}
                    <em>{_esc(info.get('version', 'N/A'))}</em>
                </span>'''
            for port, info in ports.items()
        )
        cards.append(f'''
        <div class="host-port-card">
            <div class="host-port-card-header">
                <span class="host-ip">{_esc(ip)}</span>
                <span class="badge">{len(ports)} open ports</span>
            </div>
            <div class="port-chip-row">{chips}</div>
        </div>''')

    if not cards:
        return '<div class="empty-state">No port scan / banner results are available.</div>'

    return f'<div class="host-port-grid">{"".join(cards)}</div>'


def _build_html_report(data: dict) -> str:
    timestamp = data.get("timestamp", "N/A")
    devices = data.get("network_devices", [])
    hops = data.get("traceroute", [])
    banner_results = data.get("banner_results", {})

    traceroute_html = _build_traceroute_path(hops)
    topology_html = _build_network_topology(devices, hops, banner_results)
    ports_html = _build_ports_section(banner_results)

    devices_rows = "".join(
        f'''<tr>
                <td>{_esc(d.get("ip", "N/A"))}</td>
                <td><code>{_esc(d.get("mac", "N/A"))}</code></td>
                <td>{len(banner_results.get(d.get("ip", ""), {}))}</td>
            </tr>'''
        for d in devices
    ) or '<tr><td colspan="3" class="empty-state">No devices found.</td></tr>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Scan Report - {_esc(timestamp)}</title>
<script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
    :root {{
        --bg: #0f172a;
        --panel: #1e293b;
        --panel-2: #172033;
        --border: #334155;
        --text: #e2e8f0;
        --muted: #94a3b8;
        --accent: #38bdf8;
        --accent-2: #818cf8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: radial-gradient(circle at 20% -10%, #1e293b 0%, var(--bg) 55%);
        color: var(--text);
        margin: 0;
        padding: 25px;
    }}
    .container {{ max-width: 1150px; margin: 0 auto; }}
    h1 {{ color: var(--accent); border-bottom: 2px solid var(--border); padding-bottom: 10px; margin-bottom: 5px; }}
    h2 {{ color: var(--accent-2); margin-top: 34px; font-size: 1.2rem; display:flex; align-items:center; gap:8px; }}
    h2 .step {{
        display:inline-flex; align-items:center; justify-content:center;
        width:26px; height:26px; border-radius:50%;
        background: var(--accent-2); color:#0f172a; font-size:13px; font-weight:700;
    }}
    .meta {{
        background: var(--panel); padding: 15px; border-radius: 8px;
        margin-bottom: 20px; font-size: 14px; color: var(--muted); line-height: 1.6;
        border: 1px solid var(--border);
    }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; background: var(--panel); border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); font-size: 14px; }}
    th {{ background-color: var(--bg); color: var(--accent); font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }}
    tr:hover {{ background-color: var(--border); }}
    code {{ color: #a5b4fc; }}
    .badge {{ background: #0284c7; color: #fff; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: bold; }}
    .empty-state {{ color: var(--muted); padding: 18px; text-align: center; font-style: italic; }}

    .traceroute-path {{
        display: flex; align-items: center; flex-wrap: wrap;
        gap: 4px; background: var(--panel); border: 1px solid var(--border);
        border-radius: 12px; padding: 22px 16px; margin-top: 12px;
    }}
    .hop-wrap {{ display:flex; }}
    .hop-node {{
        display:flex; flex-direction:column; align-items:center; gap:2px;
        background: var(--panel-2); border: 1px solid var(--border);
        border-radius: 10px; padding: 10px 14px; min-width: 120px;
        position: relative;
    }}
    .hop-node.origin {{ border-color: #22c55e; box-shadow: 0 0 14px rgba(34,197,94,0.25); }}
    .hop-node.target {{ border-color: #f97316; box-shadow: 0 0 14px rgba(249,115,22,0.25); }}
    .hop-index {{
        position:absolute; top:-10px; left:-10px;
        background: var(--accent); color:#0f172a; font-weight:800; font-size:11px;
        width:20px; height:20px; border-radius:50%; display:flex; align-items:center; justify-content:center;
    }}
    .hop-ip {{ font-weight: 700; font-size: 14px; color: var(--text); }}
    .hop-role {{ font-size: 11px; color: var(--muted); }}
    .hop-arrow {{ width: 46px; height: 20px; flex-shrink:0; }}
    .hop-arrow svg {{ width:100%; height:100%; }}
    .flow-line {{
        stroke: var(--accent); stroke-width: 2; stroke-dasharray: 6 4;
        animation: flowDash 1s linear infinite;
    }}
    .flow-arrow {{ fill: var(--accent); }}
    @keyframes flowDash {{ to {{ stroke-dashoffset: -20; }} }}

    #network-topology {{
        width: 100%;
        height: 600px;
        background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
        border: 1px solid var(--border);
        border-radius: 14px;
        margin-top: 12px;
        outline: none;
    }}

    .host-port-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; margin-top: 12px; }}
    .host-port-card {{
        background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px;
    }}
    .host-port-card-header {{ display:flex; justify-content: space-between; align-items:center; margin-bottom: 10px; }}
    .host-ip {{ font-weight: 700; color: var(--accent); font-size: 15px; }}
    .port-chip-row {{ display:flex; flex-wrap: wrap; gap: 8px; }}
    .port-chip {{
        background: color-mix(in srgb, var(--chip-color) 18%, var(--panel-2));
        border: 1px solid var(--chip-color);
        color: var(--text); border-radius: 999px; padding: 5px 10px; font-size: 12px;
        display:flex; gap:6px; align-items:baseline;
    }}
    .port-chip b {{ color: var(--chip-color); }}
    .port-chip em {{ color: var(--muted); font-style: normal; }}
</style>
</head>
<body>
<div class="container">
    <h1>Network Scan &amp; Audit Report</h1>
    <div class="meta">
        <strong>Scan Execution Date:</strong> {_esc(timestamp)}<br>
        <strong>Total Hosts Discovered:</strong> {len(devices)}<br>
        <strong>Traceroute Hops:</strong> {len(hops)}
    </div>

    <h2><span class="step">1</span> Network Routing Path (Traceroute)</h2>
    {traceroute_html}

    <h2><span class="step">2</span> Interactive Network Topology</h2>
    {topology_html}

    <h2><span class="step">3</span> Discovered Network Devices</h2>
    <table>
        <thead><tr><th>IP Address</th><th>MAC Address</th><th>Open Ports</th></tr></thead>
        <tbody>{devices_rows}</tbody>
    </table>

    <h2><span class="step">4</span> Detailed Service Banners &amp; Port Audit</h2>
    {ports_html}
</div>
</body>
</html>"""
    return html_content


def generate_reports():
    print(f"{Fore.BLUE}[*] Generating Audit Reports (JSON, CSV, HTML)...{Style.RESET_ALL}")
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = os.getcwd()
    
    json_path = os.path.join(base_dir, f"scan_report_{timestamp_str}.json")
    csv_path = os.path.join(base_dir, f"scan_report_{timestamp_str}.csv")
    html_path = os.path.join(base_dir, f"scan_report_{timestamp_str}.html")
    
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(scan_data, f, indent=4, ensure_ascii=False)
        
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Target IP", "MAC Address", "Port", "Service", "Version / Banner"])
        
        banner_res = scan_data.get("banner_results", {})
        dev_mac_map = {d["ip"]: d["mac"] for d in scan_data.get("network_devices", [])}
        
        if not banner_res and scan_data.get("network_devices"):
            for dev in scan_data.get("network_devices"):
                writer.writerow([dev["ip"], dev["mac"], "N/A", "N/A", "N/A"])
        else:
            for ip, ports in banner_res.items():
                mac = dev_mac_map.get(ip, "N/A")
                for port, info in ports.items():
                    writer.writerow([ip, mac, port, info.get("service", "N/A"), info.get("version", "N/A")])

    html_content = _build_html_report(scan_data)

    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
        
    print(f"{Fore.GREEN}[+] Reports generated successfully in current working directory:{Style.RESET_ALL}")
    print(f"    - JSON: {json_path}")
    print(f"    - CSV:  {csv_path}")
    print(f"    - HTML: {html_path}\n")

def automscan():
    scan_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print_banner()
    tracerouting()
    discover()
    scan_ports()
    bannergrabb()
    generate_reports()
