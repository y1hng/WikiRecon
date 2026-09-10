import json
import os
from colorama import Fore, init, Style
from scapy.all import *

init(autoreset=True)

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config_cache.json")

def get_default_interface_info():
    try:
        route_info = conf.route.route('0.0.0.0')
        iface_name = route_info[0]
        ip_addr = route_info[1]
        gw_addr = route_info[2]
        if gw_addr == '0.0.0.0' or not gw_addr:
            gw_addr = '192.168.1.1'
    except Exception:
        iface_name = 'eth0'
        ip_addr = '127.0.0.1'
        gw_addr = '192.168.1.1'

    return {
        "IP": ip_addr,
        "gateway": gw_addr,
        "interface": iface_name,
        "threading": 15,
        "user_agent": "Mozilla/5.0",
        "timeout": 2
    }

def set_configs():
    interfaces_list = []
    
    for iface in get_working_ifaces():
        iface_name = iface.name
        ip_addr = iface.ip if iface.ip else "No IP"
        
        gw_addr = "No Gateway"
        for route in conf.route.routes:
            if route[3] == iface_name and route[2] != "0.0.0.0":
                gw_addr = route[2]
                break
                
        interfaces_list.append({
            "name": iface_name,
            "ip": ip_addr,
            "gateway": gw_addr
        })

    print(f"\n{Fore.GREEN}{'#':<4} {'INTERFACE':<20} {'IP ADDRESS':<18} {'GATEWAY':<18}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'-'*62}{Style.RESET_ALL}")
    
    for idx, item in enumerate(interfaces_list, 1):
        print(f"{Fore.CYAN}{idx:<4} {item['name']:<20} {item['ip']:<18} {item['gateway']:<18}{Style.RESET_ALL}")

    print()
    while True:
        try:
            choice = input(f"{Fore.YELLOW}Select interface number: {Style.RESET_ALL}").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(interfaces_list):
                selected = interfaces_list[int(choice) - 1]
                break
            print(f"{Fore.RED}Invalid choice, try again.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            return configs()

    current_config = {
        "IP": selected['ip'],
        "gateway": selected['gateway'],
        "interface": selected['name'],
        "threading": 15,
        "user_agent": "Mozilla/5.0",
        "timeout": 2
    }

    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(current_config, f, indent=4)

    print(f"\n{Fore.GREEN}[+] Configuration updated successfully!{Style.RESET_ALL}\n")

def configs():
    if not os.path.exists(CONFIG_FILE):
        default_data = get_default_interface_info()
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_data, f, indent=4)
        data = default_data
    else:
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception:
            data = get_default_interface_info()

    return data["IP"], data["gateway"], data["interface"], data["threading"], data["user_agent"], data["timeout"]
