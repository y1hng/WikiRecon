import os
import time
from colorama import Fore, init, Style
from confs import configs as confs
import memory

init(autoreset=True)

IP, gateway, interface, threads, user_agent, Timeout = confs()

def arp_scan():
    from scanners.arp_scanner import scan
    try:
        results = scan(network=f'{gateway}/24', max_workers=threads, timeout=Timeout)
    except KeyboardInterrupt:
        return
    if not results:
        print(f"{Fore.YELLOW}[-]{Style.RESET_ALL} No active hosts found.")
        time.sleep(2)
        return

    header = f"{'IP Address':<18} {'MAC Address':<18}"
    print(f"{Fore.GREEN}{header}{Style.RESET_ALL}")
    print("-" * 54)
    for device in results:
        print(f"{Fore.CYAN}{device['ip']:<18}{Style.RESET_ALL} {Fore.WHITE}{device['mac']:<18}{Style.RESET_ALL}")
        if device not in memory.ACTIVE_devices and device['ip'] not in memory.ips: 
            memory.ACTIVE_devices.append(device)
            memory.ips.append(device['ip'])
    try:
        input(f'{Fore.YELLOW}press Enter to return')
        return
    except KeyboardInterrupt:
        return

def port_scan():
    from scanners.portscanner import portscanner, COMMON_PORTS
    if memory.ips:
        print(f'{Fore.YELLOW}do you want scan this ips Y/n:\n')
        for ip in memory.ips:
            print(f'{Fore.LIGHTCYAN_EX}{ip}')
        try:
            check = input(f'{Fore.YELLOW}$: ')
        except KeyboardInterrupt:
            return
        if check.strip().lower() in ['y', '']:
            for ip in memory.ips: 
                if ip not in memory.DEVICE_PORTS:
                    memory.DEVICE_PORTS[ip] = []
                print(f'{Fore.GREEN}{ip}')
                results = portscanner(ip) or []
                header = f"{'OPEN_PORTS':<18}{'SERVICE':<18}"
                print(f"{Fore.GREEN}{header}{Style.RESET_ALL}")
                print("-" * 54)
                for port in results:
                    service = COMMON_PORTS.get(port, 'Unknown')
                    print(f'{Fore.LIGHTGREEN_EX}{port:<18} {service:<18}')
                    if port not in memory.DEVICE_PORTS[ip]:
                        memory.DEVICE_PORTS[ip].append(port)
            try:
                input(f'{Fore.YELLOW}press Enter to return')
            except KeyboardInterrupt:
                pass
            return
    
    try:
        ips = input(f"{Fore.YELLOW}Enter custom ips: ").split()
    except KeyboardInterrupt:
        return
    os.system('clear')
    
    for ip in ips: 
        ip = ip.strip()
        if not ip:
            continue
        if ip not in memory.DEVICE_PORTS:
            memory.DEVICE_PORTS[ip] = []
        print(f'{Fore.GREEN}{ip}')
        results = portscanner(ip) or []
        header = f"{'OPEN_PORTS':<18}{'SERVICE':<18}"
        print(f"{Fore.GREEN}{header}{Style.RESET_ALL}")
        print("-" * 54)
        for port in results:
            service = COMMON_PORTS.get(port, 'Unknown')
            print(f'{Fore.LIGHTGREEN_EX}{port:<18} {service:<18}')
            if port not in memory.DEVICE_PORTS[ip]:
                memory.DEVICE_PORTS[ip].append(port)
    try:
        input(f'{Fore.YELLOW}press Enter to return')
    except KeyboardInterrupt:
        return
        
def banner_grabbing():
    from scanners.banner_grabber import grab_single_host, grab_multiple_hosts
    
    if memory.DEVICE_PORTS:
        print(f'{Fore.YELLOW}Do you want to grab banners for saved targets Y/n:\n')
        for ip in memory.DEVICE_PORTS:
            print(f'{Fore.LIGHTCYAN_EX}{ip}: {memory.DEVICE_PORTS[ip]}')
        
        try:
            check = input(f'{Fore.YELLOW}$: ')
        except KeyboardInterrupt:
            return
        if check.strip().lower() in ['y', '']:
            results = grab_multiple_hosts(memory.DEVICE_PORTS, timeout=Timeout)
            if results:
                for ip, ports_data in results.items():
                    memory.device_version[ip] = ports_data
                header = f"{'IP Address':<18} {'PORT':<8} {'SERVICE':<12} {'VERSION':<25}"
                print(f"\n{Fore.GREEN}{header}{Style.RESET_ALL}")
                print("-" * 65)
                
                for ip, ports_data in results.items():
                    for port, info in ports_data.items():
                        print(f"{Fore.CYAN}{ip:<18}{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}{port:<8}{Style.RESET_ALL} {Fore.WHITE}{info['service']:<12}{Style.RESET_ALL} {Fore.YELLOW}{info['version']:<25}{Style.RESET_ALL}")
            
            try:
                input(f'\n{Fore.YELLOW}press Enter to return')
            except KeyboardInterrupt:
                pass
            return

    try:
        target_ip = input(f"{Fore.YELLOW}Enter custom IP: ").strip()
        custom_ports = input(f"{Fore.YELLOW}Enter ports (space separated): ").split()
    except KeyboardInterrupt:
        return
    
    ports = [int(p) for p in custom_ports if p.isdigit()]
    if not target_ip or not ports:
        return
        
    os.system('clear')
    results = grab_single_host(target_ip, ports, timeout=Timeout)
    if results:
        memory.device_version[target_ip] = results
        header = f"{'PORT':<8} {'SERVICE':<12} {'VERSION':<25}"
        print(f"{Fore.GREEN}{header}{Style.RESET_ALL}")
        print("-" * 50)
        
        for port, info in results.items():
            print(f"{Fore.LIGHTGREEN_EX}{port:<8}{Style.RESET_ALL} {Fore.WHITE}{info['service']:<12}{Style.RESET_ALL} {Fore.YELLOW}{info['version']:<25}{Style.RESET_ALL}")
            
    try:
        input(f'\n{Fore.YELLOW}press Enter to return')
    except KeyboardInterrupt:
        pass
    return

def Traceroute():
    from scanners.traceroute import tracerouter as tracer
    max_Hops = 30
    try:
        check = input(f"{Fore.YELLOW}Default 8.8.8.8 Do you want continue Y/n? ")
        if check.strip().lower() not in ['y', '']:
            New_Target = input(f'{Fore.CYAN}enter Target: ')
            results = tracer(New_Target, max_Hops)
        else:
            results = tracer('8.8.8.8', max_Hops)    
    
        if not results:
            print(f"{Fore.RED}No routing results returned.{Style.RESET_ALL}")
            try:
                input(f'{Fore.YELLOW}press Enter to return')
            except KeyboardInterrupt:
                pass
            return
        header = f"{'IP Address':<18}"
        print(f"{Fore.GREEN}{header}{Style.RESET_ALL}")
        print("-" * 54)
        for ip in results:
            print(f"{Fore.CYAN}{str(ip):<18}{Style.RESET_ALL}")
            if ip not in memory.PACKETS_ROUTE:
                memory.PACKETS_ROUTE.append(ip)
    except KeyboardInterrupt:
        os.system('clear')
        return
    try:
        input(f'{Fore.YELLOW}press Enter to return')
    except KeyboardInterrupt:
        return

def automated_scan():
    from scanners import automated_full_scan
    automated_full_scan.automscan()
    try:
        input(f'{Fore.YELLOW}press Enter to return')
    except KeyboardInterrupt:
        return

def scanning_main():
    while True:
        os.system('clear')
        color = Fore.LIGHTGREEN_EX
        reset = Style.RESET_ALL
        print(
            f"{color}{'01. ARP_SCANNING':<25}{color}02. PORT_SCANNING{reset}\n"
            f"{color}{'03. BANNER_GRABBER':<25}{color}04. TRACEROUTE{reset}\n"
            f"{color}{'05. FULL_NMAPING':<25}{color}06. EXIT{reset}\n"
        )
        try:
            choice = input('$: ').strip()
        except KeyboardInterrupt:
            break
        if choice == '6':
            os.system('clear')
            break
        elif choice == '1':
            os.system('clear')
            arp_scan()
        elif choice == '2':
            os.system('clear')
            port_scan()
        elif choice == '3':
            os.system('clear')
            banner_grabbing()
        elif choice == '4':
            os.system('clear')
            Traceroute()
        elif choice == '5':
            os.system('clear')
            automated_scan()

scanning_main()
