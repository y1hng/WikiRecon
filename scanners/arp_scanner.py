import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor
from scapy.all import Ether, ARP, srp

class RootPermissionError(Exception):
    pass

def _send_arp(ip, timeout=0.9):
    ip_str = str(ip)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_str)
    try:
        ans, _ = srp(pkt, verbose=False, timeout=timeout)
        if ans:
            for _, rcv in ans:
                return {"ip": rcv.psrc, "mac": rcv.src}
    except Exception:
        pass
    return None

def scan(network, max_workers=25, timeout=0.9):
    if os.getuid() != 0:
        raise RootPermissionError("Root privileges are required to send raw ARP packets.")

    net = ipaddress.ip_network(network, strict=False)
    discovered = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(lambda ip: _send_arp(ip, timeout), net.hosts())
        for res in results:
            if res and res not in discovered:
                discovered.append(res)

    return discovered
