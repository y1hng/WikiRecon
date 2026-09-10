import time
from scapy.all import *


def tracerouter(target, max_hops=30):
    ips = []

    def icmp(TTl):
        return IP(dst=target, ttl=TTl) / ICMP()

    ttl = 1
    while ttl <= max_hops:
        time.sleep(0.5)
        icmp_Pkt = icmp(ttl)
        try:
            reply = sr1(icmp_Pkt, timeout=2, verbose=False)
        except (PermissionError, OSError):
            raise

        if reply is not None and reply.haslayer(ICMP):
            src_ip = reply.src
            icmp_type = reply[ICMP].type

            if icmp_type == 11:  
                if src_ip not in ips:
                    ips.append(src_ip)
            elif icmp_type == 0:  
                if src_ip not in ips:
                    ips.append(src_ip)
                break  

        ttl += 1
    return ips
