from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    1: "tcpmux", 7: "echo", 9: "discard", 11: "systat", 13: "daytime",
    17: "qotd", 19: "chargen", 20: "ftp-data", 21: "FTP", 22: "SSH",
    23: "Telnet", 25: "SMTP", 37: "time", 42: "nameserver", 43: "whois",
    49: "tacacs", 53: "DNS", 67: "dhcps", 68: "dhcpc", 69: "tftp",
    70: "gopher", 79: "finger", 80: "HTTP", 81: "hosts2-ns", 82: "xfer",
    83: "mit-ml-dev", 84: "ctf", 85: "mit-dcm", 88: "kerberos", 89: "su-mit-tg",
    90: "dnsix", 99: "metagram", 100: "newgroups", 102: "iso-tsap", 109: "pop2",
    110: "POP3", 111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "NetBIOS", 143: "IMAP",
    161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc", 201: "at-rtmp",
    213: "ipx", 222: "rsh-spx", 264: "bgmp", 308: "novastor-backup", 311: "asip-webadmin",
    389: "ldap", 401: "ups", 427: "svrloc", 443: "HTTPS", 444: "snpp",
    445: "SMB", 464: "kpasswd", 465: "smtps", 500: "isakmp", 512: "exec",
    513: "login", 514: "syslog", 515: "printer", 520: "efs", 522: "ulp",
    540: "uucp", 543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp",
    563: "nntps", 587: "submission", 593: "http-rpc-epmap", 631: "ipp", 636: "ldaps",
    666: "doom", 800: "mdbs_daemon", 808: "ccproxy-http", 873: "rsync", 888: "accessbuilder",
    902: "vmware-auth", 990: "ftps", 992: "telnets", 993: "imaps", 995: "pop3s",
    1025: "NFS-or-IIS", 1026: "win-rpc", 1027: "IIS", 1028: "deprecated", 1029: "ms-lsa",
    1080: "socks", 1099: "rmiregistry", 1109: "kpop", 1110: "nfsd-status", 1182: "acm-sdda",
    1194: "openvpn", 1241: "nessus", 1352: "lotusnotes", 1433: "MSSQL", 1434: "ms-sql-m",
    1521: "Oracle", 1524: "ingreslock", 1604: "icabrowser", 1701: "l2tp", 1720: "h323hostcall",
    1723: "pptp", 1755: "ms-streaming", 1801: "msmq", 1812: "radius", 1813: "radacct",
    1900: "ssdp", 2000: "cisco-sccp", 2001: "dc", 2002: "globe", 2003: "finger",
    2005: "descent", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm",
    2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl", 2100: "amiga-relay", 2121: "ccproxy-ftp",
    2222: "EtherNetIP-or-SSH", 2301: "hp-insight", 2383: "ms-olap4", 2401: "cvspserver", 2601: "zebra",
    2717: "pn-project", 2869: "icslap", 3000: "ppp", 3001: "nessus", 3128: "squid-http",
    3260: "iscsi", 3268: "ms-ldap-gc", 3269: "ms-ldap-ssl", 3306: "MySQL", 3351: "btrieve",
    3389: "RDP", 3689: "rendezvous", 3690: "svn", 3702: "ws-discovery", 3872: "oem-agent",
    3900: "udt_os", 3986: "mapper-ws_sc", 4000: "remote-anything", 4001: "newton", 4045: "lockd",
    4111: "xgrid", 4125: "rww", 4242: "vrbit", 4333: "msexch-routing", 4443: "pharos",
    4444: "krb524-or-metasploit", 4567: "tram", 4662: "edonkey", 4848: "appserv", 4899: "radmin",
    5000: "upnp", 5001: "commplex-link", 5003: "filemaker", 5004: "rtp", 5005: "rtcp",
    5009: "winbox", 5050: "mmcc", 5060: "sip", 5061: "sip-tls", 5101: "adsp",
    5120: "barracuda-http", 5190: "aol", 5222: "xmpp-client", 5269: "xmpp-server", 5353: "zeroconf",
    5432: "PostgreSQL", 5433: "pyrrho", 5544: "asls", 5631: "pcanywheredata", 5632: "pcanywhereservice",
    5800: "vnc-http", 5900: "VNC", 5901: "vnc-1", 5902: "vnc-2", 5903: "vnc-3",
    5984: "couchdb", 5985: "wsman-http", 5986: "wsman-https", 6000: "X11", 6001: "X11-1",
    6002: "X11-2", 6003: "X11-3", 6004: "X11-4", 6005: "X11-5", 6379: "Redis",
    6667: "irc", 6668: "irc", 6669: "irc", 6697: "ircs", 6881: "bittorrent",
    7000: "afs3-fileserver", 7001: "weblogic", 7002: "weblogic-ssl", 7070: "realserver", 7200: "fodms",
    7443: "oracle-as-https", 7547: "cwmp", 7777: "craton", 7800: "asr", 7937: "nsrexecd",
    7938: "lgtomapper", 8000: "http-alt", 8008: "http-alternate", 8080: "HTTP-Proxy", 8081: "blackice-icecap",
    8082: "blackice-alerts", 8088: "radan-http", 8181: "interbase", 8291: "mikrotik-winbox", 8443: "HTTPS-Alt",
    8500: "fmtp", 8888: "sun-answerbook", 9000: "cslistener", 9001: "etlservicemgr", 9080: "glrpc",
    9090: "zeus-admin", 9100: "jetdirect", 9200: "elasticsearch", 9300: "vrace", 9443: "tungsten-https",
    9876: "sd", 9999: "abyss", 10000: "sdoc", 10001: "scp-config", 10002: "documentum",
    10010: "rxapi", 10243: "sqlsrv-port", 10554: "rtsp-alt", 11211: "memcached", 12000: "c3p0",
    12345: "NetBus", 13720: "symantec-netbackup", 13721: "netbackup-db", 13782: "netbackup-bpcd", 14000: "scots-tunnel",
    15000: "hydra", 16000: "fmsas", 17200: "jdbc", 18101: "shaman", 19283: "keyserver",
    19350: "rtmp", 19810: "trns-comm", 20000: "dnp", 20005: "btx", 20031: "bakbone",
    20221: "ip2000", 24444: "netprowler", 24800: "synergy", 25000: "fep-service", 27017: "MongoDB",
    27018: "mongod", 27019: "mongos", 28017: "mongod-web", 30000: "ndmp", 30718: "raw-tcp",
    31283: "active-net", 32768: "omserv", 32769: "filenet-rpc", 32770: "sometimes-rpc", 32771: "sometimes-rpc",
    33333: "dec-notes", 33888: "dungeon", 34443: "ov-nnm-websrv", 37444: "sw-collaborator", 40000: "safetynet",
    41523: "s-gate", 41524: "s-gate", 44444: "oracle-tns", 47001: "winrm-http", 49152: "ms-rpc-ep",
    49153: "ms-rpc-ep", 49154: "ms-rpc-ep", 49155: "ms-rpc-ep", 49156: "ms-rpc-ep", 49157: "ms-rpc-ep",
    50000: "ibm-db2", 50001: "ibm-db2-alt", 50002: "iiop", 50003: "iiop-ssl", 50006: "mpx-router",
    50300: "active-net", 50500: "active-net", 50600: "active-net", 51103: "solaris-rpc", 53211: "sys-stat",
    54320: "backorifice", 55555: "freeciv", 59000: "cisco-vty", 60020: "hbase-master", 61616: "activemq"
}



def scanner(ip, port):
    service = COMMON_PORTS.get(port, 'Unknown')
    pkt = IP(dst=ip) / TCP(dport=port, flags='S')
    ans = sr1(pkt, timeout=3, verbose=False)
    if ans is not None and ans.haslayer(TCP):
        flags = ans.getlayer(TCP).flags
        if flags == 0x12:
            return port, True
    return port, False

def portscanner(DST_IP):
    print(f'Start scanning on target: {DST_IP}')
    OPEN_ports = []
    with ThreadPoolExecutor(max_workers=30) as exe:
        results = exe.map(lambda p: scanner(DST_IP, p), COMMON_PORTS.keys())
        for port, is_open in results:
            if is_open:
                OPEN_ports.append(port)
    return OPEN_ports


