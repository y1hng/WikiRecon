import socket
import ssl
import re

PROBES = {
    "HTTP": b"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "GENERIC": b"\r\n\r\n",
    "SMTP": b"EHLO localhost\r\n",
    "POP3": b"QUIT\r\n",
    "IMAP": b"a001 CAPABILITY\r\n",
    "SSH": b"",
    "FTP": b"",
    "TELNET": b"",
    "MYSQL": b"",
    "POSTGRES": b"",
    "REDIS": b"PING\r\n",
    "MONGO": b"",
    "VNC": b"RFB 003.008\n",
    "DNS": b"",
    "RDP": b"",
}

PATTERNS = [
    (re.compile(r"Server:\s*([^\r\n]+)", re.I), "http"),
    (re.compile(r"SSH-\d\.\d-([^\r\n]+)", re.I), "ssh"),
    (re.compile(r"OpenSSH[_\s]?([\w\.\-]+)", re.I), "ssh"),
    (re.compile(r"Dropbear[_\s]?([\w\.\-]+)", re.I), "ssh"),
    (re.compile(r"220[- ]([^\r\n]+)", re.I), "ftp/smtp"),
    (re.compile(r"Apache/([\d\.]+)", re.I), "http"),
    (re.compile(r"nginx/([\d\.]+)", re.I), "http"),
    (re.compile(r"Microsoft-IIS/([\d\.]+)", re.I), "http"),
    (re.compile(r"lighttpd/([\d\.]+)", re.I), "http"),
    (re.compile(r"Tomcat/([\d\.]+)", re.I), "http"),
    (re.compile(r"Jetty\(([\d\.]+)", re.I), "http"),
    (re.compile(r"Caddy/([\d\.]+)", re.I), "http"),
    (re.compile(r"vsFTPd\s+([\d\.]+)", re.I), "ftp"),
    (re.compile(r"ProFTPD\s+([\d\.]+)", re.I), "ftp"),
    (re.compile(r"Pure-FTPd\s+([\d\.]+)", re.I), "ftp"),
    (re.compile(r"FileZilla\s+Server\s+([\d\.]+)", re.I), "ftp"),
    (re.compile(r"220.*?ESMTP.*?([\d\.]+\s+[\w]+)", re.I), "smtp"),
    (re.compile(r"Exim\s+([\d\.]+)", re.I), "smtp"),
    (re.compile(r"Postfix\s+([\d\.]+)", re.I), "smtp"),
    (re.compile(r"Sendmail\s+([\d\.]+)", re.I), "smtp"),
    (re.compile(r"Microsoft\s+ESMTP\s+([\d\.]+)", re.I), "smtp"),
    (re.compile(r"POP3\s+.*?([\d\.]+)", re.I), "pop3"),
    (re.compile(r"Dovecot\s+.*?([\d\.]+)", re.I), "pop3/imap"),
    (re.compile(r"Courier-IMAP\s+([\d\.]+)", re.I), "imap"),
    (re.compile(r"IMAP4rev1\s+.*?([\d\.]+)", re.I), "imap"),
    (re.compile(r"MySQL\s+([\d\.]+)", re.I), "mysql"),
    (re.compile(r"MariaDB\s+([\d\.]+)", re.I), "mysql"),
    (re.compile(r"PostgreSQL\s+([\d\.]+)", re.I), "postgres"),
    (re.compile(r"Redis\s+([\d\.]+)", re.I), "redis"),
    (re.compile(r"MongoDB\s+([\d\.]+)", re.I), "mongodb"),
    (re.compile(r"Telnet\s+([\d\.]+)", re.I), "telnet"),
    (re.compile(r"VNC\s+([\d\.]+)", re.I), "vnc"),
    (re.compile(r"RFB\s+([\d\.]+)", re.I), "vnc"),
    (re.compile(r"SSH-2\.0-([^\r\n]+)", re.I), "ssh"),
    (re.compile(r"SSH-1\.99-([^\r\n]+)", re.I), "ssh"),
    (re.compile(r"220\s+([^\r\n]+)", re.I), "ftp"),
    (re.compile(r"FTP\s+server\s+\(version\s+([\d\.]+)\)", re.I), "ftp"),
    (re.compile(r"\(([^\)]+)\)", re.I), "generic"),
]

def _extract_version(banner: str) -> tuple[str, str]:
    if not banner:
        return "Unknown", "Unknown"

    for pattern, service in PATTERNS:
        match = pattern.search(banner)
        if match:
            if match.groups():
                version = match.group(1).strip()
            else:
                version = match.group(0).strip()
            return service, version

    first_line = banner.split("\r\n")[0].strip()
    return "Unknown", first_line if first_line else "Unknown"

def grab_single_host(ip: str, ports: list[int], timeout: float = 2.0) -> dict[int, dict]:
    results = {}

    for port in ports:
        port_info = {"service": "Unknown", "version": "Unknown"}
        
        probe = PROBES["GENERIC"]
        if port in (80, 8080, 8443, 443):
            probe = PROBES["HTTP"] % ip.encode()
        elif port == 25:
            probe = PROBES["SMTP"]
        elif port == 110:
            probe = PROBES["POP3"]
        elif port == 143:
            probe = PROBES["IMAP"]
        elif port == 22:
            probe = PROBES["SSH"]
        elif port == 21:
            probe = PROBES["FTP"]
        elif port == 23:
            probe = PROBES["TELNET"]
        elif port == 3306:
            probe = PROBES["MYSQL"]
        elif port == 5432:
            probe = PROBES["POSTGRES"]
        elif port == 6379:
            probe = PROBES["REDIS"]
        elif port == 27017:
            probe = PROBES["MONGO"]
        elif port == 5900:
            probe = PROBES["VNC"]
        elif port == 53:
            probe = PROBES["DNS"]
        elif port == 3389:
            probe = PROBES["RDP"]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            if port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)

            sock.connect((ip, port))
            if probe:
                sock.sendall(probe)

            banner = sock.recv(4096).decode("utf-8", errors="ignore").strip()
            sock.close()

            service, version = _extract_version(banner)
            port_info["service"] = service
            port_info["version"] = version

        except Exception:
            pass

        results[port] = port_info

    return results

def grab_multiple_hosts(device_ports: dict[str, list[int]], timeout: float = 2.0) -> dict[str, dict[int, dict]]:
    full_results = {}
    for ip, ports in device_ports.items():
        if ports:
            full_results[ip] = grab_single_host(ip, ports, timeout=timeout)
    return full_results
