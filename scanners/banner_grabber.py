import socket
import ssl
import re

from confs import configs

_, _, _, _, user_agent, _ = configs()

PROBES = {
    "HTTP": b"HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n",
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
    "VNC": b"",
    "DNS": b"",
    "RDP": b"",
}

BANNER_FIRST_PORTS = {21, 22, 23, 25, 110, 143, 3306, 5900}

PORT_SERVICE_HINT = {
    80: "http", 8080: "http", 8443: "http", 443: "http",
    25: "smtp", 110: "pop3", 143: "imap",
    22: "ssh", 21: "ftp", 23: "telnet",
    3306: "mysql", 5432: "postgres", 6379: "redis",
    27017: "mongodb", 5900: "vnc", 53: "dns", 3389: "rdp",
}

PATTERNS = [
    (re.compile(r"Server:\s*([^\r\n]+)", re.I), "http"),
    (re.compile(r"Apache/([\d\.]+)", re.I), "http"),
    (re.compile(r"nginx/([\d\.]+)", re.I), "http"),
    (re.compile(r"Microsoft-IIS/([\d\.]+)", re.I), "http"),
    (re.compile(r"lighttpd/([\d\.]+)", re.I), "http"),
    (re.compile(r"Tomcat/([\d\.]+)", re.I), "http"),
    (re.compile(r"Jetty\(([\d\.]+)", re.I), "http"),
    (re.compile(r"Caddy/([\d\.]+)", re.I), "http"),

    (re.compile(r"SSH-\d\.\d+-([^\r\n]+)", re.I), "ssh"),
    (re.compile(r"OpenSSH[_\s]?([\w\.\-]+)", re.I), "ssh"),
    (re.compile(r"Dropbear[_\s]?([\w\.\-]+)", re.I), "ssh"),

    (re.compile(r"vsFTPd\s+([\d\.]+)", re.I), "ftp"),
    (re.compile(r"ProFTPD\s+([\d\.]+)", re.I), "ftp"),
    (re.compile(r"Pure-FTPd\s+([\d\.]+)", re.I), "ftp"),
    (re.compile(r"FileZilla\s+Server\s+([\d\.]+)", re.I), "ftp"),
    (re.compile(r"FTP\s+server\s+\(version\s+([\d\.]+)\)", re.I), "ftp"),

    (re.compile(r"220.*?ESMTP.*?([\d\.]+\s+[\w]+)", re.I), "smtp"),
    (re.compile(r"Exim\s+([\d\.]+)", re.I), "smtp"),
    (re.compile(r"Postfix\s+([\d\.]+)", re.I), "smtp"),
    (re.compile(r"Sendmail\s+([\d\.]+)", re.I), "smtp"),
    (re.compile(r"Microsoft\s+ESMTP\s+([\d\.]+)", re.I), "smtp"),

    (re.compile(r"Dovecot\s+.*?([\d\.]+)", re.I), "pop3/imap"),
    (re.compile(r"Courier-IMAP\s+([\d\.]+)", re.I), "imap"),
    (re.compile(r"IMAP4rev1\s+.*?([\d\.]+)", re.I), "imap"),
    (re.compile(r"POP3\s+.*?([\d\.]+)", re.I), "pop3"),

    (re.compile(r"MariaDB\s+([\d\.]+)", re.I), "mysql"),
    (re.compile(r"MySQL\s+([\d\.]+)", re.I), "mysql"),
    (re.compile(r"PostgreSQL\s+([\d\.]+)", re.I), "postgres"),
    (re.compile(r"Redis\s+([\d\.]+)", re.I), "redis"),
    (re.compile(r"MongoDB\s+([\d\.]+)", re.I), "mongodb"),

    (re.compile(r"Telnet\s+([\d\.]+)", re.I), "telnet"),
    (re.compile(r"RFB\s+([\d\.]+)", re.I), "vnc"),
    (re.compile(r"VNC\s+([\d\.]+)", re.I), "vnc"),

    (re.compile(r"220[- ]([^\r\n]+)", re.I), "ftp/smtp"),
    (re.compile(r"\(([^\)]+)\)", re.I), "generic"),
]


def _extract_version(banner: str, expected_service: str | None = None) -> tuple[str, str]:
    if not banner:
        return "Unknown", "Unknown"

    for pattern, service in PATTERNS:
        match = pattern.search(banner)
        if not match:
            continue

        version = match.group(1).strip() if match.groups() else match.group(0).strip()

        if "/" in service:
            options = service.split("/")
            service = expected_service if expected_service in options else options[0]

        return service, version

    first_line = banner.split("\r\n")[0].strip()
    if not first_line:
        return "Unknown", "Unknown"
    return (expected_service or "Unknown"), first_line


def _parse_mysql_handshake(raw: bytes) -> str | None:
    try:
        if len(raw) < 6:
            return None
        payload = raw[4:]
        if not payload or payload[0] != 10:
            return None
        null_idx = payload.index(b"\x00", 1)
        version = payload[1:null_idx].decode("ascii", errors="ignore").strip()
        return version or None
    except Exception:
        return None


def _read_banner(sock: socket.socket, extra_wait: float = 0.3) -> bytes:
    chunks = []
    try:
        data = sock.recv(4096)
        if data:
            chunks.append(data)
    except (socket.timeout, ssl.SSLError, OSError):
        pass

    try:
        sock.settimeout(extra_wait)
        more = sock.recv(4096)
        if more:
            chunks.append(more)
    except (socket.timeout, ssl.SSLError, OSError):
        pass

    return b"".join(chunks)


def grab_single_host(ip: str, ports: list[int], timeout: float = 2.0) -> dict[int, dict]:
    results = {}

    for port in ports:
        port_info = {"service": "Unknown", "version": "Unknown"}

        probe = PROBES["GENERIC"]
        if port in (80, 8080, 8443, 443):
            probe = PROBES["HTTP"] % (ip.encode(), user_agent.encode())
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

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            if port in (443, 8443):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ip)

            sock.connect((ip, port))

            raw = b""
            if port in BANNER_FIRST_PORTS:
                raw = _read_banner(sock)
                if not raw and probe:
                    sock.settimeout(timeout)
                    sock.sendall(probe)
                    raw = _read_banner(sock)
            else:
                if probe:
                    sock.sendall(probe)
                raw = _read_banner(sock)

            banner = raw.decode("utf-8", errors="ignore").strip()
            service, version = _extract_version(banner, expected_service=PORT_SERVICE_HINT.get(port))

            if port == 3306 and version == "Unknown" and raw:
                mysql_version = _parse_mysql_handshake(raw)
                if mysql_version:
                    service, version = "mysql", mysql_version

            port_info["service"] = service
            port_info["version"] = version

        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
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
