import concurrent.futures
import socket
import time

from config import *
from core.banner import found, info, success, warning, make_table
from core.http import RateLimitedSession


SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 81: "HTTP-Alt", 110: "POP3", 111: "RPCBind",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-Sub", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM",
    2087: "WHM-SSL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis",
    8000: "HTTP-Alt", 8008: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "Web-Console",
    9200: "Elasticsearch", 9300: "Elasticsearch", 27017: "MongoDB",
    27018: "MongoDB",
}

PROBES = {
    21: b"USER probe\r\n",
    25: b"EHLO probe\r\n",
    110: b"USER probe\r\n",
    143: b"a1 CAPABILITY\r\n",
    587: b"EHLO probe\r\n",
    3306: b"\x00\x00\x00\x01",
    5432: b"\x00\x00\x00\x08\x04\xd2\x16\x2f",
    6379: b"PING\r\n",
    27017: b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00",
}

HTTP_PORTS = {80, 81, 8080, 8000, 8008, 8888, 9090, 2082, 2086, 3000, 5000}


class PortScannerModule:
    def __init__(self, target: str, console, ports=None):
        self.console = console
        from urllib.parse import urlparse
        parsed = urlparse(target)
        self.target_url = target
        self.host = parsed.hostname
        self.ports = ports or COMMON_PORTS
        self.open_ports = []
        self.closed = 0
        self.unconfirmed = 0
        self.cdn = None

    def _detect_cdn(self):
        try:
            resp = RateLimitedSession().get(
                self.target_url,
                timeout=REQUEST_TIMEOUT,
                request_headers={"User-Agent": USER_AGENT},
            )
            blob = (str(resp.headers) + " " + resp.url + " " + resp.text[:3000]).lower()
            for name, hints in CDN_HINTS.items():
                if any(h in blob for h in hints):
                    return name
        except Exception:
            pass
        return None

    def _grab_banner(self, sock, port):
        try:
            sock.settimeout(3)
            try:
                data = sock.recv(1024)
                if data:
                    return data.decode("utf-8", errors="ignore").strip()[:200]
            except socket.timeout:
                pass

            probe = PROBES.get(port)
            if probe is None:
                probe = (b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n"
                         if port in HTTP_PORTS else None)
            if probe:
                try:
                    sock.sendall(probe)
                    data = sock.recv(1024)
                    if data:
                        return data.decode("utf-8", errors="ignore").strip()[:200]
                except Exception:
                    return ""
        except Exception:
            return ""
        return ""

    def _scan_port(self, port: int):
        from core.network import authorize
        _, allowed_host, _ = authorize(self.target_url, "TCP port diagnostic")
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((allowed_host, port))
            if result != 0:
                return None

            banner = self._grab_banner(sock, port)
            confirmed = bool(banner)
            return {
                "port": port,
                "service": SERVICE_MAP.get(port, "Unknown"),
                "banner": banner,
                "state": "open" if confirmed else "open-unconfirmed",
                "confirmed": confirmed,
            }
        except Exception:
            return None
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def run(self) -> dict:
        import config
        if config.TRANSPORT_MODE != "direct":
            return {"skipped": True, "reason": "TCP diagnostics unavailable through proxy; no direct fallback", "open_ports": []}
        info(self.console, f"Scanning {len(self.ports)} ports on {self.host}...")

        self.cdn = self._detect_cdn()
        if self.cdn:
            warning(
                self.console,
                f"{self.host} is served by {self.cdn}. Ports belong to shared CDN edge "
                "infrastructure and are not the origin's real attack surface.",
            )

        time.sleep(0.2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as pool:
            futures = {pool.submit(self._scan_port, p): p for p in self.ports}
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result:
                    self.open_ports.append(result)
                    if not result["confirmed"]:
                        self.unconfirmed += 1
                        found(
                            self.console,
                            f"Port {result['port']}/{result['service']} TCP-open but UNCONFIRMED "
                            "(no protocol banner - likely filtered or edge behaviour)",
                        )
                    else:
                        found(
                            self.console,
                            f"Port {result['port']}/{result['service']} OPEN | {result['banner'][:80]}",
                        )
                else:
                    self.closed += 1

        self.open_ports.sort(key=lambda x: x["port"])
        success(
            self.console,
            f"Port scan complete: {len(self.open_ports)} reachable, {self.closed} closed/filtered",
        )

        if self.open_ports:
            rows = [
                (str(p["port"]), p["service"],
                 p["banner"][:50] if p["banner"] else "-",
                 "yes" if p["confirmed"] else "no")
                for p in self.open_ports
            ]
            self.console.print(make_table("Open Ports", ["Port", "Service", "Banner", "Confirmed"], rows))

        return {
            "open_ports": self.open_ports,
            "closed_count": self.closed,
            "total_scanned": len(self.ports),
            "unconfirmed": self.unconfirmed,
            "cdn_detected": self.cdn,
        }
