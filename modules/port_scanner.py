#!/usr/bin/env python3
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    def __init__(self, target, timeout=3, threads=100):
        self.target = target.replace("https://", "").replace("http://", "").split("/")[0]
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []

        self.top_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,5901,
                         6379,8080,8443,8888,9000,9090,9200,9300,10000,27017,50070]
        self.common_services = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",111:"RPC",
                               135:"MSRPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",993:"IMAPS",995:"POP3S",
                               1723:"PPTP",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",5901:"VNC",
                               6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"HTTP-Alt",9000:"PHP-FPM",
                               9090:"WebSM",9200:"Elasticsearch",9300:"ES-Transport",10000:"Webmin",27017:"MongoDB",
                               50070:"Hadoop"}

    def _scan_port(self, port):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                banner = ""
                try:
                    s.settimeout(2)
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
                service = self.common_services.get(port, "Unknown")
                return (port, service, banner)
        except Exception:
            pass
        finally:
            # FIX: Always close socket to prevent leaks
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        return None

    def scan(self):
        print(f"[+] Scanning ports on {self.target}...")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._scan_port, p): p for p in self.top_ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.open_ports.append(result)

        self.open_ports.sort(key=lambda x: x[0])
        for port, svc, banner in self.open_ports:
            b = f" - {banner[:60]}" if banner else ""
            print(f"    [+] Port {port}/tcp open - {svc}{b}")

        return self.open_ports