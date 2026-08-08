#!/usr/bin/env python3
import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

class SubdomainScanner:
    def __init__(self, target, threads=50, timeout=5):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.subdomains = set()

        parsed = urlparse(target) if '://' in target else urlparse(f"http://{target}")
        self.domain = parsed.netloc.replace('www.', '').split(':')[0]

        self.wordlist = ["www","mail","ftp","webmail","smtp","pop","ns1","webdisk","ns2","cpanel","whm",
                        "autodiscover","autoconfig","ns3","m","imap","test","ns","blog","pop3","dev",
                        "www2","admin","forum","news","vpn","ns4","www1","shop","sql","www3","webmaster",
                        "mysql","mail2","secure","server","mail3","marketing","www5","support","api",
                        "staging","demo","mobile","docs","git","wiki","old","new","portal","host","video",
                        "search","stats","whois","remote","webdav","panel","direct","vps","cdn","assets",
                        "static","media","img","upload","files","download","downloads","careers","jobs",
                        "apply","partners","clients","users","members","accounts","auth","sso","login",
                        "signin","signup","register","app","apps","application","service","services",
                        "api-v1","api-v2","graphql","rest","ws","websocket","realtime","stream","chat",
                        "push","queue","worker","task","cron","backup","archive","storage","bucket",
                        "s3","minio","jenkins","gitlab","github","jira","confluence","slack","zoom",
                        "meet","kibana","grafana","prometheus","elasticsearch","redis","mongo","db",
                        "database","data","analytics","metrics","monitor","monitoring","alert","status",
                        "health","ping","ready","live","probe","internal","private","public","extranet",
                        "intranet","corp","corporate","business","enterprise","prod","production","dev",
                        "development","test","testing","qa","uat","staging","sandbox","preview","beta",
                        "alpha","canary","blue","green","release","deploy","build","ci","cd","pipeline"]

    def _check_subdomain(self, sub):
        host = f"{sub}.{self.domain}"
        try:
            socket.gethostbyname(host)
            return host
        except socket.gaierror:
            pass
        return None

    def _crt_sh(self):
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    # FIX: split on actual newline, not escaped backslash-n
                    for n in name.split('\n'):
                        n = n.strip().lstrip('*')
                        if n.endswith(self.domain) and n != self.domain:
                            self.subdomains.add(n)
        except Exception as e:
            print(f"[!] crt.sh error: {e}")

    def scan(self):
        print(f"[+] Enumerating subdomains for {self.domain}...")

        self._crt_sh()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_subdomain, w): w for w in self.wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.subdomains.add(result)

        found = sorted(list(self.subdomains))
        if found:
            for s in found[:30]:
                print(f"    [+] Found: {s}")
            if len(found) > 30:
                print(f"    [...] and {len(found)-30} more")
        else:
            print("    [-] No subdomains found")

        return found