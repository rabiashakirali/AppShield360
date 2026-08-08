#!/usr/bin/env python3
import requests
import urllib.parse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Static file extensions to skip
STATIC_EXTS = ['.png','.jpg','.jpeg','.gif','.css','.js','.svg','.ico','.woff','.woff2','.ttf','.mp4','.pdf','.zip']

def is_static_file(url):
    """Check if URL points to a static file (ignoring query params)"""
    clean = url.split('?')[0].lower()
    return any(clean.endswith(ext) for ext in STATIC_EXTS)

class VulnScanner:
    def __init__(self, target, endpoints=None, threads=25, timeout=10):
        self.target = target.rstrip("/")
        self.endpoints = endpoints or [self.target]
        self.threads = threads
        self.timeout = timeout
        self.findings = []

    def _req(self, url, method="GET", data=None, headers=None, cookies=None):
        try:
            h = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            if headers:
                h.update(headers)
            if method == "GET":
                return requests.get(url, headers=h, cookies=cookies, timeout=self.timeout, allow_redirects=False)
            else:
                return requests.post(url, data=data, headers=h, cookies=cookies, timeout=self.timeout, allow_redirects=False)
        except Exception:
            return None

    def test_sqli(self, url):
        payloads = [
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' UNION SELECT null--",
            "1' OR '1'='1'--",
            "1' WAITFOR DELAY '0:0:5'--"
        ]
        errors = ["sql syntax","mysql_fetch","ORA-","PostgreSQL","SQLite","ODBC SQL Server",
                 "Unclosed quotation mark","quoted string not properly terminated",
                 "You have an error in your SQL syntax","Warning: mysql"]
        wp_errors = ["WordPress database error", "wp_die", "There has been a critical error"]

        for p in payloads:
            test_url = f"{url}{p}" if "?" in url else f"{url}?id={p}"
            r = self._req(test_url)
            if r and any(e.lower() in r.text.lower() for e in errors):
                if any(wp.lower() in r.text.lower() for wp in wp_errors):
                    continue
                return {
                    "type": "SQL Injection",
                    "url": url,
                    "param": "id" if "?" not in url else "query",
                    "method": "GET",
                    "payload": p,
                    "evidence": f"SQL error detected with payload: {p[:30]}",
                    "fix": "Use parameterized queries/prepared statements. Validate and sanitize all user inputs.",
                    "cwe": "CWE-89",
                    "severity": "CRITICAL"
                }
        return None

    def test_xss(self, url):
        payloads = [
            ("<script>alert(1)</script>", "<script>alert(1)</script>"),
            ('"><script>alert(1)</script>', '"><script>alert(1)</script>'),
            ("'\"><img src=x onerror=alert(1)>", "'\"><img src=x onerror=alert(1)>"),
            ("<svg onload=alert(1)>", "<svg onload=alert(1)>"),
        ]
        for p, check in payloads:
            test_url = f"{url}{p}" if "?" in url else f"{url}?q={urllib.parse.quote(p)}"
            r = self._req(test_url)
            if r and check in r.text:
                return {
                    "type": "XSS",
                    "url": url,
                    "param": "q" if "?" not in url else "query",
                    "method": "GET",
                    "payload": p,
                    "evidence": f"Payload reflected in response: {p[:40]}",
                    "fix": "Encode output using HTML entity encoding. Implement CSP headers.",
                    "cwe": "CWE-79",
                    "severity": "HIGH"
                }
        return None

    def test_lfi(self, url):
        payloads = ["../../../etc/passwd","..\\..\\..\\windows\\win.ini",
                   "....//....//....//etc/passwd","/etc/passwd%00",
                   "php://filter/read=convert.base64-encode/resource=index.php"]
        indicators = ["root:x:0:0:", "[extensions]", "[fonts]"]
        for p in payloads:
            test_url = f"{url}{p}" if "?" in url else f"{url}?page={p}"
            r = self._req(test_url)
            if r and any(i in r.text for i in indicators):
                return {
                    "type": "LFI",
                    "url": url,
                    "param": "page" if "?" not in url else "file",
                    "method": "GET",
                    "payload": p,
                    "evidence": f"System file contents detected with payload: {p[:30]}",
                    "fix": "Validate and sanitize file paths. Use allowlists. Avoid user input in file paths.",
                    "cwe": "CWE-22",
                    "severity": "HIGH"
                }
        return None

    def test_open_redirect(self, url):
        # FIX: Skip artificial fallback URLs and static files
        if is_static_file(url):
            return None
        if "search=test&redirect=&next=" in url:
            return None

        payloads = ["//evil.com","https://evil.com","/\\evil.com","//google.com/%2f..",
                   "http://evil.com","https://google.com@evil.com"]
        for p in payloads:
            if "?" in url:
                test_url = f"{url}&redirect={urllib.parse.quote(p)}"
            else:
                test_url = f"{url}?redirect={urllib.parse.quote(p)}&next={urllib.parse.quote(p)}&url={urllib.parse.quote(p)}&return={urllib.parse.quote(p)}&returnUrl={urllib.parse.quote(p)}"
            r = self._req(test_url)
            if r and r.status_code in [301,302,307,308]:
                loc = r.headers.get("Location", "")
                # FIX: Exact redirect check, not substring match
                if loc.startswith("//evil.com") or loc.startswith("http://evil.com") or loc.startswith("https://evil.com"):
                    return {
                        "type": "Open Redirect",
                        "url": url,
                        "param": "redirect",
                        "method": "GET",
                        "payload": p,
                        "evidence": f"Redirect to evil.com detected: {loc[:60]}",
                        "fix": "Validate redirect URLs against an allowlist. Use relative paths only.",
                        "cwe": "CWE-601",
                        "severity": "MEDIUM"
                    }
        return None

    def test_cors(self, url):
        headers = {"Origin": "https://evil.com"}
        r = self._req(url, headers=headers)
        if r:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "https://evil.com":
                return {
                    "type": "CORS Misconfiguration",
                    "url": url,
                    "param": "-",
                    "method": "GET",
                    "payload": "Origin: https://evil.com",
                    "evidence": f"Access-Control-Allow-Origin reflects evil.com (credentials={acac})",
                    "fix": "Configure specific allowed origins. Avoid wildcard * with credentials.",
                    "cwe": "CWE-942",
                    "severity": "MEDIUM"
                }
            elif acao == "*" and acac.lower() == "true":
                return {
                    "type": "CORS Misconfiguration",
                    "url": url,
                    "param": "-",
                    "method": "GET",
                    "payload": "Origin: https://evil.com",
                    "evidence": "Wildcard CORS with credentials enabled",
                    "fix": "Configure specific allowed origins. Avoid wildcard * with credentials.",
                    "cwe": "CWE-942",
                    "severity": "MEDIUM"
                }
        return None

    def test_ssrf(self, url):
        # FIX: Skip static files
        if is_static_file(url):
            return None

        payloads = ["http://169.254.169.254/latest/meta-data/","http://localhost:22",
                   "http://127.0.0.1:80","http://[::1]:80","dict://localhost:11211/"]
        for p in payloads:
            if "?" not in url:
                test_url = f"{url}?url={urllib.parse.quote(p)}"
            else:
                test_url = f"{url}&url={urllib.parse.quote(p)}"
            r = self._req(test_url)
            if r and r.status_code == 200:
                text_lower = r.text.lower()
                if any(x in text_lower for x in ["ami-id", "instance-id", "instance-type", "hostname"]):
                    return {
                        "type": "SSRF",
                        "url": url,
                        "param": "url",
                        "method": "GET",
                        "payload": p,
                        "evidence": "AWS metadata accessed via SSRF payload",
                        "fix": "Validate and sanitize URLs. Use allowlists for allowed domains/IPs.",
                        "cwe": "CWE-918",
                        "severity": "HIGH"
                    }
                elif "ssh-" in text_lower or "openssh" in text_lower:
                    return {
                        "type": "SSRF",
                        "url": url,
                        "param": "url",
                        "method": "GET",
                        "payload": p,
                        "evidence": "Internal SSH service accessed via SSRF",
                        "fix": "Validate and sanitize URLs. Use allowlists for allowed domains/IPs.",
                        "cwe": "CWE-918",
                        "severity": "HIGH"
                    }
        return None

    def test_idor(self, url):
        # FIX: Skip static files - query params don't affect images/CSS/JS
        if is_static_file(url):
            return None
        if "?" in url and any(x in url for x in ["id=","user=","account=","order="]):
            original = url
            for i in range(1, 5):
                test = re.sub(r"(id|user|account|order)=\d+", lambda m: f"{m.group(1)}={i}", original)
                if test != original:
                    r = self._req(test)
                    if r and r.status_code == 200 and len(r.content) > 500:
                        return {
                            "type": "IDOR",
                            "url": url,
                            "param": "id",
                            "method": "GET",
                            "payload": f"Changed ID to {i}",
                            "evidence": f"Different ID ({i}) returns valid content ({len(r.content)} bytes)",
                            "fix": "Implement proper access control checks. Use indirect object references.",
                            "cwe": "CWE-639",
                            "severity": "MEDIUM"
                        }
        return None

    def test_header_injection(self, url):
        r = self._req(url, headers={"X-Forwarded-Host": "evil.com", "X-HTTP-Host-Override": "evil.com"})
        if r:
            loc = r.headers.get("Location", "")
            body = r.text
            if "evil.com" in loc or "evil.com" in body:
                return {
                    "type": "Header Injection",
                    "url": url,
                    "param": "X-Forwarded-Host",
                    "method": "GET",
                    "payload": "X-Forwarded-Host: evil.com",
                    "evidence": "Host header poisoning reflected in response",
                    "fix": "Validate and sanitize host headers. Use a whitelist of valid hosts.",
                    "cwe": "CWE-644",
                    "severity": "MEDIUM"
                }
        return None

    def _test_endpoint(self, ep):
        findings = []
        tests = [
            self.test_sqli, self.test_xss, self.test_lfi,
            self.test_open_redirect, self.test_cors, self.test_ssrf,
            self.test_idor, self.test_header_injection
        ]
        for test in tests:
            try:
                result = test(ep)
                if result:
                    findings.append(result)
            except Exception:
                pass
        return findings

    def scan(self):
        print(f"[+] Testing {len(self.endpoints)} endpoints for vulnerabilities...")
        all_findings = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._test_endpoint, ep): ep for ep in self.endpoints}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    all_findings.extend(result)

        seen = set()
        deduped = []
        for f in all_findings:
            key = (f.get("url"), f.get("type"))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        self.findings = deduped
        if self.findings:
            for f in self.findings:
                print(f"    [!] [{f.get('severity','MEDIUM')}] {f.get('type','')} at {f.get('url','')}")
        else:
            print("    [-] No confirmed vulnerabilities found")
        return self.findings