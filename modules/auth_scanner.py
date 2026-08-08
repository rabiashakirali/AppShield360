#!/usr/bin/env python3
"""AppShield 360 - Authentication Scanner"""
import requests

class AuthScanner:
    def __init__(self, target):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.target = self.target.rstrip("/")
        self.session = requests.Session()
        self.issues = []
    
    def scan(self):
        try:
            resp = self.session.get(self.target, timeout=10)
            headers = resp.headers
            
            if "X-Frame-Options" not in headers:
                self.issues.append({"type": "Missing Security Header", "severity": "MEDIUM", "detail": "X-Frame-Options missing (Clickjacking possible)", "fix": "Add X-Frame-Options: DENY or SAMEORIGIN", "cwe": "CWE-1021"})
            if "Content-Security-Policy" not in headers:
                self.issues.append({"type": "Missing Security Header", "severity": "MEDIUM", "detail": "CSP header missing", "fix": "Implement CSP headers", "cwe": "CWE-693"})
            if "Strict-Transport-Security" not in headers:
                self.issues.append({"type": "Missing Security Header", "severity": "MEDIUM", "detail": "HSTS header missing", "fix": "Add Strict-Transport-Security", "cwe": "CWE-319"})
            if "X-Content-Type-Options" not in headers:
                self.issues.append({"type": "Missing Security Header", "severity": "LOW", "detail": "X-Content-Type-Options missing", "fix": "Add X-Content-Type-Options: nosniff", "cwe": "CWE-693"})
            
            for url in [f"{self.target}/login", f"{self.target}/admin", f"{self.target}/wp-login.php"]:
                try:
                    r = self.session.get(url, timeout=5, allow_redirects=False)
                    if r.status_code == 200:
                        self.issues.append({"type": "Exposed Login Endpoint", "severity": "INFO", "detail": f"Login page at {url}", "fix": "Ensure strong passwords and rate limiting", "cwe": "N/A"})
                        break
                except: pass
        except: pass
        return self.issues