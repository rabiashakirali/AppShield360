#!/usr/bin/env python3
"""AppShield 360 - API Security Scanner"""
import requests

class APIScanner:
    def __init__(self, target):
        self.target = target if target.startswith("http") else f"https://{target}"
        self.target = self.target.rstrip("/")
        self.session = requests.Session()
        self.issues = []
    
    def scan(self):
        endpoints = ["/api","/api/v1","/api/v2","/swagger.json","/openapi.json","/graphql","/rest","/api/users","/api/admin"]
        found_apis = []
        for ep in endpoints:
            try:
                url = f"{self.target}{ep}"
                resp = self.session.get(url, timeout=8)
                if resp.status_code == 200:
                    ct = resp.headers.get("Content-Type","")
                    if "json" in ct:
                        found_apis.append({"endpoint": ep, "status": 200, "type": "JSON API"})
                    elif "html" in ct and ("swagger" in resp.text.lower() or "openapi" in resp.text.lower()):
                        found_apis.append({"endpoint": ep, "status": 200, "type": "API Documentation"})
            except: pass
        if found_apis:
            self.issues.append({"type": "Exposed API Endpoints", "severity": "INFO", "detail": f"Found {len(found_apis)} API endpoints", "endpoints": found_apis, "fix": "Ensure API endpoints require authentication", "cwe": "CWE-306"})
        return self.issues