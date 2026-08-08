#!/usr/bin/env python3
"""AppShield 360 - Cloud Configuration Scanner"""
import requests

class CloudScanner:
    def __init__(self, target):
        self.domain = target.replace("https://","").replace("http://","").split("/")[0]
        self.issues = []
    
    def scan(self):
        checks = [
            (f"https://{self.domain}.s3.amazonaws.com", "S3 Bucket"),
            (f"https://s3.amazonaws.com/{self.domain}", "S3 Bucket (path-style)"),
        ]
        for url, service in checks:
            try:
                resp = requests.get(url, timeout=8)
                if resp.status_code == 200 and "ListBucketResult" in resp.text:
                    self.issues.append({"type": "Exposed Cloud Storage", "severity": "HIGH", "detail": f"{service} public: {url}", "fix": "Restrict bucket permissions. Disable public access.", "cwe": "CWE-306"})
                elif resp.status_code == 403:
                    self.issues.append({"type": "Cloud Storage Detected", "severity": "INFO", "detail": f"{service} exists (403 - check permissions)", "fix": "Verify bucket permissions", "cwe": "CWE-306"})
            except: pass
        return self.issues