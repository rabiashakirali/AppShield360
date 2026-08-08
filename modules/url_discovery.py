#!/usr/bin/env python3
"""AppShield 360 - Wayback Machine URL Discovery"""
import requests

class URLDiscovery:
    def __init__(self, target):
        self.domain = target.replace("https://","").replace("http://","").split("/")[0]
    
    def discover(self):
        endpoints = []
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey"
            resp = requests.get(url, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                seen = set()
                for item in data[1:]:  # skip header
                    u = item[2]
                    if "?" in u and u not in seen:
                        seen.add(u)
                        params = [p.split("=")[0] for p in u.split("?")[1].split("&") if "=" in p]
                        endpoints.append({"url": u, "params": params, "forms": [], "links": []})
                        if len(endpoints) >= 30:
                            break
        except Exception:
            pass
        return endpoints