#!/usr/bin/env python3
import requests
import re
from urllib.parse import urlparse

class TechStackScanner:
    def __init__(self, target, timeout=15):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.headers = {}
        self.technologies = []
        self.server = "Unknown"
        self.waf = None
        
        self.signatures = {
            "nginx": {"headers": ["Server: nginx"], "html": []},
            "Apache": {"headers": ["Server: Apache"], "html": []},
            "IIS": {"headers": ["Microsoft-IIS"], "html": []},
            "Cloudflare": {"headers": ["CF-RAY", "cloudflare"], "html": []},
            "AWS": {"headers": ["X-Amz-Cf-Id", "awselb"], "html": []},
            "Akamai": {"headers": ["AkamaiGHost", "X-Akamai"], "html": []},
            "Django": {"headers": [], "html": ["csrfmiddlewaretoken", "__debug__", "/static/admin/"], "cookies": ["csrftoken"]},
            "Flask": {"headers": ["Werkzeug"], "html": [], "cookies": []},
            "Laravel": {"headers": [], "html": [], "cookies": ["laravel_session"]},
            "Express.js": {"headers": ["X-Powered-By: Express"], "html": [], "cookies": ["connect.sid"]},
            "ASP.NET": {"headers": ["X-AspNet-Version", "ASP.NET"], "html": ["__VIEWSTATE"], "cookies": ["ASP.NET_SessionId"]},
            "Spring": {"headers": ["X-Application-Context"], "html": [], "cookies": ["JSESSIONID"]},
            "WordPress": {"headers": [], "html": ["/wp-content/", "/wp-includes/", "wp-json"], "cookies": []},
            "Joomla": {"headers": [], "html": ["/media/system/js/", "Joomla"], "cookies": []},
            "Drupal": {"headers": [], "html": ["drupal.js", "/sites/default/"], "cookies": []},
            "Shopify": {"headers": [], "html": ["cdn.shopify.com", "Shopify.theme"], "cookies": []},
            "React": {"headers": [], "html": ["reactroot", "data-reactroot", "__NEXT_DATA__"], "cookies": []},
            "Vue.js": {"headers": [], "html": ["vue.js", "vue.min.js", "__VUE__"], "cookies": []},
            "Angular": {"headers": [], "html": ["ng-app", "angular.js", "ng-version"], "cookies": []},
            "jQuery": {"headers": [], "html": ["jquery.min.js", "jquery.js"], "cookies": []},
            "Bootstrap": {"headers": [], "html": ["bootstrap.min.css", "bootstrap.css"], "cookies": []},
            "phpMyAdmin": {"headers": [], "html": [], "endpoints": ["/phpmyadmin", "/pma"]},
            "GraphQL": {"headers": [], "html": [], "endpoints": ["/graphql", "/api/graphql"]},
            "Swagger": {"headers": [], "html": ["swagger-ui", "Swagger UI"], "endpoints": ["/swagger-ui.html", "/api-docs", "/swagger.json"]},
            "Google Analytics": {"headers": [], "html": ["google-analytics.com", "gtag(", "googletagmanager"], "cookies": ["_ga"]},
        }
        
        self.waf_signatures = {
            "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
            "AWS WAF": ["awselb", "awsalb"],
            "Akamai": ["akamai", "akamaighost"],
            "Sucuri": ["x-sucuri", "sucuri"],
            "Incapsula": ["incap_ses", "visid_incap"],
            "ModSecurity": ["mod_security"],
            "F5 BIG-IP": ["bigip", "f5"],
            "Barracuda": ["barra"],
        }

    def _fetch(self, url):
        try:
            return requests.get(url, timeout=self.timeout, allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        except:
            return None

    def scan(self):
        print(f"[+] Analyzing technology stack...")
        resp = self._fetch(self.target)
        if not resp:
            return {"server": "Unknown", "technologies": [], "waf": None}

        # Headers
        self.headers = dict(resp.headers)
        srv = resp.headers.get('Server', '')
        if srv:
            self.server = srv
        
        all_hdr = ' '.join([f"{k}:{v}" for k,v in resp.headers.items()]).lower()
        for waf, sigs in self.waf_signatures.items():
            for s in sigs:
                if s.lower() in all_hdr:
                    self.waf = waf
                    self.technologies.append(f"WAF: {waf}")
                    break

        # HTML
        html = resp.text.lower()
        for tech, sigs in self.signatures.items():
            found = False
            for h in sigs.get("headers", []):
                if h.lower() in all_hdr:
                    found = True
            for h in sigs.get("html", []):
                if h.lower() in html:
                    found = True
            for c in sigs.get("cookies", []):
                if c.lower() in str(resp.cookies).lower():
                    found = True
            if found and tech not in self.technologies:
                self.technologies.append(tech)

        # Check endpoints
        endpoints = ["/robots.txt", "/.env", "/.git/HEAD", "/admin", "/login", "/api", "/phpmyadmin", "/swagger-ui.html"]
        found_eps = []
        for ep in endpoints:
            try:
                r = requests.get(f"{self.target}{ep}", timeout=8, allow_redirects=False,
                    headers={'User-Agent': 'Mozilla/5.0'})
                if r.status_code in [200, 401, 403, 407]:
                    found_eps.append(f"{ep} ({r.status_code})")
            except:
                pass

        print(f"[+] Server: {self.server}")
        if self.technologies:
            print(f"[+] Technologies: {', '.join(self.technologies)}")
        if found_eps:
            print(f"[+] Endpoints: {', '.join(found_eps)}")

        return {"server": self.server, "technologies": self.technologies, "waf": self.waf, "endpoints": found_eps}