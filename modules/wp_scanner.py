#!/usr/bin/env python3
import requests
import re

class WPScanner:
    def __init__(self, target, timeout=10):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.findings = []

    def _req(self, path):
        try:
            return requests.get(f"{self.target}{path}", timeout=self.timeout,
                headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=False)
        except:
            return None

    def scan(self):
        print(f"[+] Checking WordPress specific endpoints...")
        r = self._req('/feed/')
        if r and 'wordpress' in r.text.lower():
            m = re.search(r'<generator>https://wordpress.org/\?v=(.+?)</generator>', r.text)
            if m:
                self.findings.append(f"WordPress version: {m.group(1)}")
        r = self._req('/readme.html')
        if r and r.status_code == 200 and 'WordPress' in r.text:
            self.findings.append("WordPress readme.html exposed")
        for i in range(1, 6):
            r = self._req(f'/wp-json/wp/v2/users/{i}')
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    self.findings.append(f"WP User found: {data.get('name')} ({data.get('slug')})")
                except:
                    pass
        plugins = ["woocommerce","elementor","contact-form-7","yoast-seo","akismet",
                  "wordfence","jetpack","wp-super-cache","all-in-one-seo-pack"]
        for plugin in plugins:
            r = self._req(f'/wp-content/plugins/{plugin}/readme.txt')
            if r and r.status_code == 200:
                m = re.search(r'Stable tag:\s*(.+)', r.text)
                ver = m.group(1) if m else "unknown"
                self.findings.append(f"WP Plugin: {plugin} v{ver}")
        r = self._req('/wp-content/themes/')
        if r and r.status_code == 200:
            themes = re.findall(r'href="([\w-]+)/"', r.text)
            for t in themes[:5]:
                self.findings.append(f"WP Theme: {t}")
        r = self._req('/xmlrpc.php')
        if r and r.status_code == 405:
            self.findings.append("XML-RPC enabled (potential brute force vector)")
        for ext in ['.bak','.old','.save','.swp','.txt','~']:
            r = self._req(f'/wp-config.php{ext}')
            if r and r.status_code == 200 and 'DB_' in r.text:
                self.findings.append(f"CRITICAL: wp-config.php{ext} exposed!")
        if self.findings:
            for f in self.findings:
                print(f"    [!] {f}")
        else:
            print("    [-] No WP issues found")
        return self.findings