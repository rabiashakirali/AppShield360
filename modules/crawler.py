#!/usr/bin/env python3
import requests
import re
from urllib.parse import urljoin, urlparse

class Crawler:
    def __init__(self, target, max_depth=2, max_urls=100, timeout=10):
        self.target = target.rstrip("/")
        self.domain = urlparse(self.target).netloc
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.visited = set()
        self.endpoints = []
        self.js_files = []
        self.forms = []

    def _fetch(self, url):
        try:
            r = requests.get(url, timeout=self.timeout, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
            return r
        except:
            return None

    def _extract_links(self, url, html):
        links = set()
        # href links
        for match in re.findall(r"href=[\"\']?(.*?)[\"\'\s>]", html, re.IGNORECASE):
            full = urljoin(url, match)
            if self.domain in full:
                links.add(full.split("#")[0])
        # src links
        for match in re.findall(r"src=[\"\']?(.*?)[\"\'\s>]", html, re.IGNORECASE):
            full = urljoin(url, match)
            if self.domain in full:
                links.add(full.split("#")[0])
        # JS files
        for match in re.findall(r"src=[\"\']?(.*?\.js)[\"\'\s>]", html, re.IGNORECASE):
            full = urljoin(url, match)
            if self.domain in full:
                self.js_files.append(full)
        # API endpoints in JS
        for match in re.findall(r"[\"\'](/api/[^\"\'\s]+)[\"\']", html):
            self.endpoints.append(urljoin(url, match))
        # Forms
        for match in re.findall(r"<form.*?action=[\"\']?(.*?)[\"\'\s>].*?>", html, re.IGNORECASE | re.DOTALL):
            self.forms.append(urljoin(url, match))
        return links

    def crawl(self, url=None, depth=0):
        if url is None:
            url = self.target
        if depth > self.max_depth or url in self.visited or len(self.visited) >= self.max_urls:
            return
        self.visited.add(url)
        r = self._fetch(url)
        if not r or "text/html" not in r.headers.get("Content-Type", ""):
            return
        links = self._extract_links(url, r.text)
        for link in links:
            if link not in self.visited:
                self.crawl(link, depth + 1)

    def get_endpoints(self):
        self.crawl()
        all_eps = list(self.visited) + self.endpoints + self.forms
        fallbacks = [
            f"{self.target}/", f"{self.target}/about", f"{self.target}/contact",
            f"{self.target}/login", f"{self.target}/register", f"{self.target}/api",
            f"{self.target}/search", f"{self.target}/products", f"{self.target}/services",
            f"{self.target}/blog", f"{self.target}/news", f"{self.target}/help",
            f"{self.target}/faq", f"{self.target}/terms", f"{self.target}/privacy",
            f"{self.target}/sitemap", f"{self.target}/robots.txt"
        ]
        for fb in fallbacks:
            if fb not in all_eps:
                all_eps.append(fb)
        param_eps = []
        for ep in all_eps[:20]:
            if "?" not in ep:
                param_eps.append(f"{ep}?id=1&search=test&redirect=&next=")
        all_eps.extend(param_eps)
        print(f"[+] Crawler found {len(self.visited)} pages, {len(self.js_files)} JS files")
        return list(set(all_eps))[:self.max_urls]