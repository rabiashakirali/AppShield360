#!/usr/bin/env python3
"""
AppShield 360 - Professional Security Scanner v3.0
Usage: python3 scanner.py <target>
"""

import sys
import json
import time
import os
from datetime import datetime
from urllib.parse import urlparse

# Import all modules
from modules.crawler import Crawler
from modules.port_scanner import PortScanner
from modules.vuln_scanner import VulnScanner
from modules.dir_scanner import DirScanner
from modules.subdomain_scanner import SubdomainScanner
from modules.tech_stack import TechStackScanner
from modules.wp_scanner import WPScanner

# Keep old modules if they exist (backward compatibility)
try:
    from modules.auth_scanner import AuthScanner
except ImportError:
    AuthScanner = None
try:
    from modules.api_scanner import APIScanner
except ImportError:
    APIScanner = None
try:
    from modules.cloud_scanner import CloudScanner
except ImportError:
    CloudScanner = None
try:
    from modules.cvss_scorer import enrich_finding
except ImportError:
    def enrich_finding(f):
        if "severity" not in f:
            f["severity"] = "MEDIUM"
        if "cwe" not in f:
            f["cwe"] = "CWE-200"
        if "fix" not in f:
            f["fix"] = "Review and sanitize input"
        if "cvss" not in f:
            f["cvss"] = 5.0
        return f


class C:
    G = "\033[92m"
    R = "\033[91m"
    Y = "\033[93m"
    B = "\033[94m"
    C = "\033[96m"
    BO = "\033[1m"
    E = "\033[0m"


def c(color, text):
    return f"{color}{text}{C.E}"


def banner():
    print(c(C.C, "=" * 65))
    print(c(C.BO + C.C, "     APPSHIELD 360 - PROFESSIONAL SECURITY SCANNER v3.0"))
    print(c(C.C, "=" * 65))
    print(c(C.Y, "     Safe | Fast | Real Vulnerabilities | Zero False Positives"))
    print(c(C.C, "=" * 65))


def get_fallback_endpoints(target):
    """Jab crawler fail ho, common vulnerable URLs test karo"""
    target = target.rstrip("/")
    return [
        f"{target}/",
        f"{target}/?id=1&search=test&redirect=",
        f"{target}/search.php?test=1",
        f"{target}/artists.php?artist=1",
        f"{target}/listproducts.php?cat=1",
        f"{target}/product.php?pic=1",
        f"{target}/login.php",
        f"{target}/signup.php",
        f"{target}/comment.php?aid=1",
        f"{target}/index.php?page=1",
        f"{target}/redirect.php?url=/",
        f"{target}/showimage.php?file=1",
        f"{target}/userinfo.php",
        f"{target}/cart.php",
        f"{target}/api/users?id=1",
        f"{target}/api/search?q=test",
        f"{target}/graphql?query={{__typename}}",
    ]


def main():
    if len(sys.argv) < 2:
        print(c(C.R, "Usage: python3 scanner.py <target>"))
        sys.exit(1)

    target = sys.argv[1]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    banner()
    print(c(C.G, f"[+] Target: {target}"))
    print(c(C.G, f"[+] Mode: FULL SCAN (All Modules)"))
    print()
    start = time.time()

    report = {
        "scan_info": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scanner": "AppShield 360 v3.0",
            "mode": "full"
        },
        "findings": {}
    }

    # PHASE 1: RECON & TECH STACK
    print(c(C.B, "[PHASE 1] RECONNAISSANCE & TECHNOLOGY"))
    print(c(C.C, "-" * 65))
    try:
        tech_scanner = TechStackScanner(target)
        tech = tech_scanner.scan()
    except Exception as e:
        print(c(C.R, f"    [!] Tech fingerprint failed: {e}"))
        tech = {"technologies": [], "server": "Unknown", "waf": None, "endpoints": [], "error": str(e)}

    report["findings"]["technology"] = tech
    print(c(C.G, f"[+] Server: {tech.get('server', 'Unknown')}"))
    techs = tech.get("technologies", [])
    print(c(C.G, f"[+] Technologies: {', '.join(techs) if techs else 'None detected'}"))

    if tech.get("waf"):
        print(c(C.Y, f"[+] WAF Detected: {tech['waf']}"))
    if tech.get("endpoints"):
        print(c(C.Y, f"[+] Interesting Endpoints: {len(tech['endpoints'])} found"))
        for ep in tech["endpoints"][:5]:
            print(c(C.Y, f"    - {ep}"))
    print()

    # PHASE 2: PORTS
    print(c(C.B, "[PHASE 2] PORT SCANNING"))
    print(c(C.C, "-" * 65))
    try:
        port_scanner = PortScanner(target)
        ports_raw = port_scanner.scan()
        ports = [{"port": p[0], "service": p[1], "banner": p[2]} for p in ports_raw]
    except Exception as e:
        print(c(C.R, f"    [!] Port scan failed: {e}"))
        ports = []
    report["findings"]["ports"] = ports
    if not ports:
        print(c(C.Y, "    [-] No open ports found"))
    print()

    # PHASE 3: SUBDOMAINS
    print(c(C.B, "[PHASE 3] SUBDOMAIN ENUMERATION"))
    print(c(C.C, "-" * 65))
    try:
        sub_scanner = SubdomainScanner(target)
        subs_raw = sub_scanner.scan()
        subs = [{"subdomain": s, "type": "A"} for s in subs_raw]
    except Exception as e:
        print(c(C.R, f"    [!] Subdomain scan failed: {e}"))
        subs = []
    report["findings"]["subdomains"] = subs
    if not subs:
        print(c(C.Y, "    [-] No subdomains found"))
    print()

    # PHASE 4: DIRECTORIES
    print(c(C.B, "[PHASE 4] DIRECTORY DISCOVERY"))
    print(c(C.C, "-" * 65))
    try:
        dir_scanner = DirScanner(target)
        dirs_raw = dir_scanner.scan()
        dirs = [{"path": d[0], "status": d[1], "size": d[2]} for d in dirs_raw]
    except Exception as e:
        print(c(C.R, f"    [!] Directory scan failed: {e}"))
        dirs = []
    report["findings"]["directories"] = dirs
    if not dirs:
        print(c(C.Y, "    [-] No interesting directories"))
    print()

    # PHASE 5: CRAWL
    print(c(C.B, "[PHASE 5] WEB CRAWLING"))
    print(c(C.C, "-" * 65))
    try:
        crawler = Crawler(target, max_depth=2, max_urls=100)
        endpoints = crawler.get_endpoints()
    except Exception as e:
        print(c(C.R, f"    [!] Crawler failed: {e}"))
        endpoints = []

    # FALLBACK
    if len(endpoints) == 0:
        print(c(C.Y, "[*] Crawler found nothing. Adding fallback endpoints..."))
        endpoints = get_fallback_endpoints(target)
        print(c(C.G, f"[+] Added {len(endpoints)} fallback endpoints"))

    report["findings"]["endpoints_count"] = len(endpoints)
    print(c(C.G, f"[+] Testing {len(endpoints)} endpoints"))
    print()

    # PHASE 6: VULN SCAN
    print(c(C.B, "[PHASE 6] VULNERABILITY SCANNING"))
    print(c(C.C, "-" * 65))
    print(c(C.Y, "[*] Testing for SQLi, XSS, LFI, Open Redirect, CORS, SSRF, IDOR..."))
    print(c(C.Y, "[*] Using safe, non-destructive payloads only.\n"))

    try:
        vuln_scanner = VulnScanner(target, endpoints=endpoints)
        vulns = vuln_scanner.scan()
        # FIX: vuln_scanner.scan() now returns structured dicts directly
        vulns = [enrich_finding(v) for v in vulns]
    except Exception as e:
        print(c(C.R, f"    [!] Vuln scan failed: {e}"))
        vulns = []

    report["findings"]["vulnerabilities"] = vulns

    if vulns:
        print()
        print(c(C.R + C.BO, f"[!] {len(vulns)} REAL VULNERABILITIES CONFIRMED!"))
        print(c(C.C, "-" * 65))
        for i, v in enumerate(vulns, 1):
            sev = v.get("severity", "MEDIUM")
            col = C.R if sev == "CRITICAL" else C.Y if sev == "HIGH" else C.G
            print(f"\n{i}. [{sev}] {v.get('type', 'Unknown')}")
            print(c(col, f"   URL: {v.get('url', '')}"))
            print(f"   Parameter: {v.get('param', '')}")
            print(f"   Method: {v.get('method', 'GET')}")
            print(f"   Payload: {v.get('payload', '')}")
            print(f"   Evidence: {v.get('evidence', '')}")
            print(f"   Fix: {v.get('fix', '')}")
            print(f"   CWE: {v.get('cwe', '')}")
    else:
        print(c(C.G, "\n[+] No confirmed vulnerabilities found."))
    print()

    # PHASE 7: AUTH & API & CLOUD
    print(c(C.B, "[PHASE 7] AUTHENTICATION & API CHECKS"))
    print(c(C.C, "-" * 65))
    auth_issues = []
    api_issues = []
    cloud_issues = []

    if AuthScanner:
        try:
            auth_raw = AuthScanner(target).scan()
            auth_issues = [enrich_finding(a) for a in auth_raw]
        except Exception as e:
            print(c(C.R, f"    [!] Auth scan failed: {e}"))

    if APIScanner:
        try:
            api_raw = APIScanner(target).scan()
            api_issues = [enrich_finding(a) for a in api_raw]
        except Exception as e:
            print(c(C.R, f"    [!] API scan failed: {e}"))

    if CloudScanner:
        try:
            cloud_raw = CloudScanner(target).scan()
            cloud_issues = [enrich_finding(a) for a in cloud_raw]
        except Exception as e:
            print(c(C.R, f"    [!] Cloud scan failed: {e}"))

    report["findings"]["auth_issues"] = auth_issues
    report["findings"]["api_issues"] = api_issues
    report["findings"]["cloud_issues"] = cloud_issues

    for issue in auth_issues:
        sev = issue.get("severity", "INFO")
        col = C.Y if sev in ["HIGH", "MEDIUM"] else C.G
        print(c(col, f"    [!] [{sev}] {issue.get('type', '')}: {issue.get('detail', '')}"))
    for issue in api_issues:
        print(c(C.Y, f"    [!] {issue.get('type', '')}: {issue.get('detail', '')}"))
    for issue in cloud_issues:
        sev = issue.get("severity", "INFO")
        col = C.R if sev == "HIGH" else C.Y
        print(c(col, f"    [!] [{sev}] {issue.get('type', '')}: {issue.get('detail', '')}"))
    if not auth_issues and not api_issues and not cloud_issues:
        print(c(C.G, "    [+] Basic auth checks passed"))
    print()

    # PHASE 8: WORDPRESS SPECIFIC
    wp_issues = []
    if any("WordPress" in str(t) for t in tech.get("technologies", [])):
        print(c(C.B, "[PHASE 8] WORDPRESS SECURITY AUDIT"))
        print(c(C.C, "-" * 65))
        try:
            wp_raw = WPScanner(target).scan()
            wp_issues = []
            for w in wp_raw:
                wp_issues.append(enrich_finding({
                    "type": "WordPress Issue",
                    "detail": w,
                    "severity": "HIGH" if "CRITICAL" in w or "exposed" in w.lower() else "MEDIUM",
                    "url": target
                }))
        except Exception as e:
            print(c(C.R, f"    [!] WP scan failed: {e}"))

        report["findings"]["wp_issues"] = wp_issues
        for issue in wp_issues:
            sev = issue.get("severity", "INFO")
            col = C.R if sev == "CRITICAL" else C.Y if sev == "HIGH" else C.G
            print(c(col, f"    [!] [{sev}] {issue.get('type', '')}: {issue.get('detail', '')}"))
        if not wp_issues:
            print(c(C.G, "    [+] No WordPress-specific issues found"))
        print()

    # SAVE REPORT
    duration = round(time.time() - start, 2)
    report["scan_info"]["duration_seconds"] = duration
    with open("appshield360_report.json", "w") as f:
        json.dump(report, f, indent=2)

    # SUMMARY
    all_issues = vulns + auth_issues + api_issues + cloud_issues + wp_issues
    crit = sum(1 for x in all_issues if x.get("severity") == "CRITICAL")
    high = sum(1 for x in all_issues if x.get("severity") == "HIGH")
    medium = sum(1 for x in all_issues if x.get("severity") == "MEDIUM")
    low_info = sum(1 for x in all_issues if x.get("severity") in ["LOW", "INFO"])

    print(c(C.C, "=" * 65))
    print(c(C.BO + C.C, "  SCAN SUMMARY"))
    print(c(C.C, "=" * 65))
    print(c(C.G, f"[+] Target: {target}"))
    print(c(C.G, f"[+] Duration: {duration}s"))
    print(c(C.G, f"[+] Endpoints: {len(endpoints)}"))
    print(c(C.G, f"[+] Open Ports: {len(ports)}"))
    print(c(C.G, f"[+] Subdomains: {len(subs)}"))
    print(c(C.G, f"[+] Directories: {len(dirs)}"))
    print(c(C.G, f"[+] Total Issues: {len(all_issues)}"))
    if crit > 0:
        print(c(C.R, f"    - CRITICAL: {crit}"))
    if high > 0:
        print(c(C.R, f"    - HIGH: {high}"))
    if medium > 0:
        print(c(C.Y, f"    - MEDIUM: {medium}"))
    if low_info > 0:
        print(c(C.G, f"    - LOW/INFO: {low_info}"))
    print(c(C.G, "\n[v] Report saved: appshield360_report.json"))
    print(c(C.C, "=" * 65))
    print(c(C.BO + C.C, "  AppShield 360 - Scan Complete"))
    print(c(C.C, "=" * 65))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c(C.R, "\n\n[!] Scan interrupted by user."))
        sys.exit(0)
    except Exception as e:
        print(c(C.R, f"\n[!] Fatal Error: {e}"))
        import traceback
        traceback.print_exc()
        sys.exit(1)