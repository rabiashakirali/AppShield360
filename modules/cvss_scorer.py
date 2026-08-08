#!/usr/bin/env python3
"""AppShield 360 - CVSS Scorer & Finding Enricher"""

def get_cvss(vuln_type):
    """Return approximate CVSS score based on vuln type"""
    scores = {
        "SQL Injection": 9.8,
        "XSS": 6.1,
        "LFI": 7.5,
        "Open Redirect": 6.1,
        "CORS Misconfiguration": 5.3,
        "SSRF": 8.6,
        "IDOR": 5.3,
        "Header Injection": 5.3,
    }
    return scores.get(vuln_type, 5.0)

def enrich_finding(finding):
    """Enrich a finding with severity, CWE, and CVSS if missing"""
    vuln_type = finding.get("type", "")

    # Determine severity based on type if not present
    if "severity" not in finding or not finding["severity"]:
        severity_map = {
            "SQL Injection": "CRITICAL",
            "LFI": "HIGH",
            "SSRF": "HIGH",
            "XSS": "HIGH",
            "Open Redirect": "MEDIUM",
            "CORS Misconfiguration": "MEDIUM",
            "IDOR": "MEDIUM",
            "Header Injection": "MEDIUM",
        }
        finding["severity"] = severity_map.get(vuln_type, "MEDIUM")

    # Determine CWE based on type
    cwe_map = {
        "SQL Injection": "CWE-89",
        "XSS": "CWE-79",
        "LFI": "CWE-22",
        "Open Redirect": "CWE-601",
        "CORS Misconfiguration": "CWE-942",
        "SSRF": "CWE-918",
        "IDOR": "CWE-639",
        "Header Injection": "CWE-644",
    }
    if "cwe" not in finding or not finding["cwe"] or (finding["cwe"] == "CWE-79" and vuln_type != "XSS"):
        finding["cwe"] = cwe_map.get(vuln_type, "CWE-200")

    # Add CVSS score
    if "cvss" not in finding or not finding["cvss"]:
        finding["cvss"] = get_cvss(vuln_type)

    # Add fix recommendation
    if "fix" not in finding or not finding["fix"] or finding["fix"] == "Review and sanitize input":
        fix_map = {
            "SQL Injection": "Use parameterized queries/prepared statements. Validate and sanitize all user inputs.",
            "XSS": "Encode output using HTML entity encoding. Implement CSP headers. Validate input.",
            "LFI": "Validate and sanitize file paths. Use allowlists. Avoid user input in file paths.",
            "Open Redirect": "Validate redirect URLs against an allowlist. Use relative paths only.",
            "CORS Misconfiguration": "Configure specific allowed origins. Avoid wildcard * with credentials.",
            "SSRF": "Validate and sanitize URLs. Use allowlists for allowed domains/IPs. Disable unnecessary URL schemes.",
            "IDOR": "Implement proper access control checks. Use indirect object references.",
            "Header Injection": "Validate and sanitize host headers. Use a whitelist of valid hosts.",
        }
        finding["fix"] = fix_map.get(vuln_type, "Review and sanitize input")

    return finding