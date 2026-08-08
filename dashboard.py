#!/usr/bin/env python3
"""AppShield 360 - Web Dashboard (FIXED v3)
Launch: python3 dashboard.py
Open: http://localhost:5000
"""
from flask import Flask, render_template_string, jsonify
import json
import os

app = Flask(__name__)

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AppShield 360 Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; }
.sidebar { width: 260px; background: #1e293b; height: 100vh; position: fixed; padding: 20px; }
.sidebar h1 { color: #38bdf8; font-size: 1.5em; margin-bottom: 30px; }
.sidebar a { display: block; color: #94a3b8; text-decoration: none; padding: 12px; border-radius: 8px; margin-bottom: 5px; }
.sidebar a:hover, .sidebar a.active { background: #334155; color: #f8fafc; }
.main { margin-left: 260px; padding: 30px; }
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
.header h2 { color: #38bdf8; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
.card { background: #1e293b; border-radius: 12px; padding: 25px; border-left: 4px solid #38bdf8; }
.card.red { border-left-color: #ef4444; }
.card.orange { border-left-color: #f97316; }
.card.green { border-left-color: #22c55e; }
.card h4 { color: #94a3b8; font-size: 0.85em; text-transform: uppercase; margin-bottom: 10px; }
.card .num { font-size: 2.2em; font-weight: bold; color: #f8fafc; }
.section { background: #1e293b; border-radius: 12px; padding: 25px; margin-bottom: 20px; }
.section h3 { color: #38bdf8; margin-bottom: 15px; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
th { color: #94a3b8; font-size: 0.8em; text-transform: uppercase; }
.badge { padding: 4px 10px; border-radius: 10px; font-size: 0.7em; font-weight: bold; }
.badge-crit { background: #ef4444; color: white; }
.badge-high { background: #f97316; color: white; }
.badge-med { background: #eab308; color: black; }
.badge-low { background: #22c55e; color: white; }
.empty { color: #64748b; font-style: italic; }
</style>
</head>
<body>
<div class="sidebar">
<h1>🛡️ AppShield 360</h1>
<a href="/" class="active">Dashboard</a>
<a href="/report">View Report</a>
<a href="/api/data">JSON API</a>
</div>
<div class="main">
<div class="header">
<h2>Security Dashboard</h2>
<span style="color:#64748b;">{{ target }}</span>
</div>
<div class="cards">
<div class="card"><h4>Endpoints</h4><div class="num">{{ endpoints }}</div></div>
<div class="card"><h4>Open Ports</h4><div class="num">{{ ports }}</div></div>
<div class="card red"><h4>Critical/High</h4><div class="num">{{ critical }}</div></div>
<div class="card orange"><h4>Medium</h4><div class="num">{{ medium }}</div></div>
<div class="card green"><h4>Low/Info</h4><div class="num">{{ low }}</div></div>
</div>
<div class="section">
<h3>🚨 Vulnerabilities</h3>
{% if vulns %}
<table>
<tr><th>Severity</th><th>Type</th><th>URL</th><th>Parameter</th><th>Method</th></tr>
{% for v in vulns %}
<tr>
<td><span class="badge badge-{{ v.sev_class }}">{{ v.severity }}</span></td>
<td>{{ v.type }}</td>
<td>{{ v.url }}</td>
<td>{{ v.param }}</td>
<td>{{ v.method }}</td>
</tr>
{% endfor %}
</table>
{% else %}
<p class="empty">No confirmed vulnerabilities found.</p>
{% endif %}
</div>
<div class="section">
<h3>🔍 Technology Stack</h3>
<p><strong>Server:</strong> {{ tech_server }}</p>
<p><strong>Detected:</strong> {{ tech_list }}</p>
</div>
</div>
</body>
</html>"""

REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AppShield 360 - Security Report</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
header { text-align: center; padding: 40px 0; border-bottom: 2px solid #334155; margin-bottom: 30px; }
header h1 { color: #38bdf8; font-size: 2.5em; margin-bottom: 10px; }
header p { color: #94a3b8; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }
.card { background: #1e293b; border-radius: 10px; padding: 20px; border-left: 4px solid #38bdf8; }
.card.critical { border-left-color: #ef4444; }
.card.high { border-left-color: #f97316; }
.card.medium { border-left-color: #eab308; }
.card.info { border-left-color: #22c55e; }
.card h3 { color: #94a3b8; font-size: 0.9em; text-transform: uppercase; margin-bottom: 8px; }
.card .value { font-size: 2em; font-weight: bold; color: #f8fafc; }
.section { background: #1e293b; border-radius: 10px; padding: 25px; margin-bottom: 20px; }
.section h2 { color: #38bdf8; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #334155; }
.vuln { background: #0f172a; border-radius: 8px; padding: 15px; margin-bottom: 12px; border-left: 4px solid #ef4444; }
.vuln.high { border-left-color: #f97316; }
.vuln.medium { border-left-color: #eab308; }
.vuln.info { border-left-color: #22c55e; }
.vuln h4 { color: #f8fafc; margin-bottom: 8px; }
.vuln p { color: #cbd5e1; font-size: 0.95em; margin-bottom: 5px; }
.vuln .label { color: #64748b; font-weight: 600; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }
.badge-critical { background: #ef4444; color: white; }
.badge-high { background: #f97316; color: white; }
.badge-medium { background: #eab308; color: black; }
.badge-info { background: #22c55e; color: white; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; }
th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
th { color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.85em; }
td { color: #cbd5e1; }
tr:hover { background: #0f172a; }
footer { text-align: center; padding: 30px; color: #64748b; margin-top: 30px; border-top: 1px solid #334155; }
</style>
</head>
<body>
<div class="container">
<header>
<h1>🛡️ AppShield 360</h1>
<p>Professional Security Audit Report</p>
<p style="margin-top:10px; color:#64748b;">Target: {{TARGET}} | Date: {{DATE}} | Duration: {{DURATION}}s</p>
</header>
<div class="summary">
<div class="card"><h3>Endpoints</h3><div class="value">{{ENDPOINTS}}</div></div>
<div class="card"><h3>Open Ports</h3><div class="value">{{PORTS}}</div></div>
<div class="card critical"><h3>Critical/High</h3><div class="value">{{CRITICAL}}</div></div>
<div class="card medium"><h3>Medium</h3><div class="value">{{MEDIUM}}</div></div>
<div class="card info"><h3>Low/Info</h3><div class="value">{{LOW}}</div></div>
</div>
{{VULNERABILITIES_SECTION}}
{{PORTS_SECTION}}
{{TECH_SECTION}}
{{DIRS_SECTION}}
{{SUBS_SECTION}}
<footer><p>Generated by AppShield 360 v3.0 | Safe & Professional Pentesting Toolkit</p></footer>
</div>
</body>
</html>"""

def load_report():
    try:
        with open("appshield360_report.json", "r") as f:
            return json.load(f)
    except:
        return None

def generate_html_report(data):
    info = data.get("scan_info", {})
    findings = data.get("findings", {})
    target = info.get("target", "Unknown")
    date = info.get("timestamp", "")
    duration = info.get("duration_seconds", 0)
    vulns = findings.get("vulnerabilities", [])
    ports = findings.get("ports", [])
    tech = findings.get("technology", {})
    dirs = findings.get("directories", [])
    subs = findings.get("subdomains", [])
    endpoints = findings.get("endpoints_count", 0)

    all_issues = list(vulns)
    for issue in findings.get("auth_issues", []):
        all_issues.append({
            "severity": issue.get("severity", "INFO"),
            "type": issue.get("type", "Auth Issue"),
            "url": issue.get("detail", "N/A"),
            "param": "-", "method": "-", "payload": "",
            "evidence": issue.get("detail", ""),
            "fix": issue.get("fix", ""),
            "cwe": issue.get("cwe", "N/A")
        })
    for issue in findings.get("api_issues", []):
        all_issues.append({
            "severity": issue.get("severity", "INFO"),
            "type": issue.get("type", "API Issue"),
            "url": issue.get("detail", "N/A"),
            "param": "-", "method": "-", "payload": "",
            "evidence": issue.get("detail", ""),
            "fix": issue.get("fix", ""),
            "cwe": issue.get("cwe", "N/A")
        })
    for issue in findings.get("cloud_issues", []):
        all_issues.append({
            "severity": issue.get("severity", "INFO"),
            "type": issue.get("type", "Cloud Issue"),
            "url": issue.get("detail", "N/A"),
            "param": "-", "method": "-", "payload": "",
            "evidence": issue.get("detail", ""),
            "fix": issue.get("fix", ""),
            "cwe": issue.get("cwe", "N/A")
        })
    for issue in findings.get("wp_issues", []):
        all_issues.append({
            "severity": issue.get("severity", "INFO"),
            "type": issue.get("type", "WordPress Issue"),
            "url": issue.get("url", "N/A"),
            "param": "-", "method": "-", "payload": "",
            "evidence": issue.get("detail", ""),
            "fix": issue.get("fix", ""),
            "cwe": issue.get("cwe", "N/A")
        })

    critical = sum(1 for v in all_issues if v.get("severity") == "CRITICAL")
    high = sum(1 for v in all_issues if v.get("severity") == "HIGH")
    medium = sum(1 for v in all_issues if v.get("severity") == "MEDIUM")
    low = sum(1 for v in all_issues if v.get("severity") in ["LOW", "INFO"])

    vuln_html = '<div class="section"><h2>🚨 Vulnerabilities & Issues</h2>'
    if all_issues:
        for v in all_issues:
            sev = v.get("severity", "INFO").lower()
            badge = f'<span class="badge badge-{sev}">{v.get("severity", "INFO")}</span>'
            vuln_html += f'<div class="vuln {sev}"><h4>{badge} {v.get("type", "Unknown")} <span style="color:#64748b;font-size:0.8em;">({v.get("cwe", "N/A")})</span></h4>'
            vuln_html += f'<p><span class="label">URL:</span> {v.get("url", "N/A")}</p>'
            vuln_html += f'<p><span class="label">Parameter:</span> {v.get("param", "N/A")}</p>'
            vuln_html += f'<p><span class="label">Method:</span> {v.get("method", "N/A")}</p>'
            if v.get("payload"):
                vuln_html += f'<p><span class="label">Payload:</span> <code>{v["payload"]}</code></p>'
            if v.get("evidence"):
                vuln_html += f'<p><span class="label">Evidence:</span> {v["evidence"]}</p>'
            if v.get("fix"):
                vuln_html += f'<p><span class="label">Fix:</span> {v["fix"]}</p></div>'
    else:
        vuln_html += '<p style="color:#22c55e;">✅ No confirmed vulnerabilities found.</p>'
    vuln_html += "</div>"

    ports_html = '<div class="section"><h2>🔌 Open Ports</h2>'
    if ports:
        ports_html += '<table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>'
        for p in ports:
            ports_html += f'<tr><td>{p["port"]}/tcp</td><td>{p["service"]}</td><td>{p.get("banner", "")[:60]}</td></tr>'
        ports_html += "</table>"
    else:
        ports_html += "<p>No unusual open ports detected.</p>"
    ports_html += "</div>"

    tech_html = '<div class="section"><h2>🔍 Technology Stack</h2>'
    tech_html += f'<p><strong>Server:</strong> {tech.get("server", "Unknown")}</p>'
    if tech.get("technologies"):
        tech_html += f'<p><strong>Detected:</strong> {", ".join(tech["technologies"])}</p>'
    if tech.get("waf"):
        tech_html += f'<p><strong>WAF:</strong> {tech["waf"]}</p>'
    tech_html += "</div>"

    dirs_html = '<div class="section"><h2>📁 Discovered Directories</h2>'
    if dirs:
        dirs_html += '<table><tr><th>Path</th><th>Status</th><th>Size</th></tr>'
        for d in dirs:
            dirs_html += f'<tr><td>{d["path"]}</td><td>{d["status"]}</td><td>{d["size"]} bytes</td></tr>'
        dirs_html += "</table>"
    else:
        dirs_html += "<p>No interesting directories found.</p>"
    dirs_html += "</div>"

    subs_html = '<div class="section"><h2>🌐 Subdomains</h2>'
    if subs:
        subs_html += '<table><tr><th>Subdomain</th><th>Type</th></tr>'
        for s in subs:
            subs_html += f'<tr><td>{s["subdomain"]}</td><td>{s["type"]}</td></tr>'
        subs_html += "</table>"
    else:
        subs_html += "<p>No common subdomains found.</p>"
    subs_html += "</div>"

    html = REPORT_HTML_TEMPLATE
    html = html.replace("{{TARGET}}", target)
    html = html.replace("{{DATE}}", date)
    html = html.replace("{{DURATION}}", str(duration))
    html = html.replace("{{ENDPOINTS}}", str(endpoints))
    html = html.replace("{{PORTS}}", str(len(ports)))
    html = html.replace("{{CRITICAL}}", str(critical + high))
    html = html.replace("{{MEDIUM}}", str(medium))
    html = html.replace("{{LOW}}", str(low))
    html = html.replace("{{VULNERABILITIES_SECTION}}", vuln_html)
    html = html.replace("{{PORTS_SECTION}}", ports_html)
    html = html.replace("{{TECH_SECTION}}", tech_html)
    html = html.replace("{{DIRS_SECTION}}", dirs_html)
    html = html.replace("{{SUBS_SECTION}}", subs_html)

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)
    return html

@app.route("/")
def dashboard():
    data = load_report()
    if not data:
        return "<h2>No report found. Run scanner first: python3 scanner.py &lt;target&gt;</h2>"

    info = data.get("scan_info", {})
    findings = data.get("findings", {})
    vulns = findings.get("vulnerabilities", [])
    tech = findings.get("technology", {})

    all_display_issues = list(vulns)
    for issue in findings.get("auth_issues", []):
        all_display_issues.append({
            "severity": issue.get("severity", "INFO"),
            "type": issue.get("type", "Auth Issue"),
            "url": issue.get("detail", "N/A"),
            "param": "-", "method": "-",
            "sev_class": issue.get("severity", "INFO").lower().replace("critical", "crit").replace("medium", "med")
        })
    for issue in findings.get("api_issues", []):
        all_display_issues.append({
            "severity": issue.get("severity", "INFO"),
            "type": issue.get("type", "API Issue"),
            "url": issue.get("detail", "N/A"),
            "param": "-", "method": "-",
            "sev_class": issue.get("severity", "INFO").lower().replace("critical", "crit").replace("medium", "med")
        })
    for issue in findings.get("cloud_issues", []):
        all_display_issues.append({
            "severity": issue.get("severity", "INFO"),
            "type": issue.get("type", "Cloud Issue"),
            "url": issue.get("detail", "N/A"),
            "param": "-", "method": "-",
            "sev_class": issue.get("severity", "INFO").lower().replace("critical", "crit").replace("medium", "med")
        })
    for issue in findings.get("wp_issues", []):
        all_display_issues.append({
            "severity": issue.get("severity", "INFO"),
            "type": issue.get("type", "WordPress Issue"),
            "url": issue.get("url", "N/A"),
            "param": "-", "method": "-",
            "sev_class": issue.get("severity", "INFO").lower().replace("critical", "crit").replace("medium", "med")
        })

    processed_vulns = []
    for v in all_display_issues:
        sev = v.get("severity", "INFO")
        v["sev_class"] = sev.lower().replace("critical", "crit").replace("medium", "med")
        processed_vulns.append(v)

    critical_count = sum(1 for v in all_display_issues if v["severity"] in ["CRITICAL", "HIGH"])
    medium_count = sum(1 for v in all_display_issues if v["severity"] == "MEDIUM")
    low_count = sum(1 for v in all_display_issues if v["severity"] in ["LOW", "INFO"])

    return render_template_string(DASHBOARD_HTML,
        target=info.get("target", "Unknown"),
        endpoints=findings.get("endpoints_count", 0),
        ports=len(findings.get("ports", [])),
        critical=critical_count,
        medium=medium_count,
        low=low_count,
        vulns=processed_vulns,
        tech_server=tech.get("server", "Unknown"),
        tech_list=", ".join(tech.get("technologies", [])) or "None"
    )

@app.route("/report")
def report():
    data = load_report()
    if not data:
        return "<h2>No report found. Run scanner first: python3 scanner.py &lt;target&gt;</h2>"
    html = generate_html_report(data)
    return html

@app.route("/api/data")
def api_data():
    data = load_report()
    if data:
        return jsonify(data)
    return jsonify({"error": "No report found"})

if __name__ == "__main__":
    print("[*] Starting AppShield 360 Dashboard...")
    print("[*] Open http://localhost:5000 in your browser")
    app.run(host="0.0.0.0", port=5000, debug=False)