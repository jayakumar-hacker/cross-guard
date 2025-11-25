#!/usr/bin/env python3
"""
reporter.py

Reads:
    /var/log/sys_hardener/results.json   (Linux)
    C:\SysHardener\logs\results.json     (Windows)

Generates:
    report.json
    report.csv
    report.html

Works for SIH 2025 scoring + demo presentation.
"""

import json
import csv
import os
from datetime import datetime

# Auto-detect platform
if os.name == "nt":  # Windows
    RESULT_PATH = r"C:\SysHardener\logs\results.json"
    OUT_DIR = r"C:\SysHardener\reports"
else:  # Linux
    RESULT_PATH = "/var/log/sys_hardener/results.json"
    OUT_DIR = "/var/log/sys_hardener/reports"

os.makedirs(OUT_DIR, exist_ok=True)


# -----------------------------------------------------------
# Load results file
# -----------------------------------------------------------
def load_results():
    if not os.path.exists(RESULT_PATH):
        raise FileNotFoundError(f"Result file not found: {RESULT_PATH}")

    with open(RESULT_PATH, "r") as f:
        return json.load(f)


# -----------------------------------------------------------
# Save clean JSON report
# -----------------------------------------------------------
def save_json(results):
    out_json = os.path.join(OUT_DIR, "report.json")
    with open(out_json, "w") as f:
        json.dump(results, f, indent=4)
    return out_json


# -----------------------------------------------------------
# Save CSV report
# -----------------------------------------------------------
def save_csv(results):
    out_csv = os.path.join(OUT_DIR, "report.csv")
    with open(out_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Rule ID", "Title", "Status", "Details"])
        for r in results:
            writer.writerow([r["id"], r["title"], r["status"], r["details"]])
    return out_csv


# -----------------------------------------------------------
# Generate HTML report (SIH-ready)
# -----------------------------------------------------------
def save_html(results, score):
    out_html = os.path.join(OUT_DIR, "report.html")

    passed = sum(1 for r in results if r["status"] == "PASS")
    fixed = sum(1 for r in results if r["status"] == "FIXED")
    failed = sum(1 for r in results if r["status"] == "FAILED")

    html = f"""
<html>
<head>
    <title>System Hardening Report</title>
    <style>
        body {{ font-family: Arial; margin: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; border: 1px solid #ccc; }}
        th {{ background: #eee; }}
        .pass {{ color: green; font-weight: bold; }}
        .fixed {{ color: orange; font-weight: bold; }}
        .fail {{ color: red; font-weight: bold; }}
    </style>
</head>
<body>
<h2>Cross-Platform System Hardening Report</h2>
<p><b>Generated:</b> {datetime.now()}</p>

<h3>Summary</h3>
<ul>
    <li><b>Total Rules:</b> {len(results)}</li>
    <li><b>Pass:</b> {passed}</li>
    <li><b>Fixed:</b> {fixed}</li>
    <li><b>Failed:</b> {failed}</li>
    <li><b>Security Score:</b> {score}%</li>
</ul>

<table>
<tr>
    <th>Rule ID</th>
    <th>Title</th>
    <th>Status</th>
    <th>Details</th>
</tr>
"""

    for r in results:
        status_class = "pass" if r["status"] == "PASS" \
            else "fixed" if r["status"] == "FIXED" \
            else "fail"

        html += f"""
<tr>
    <td>{r["id"]}</td>
    <td>{r["title"]}</td>
    <td class="{status_class}">{r["status"]}</td>
    <td>{r["details"]}</td>
</tr>
"""

    html += """
</table>
</body>
</html>
"""

    with open(out_html, "w") as f:
        f.write(html)

    return out_html


# -----------------------------------------------------------
# Score calculation
# -----------------------------------------------------------
def calculate_score(results):
    total = len(results)
    if total == 0:
        return 0

    secure = sum(1 for r in results if r["status"] in ("PASS", "FIXED"))
    score = round((secure / total) * 100, 2)
    return score


# -----------------------------------------------------------
# Main
# -----------------------------------------------------------
def main():
    print("Generating security report...")

    results = load_results()
    score = calculate_score(results)

    json_path = save_json(results)
    csv_path = save_csv(results)
    html_path = save_html(results, score)

    print("Report generated successfully:")
    print(" - JSON:", json_path)
    print(" - CSV :", csv_path)
    print(" - HTML:", html_path)
    print(" - Score:", score, "%")


if __name__ == "__main__":
    main()
