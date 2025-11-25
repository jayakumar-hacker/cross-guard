#!/usr/bin/env python3
"""
runner_windows.py

Executes Windows hardening rules defined in windows_rules.yml.
Coordinates:
    - Loading rules
    - PowerShell checks
    - Running fixes via fix_windows.ps1
    - Writing results.json for SIH evaluation

Logs and results:
    C:\SysHardener\logs\runner.log
    C:\SysHardener\logs\results.json
"""

import yaml
import subprocess
import json
import os
from datetime import datetime

RULE_FILE = "windows_rules.yml"
FIX_SCRIPT = "fix_windows.ps1"

LOG_DIR = r"C:\SysHardener\logs"
LOG_FILE = os.path.join(LOG_DIR, "runner.log")
RESULT_FILE = os.path.join(LOG_DIR, "results.json")

os.makedirs(LOG_DIR, exist_ok=True)


# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------
def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts}  {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


# ----------------------------------------------------------------------
# PowerShell Execution
# ----------------------------------------------------------------------
def run_powershell(command):
    """Run a PowerShell command and capture output."""
    cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", command]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        stdout = result.stdout.strip()
        return stdout, result.returncode
    except Exception as e:
        return str(e), 1


# ----------------------------------------------------------------------
# Check execution
# ----------------------------------------------------------------------
def execute_check(rule):
    check = rule.get("check", {})
    cmd = check.get("cmd")
    expected = str(check.get("expect", "")).strip()

    log(f"[{rule['id']}] Running check: {cmd}")

    output, code = run_powershell(cmd)

    if code != 0:
        log(f"[{rule['id']}] Check failed: {output}")
        return False, output

    is_pass = (output.strip() == expected)
    return is_pass, output


# ----------------------------------------------------------------------
# Fix execution
# ----------------------------------------------------------------------
def apply_fix(rule):
    fix = rule.get("fix", {})
    script_body = fix.get("script", "")

    log(f"[{rule['id']}] Applying fix...")

    # Create PowerShell call
    cmd = [
        "powershell.exe",
        "-ExecutionPolicy", "Bypass",
        "-File", FIX_SCRIPT,
        "-RuleId", rule["id"],
        "-Script", script_body
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        stdout = result.stdout.strip()
        if result.returncode == 0:
            log(f"[{rule['id']}] Fix applied successfully.")
            return True, stdout
        else:
            log(f"[{rule['id']}] Fix FAILED: {stdout}")
            return False, stdout
    except Exception as e:
        log(f"[{rule['id']}] Fix error: {e}")
        return False, str(e)


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    log("------------------------------------------------------------")
    log("Windows Hardening Runner Started")

    with open(RULE_FILE, "r") as f:
        yaml_data = yaml.safe_load(f)

    rules = yaml_data.get("rules", [])
    results = []

    for rule in rules:
        rid = rule["id"]
        title = rule["title"]

        log(f"[{rid}] Checking rule: {title}")

        passed, output = execute_check(rule)

        if passed:
            results.append({
                "id": rid,
                "title": title,
                "status": "PASS",
                "details": output
            })
            log(f"[{rid}] PASS")
        else:
            log(f"[{rid}] FAIL → Fix required")

            fixed, fix_output = apply_fix(rule)

            results.append({
                "id": rid,
                "title": title,
                "status": "FIXED" if fixed else "FAILED",
                "details": fix_output
            })

    # Save results
    with open(RESULT_FILE, "w") as f:
        json.dump(results, f, indent=4)

    log(f"Results saved to {RESULT_FILE}")
    log("Windows Hardening Runner Completed")
    log("------------------------------------------------------------")


if __name__ == "__main__":
    main()
