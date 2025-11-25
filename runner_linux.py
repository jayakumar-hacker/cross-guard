#!/usr/bin/env python3
"""
runner_linux.py

Executes Linux hardening rules defined in linux_rules.yml.
Coordinates:
    - Loading rules
    - Running checks
    - Executing fixes through fix_linux.sh
    - Producing scan result JSON

Logs and results go to:
    /var/log/sys_hardener/runner.log
    /var/log/sys_hardener/results.json
"""

import yaml
import subprocess
import json
import os
from datetime import datetime

RULE_FILE = "linux_rules.yml"
FIX_SCRIPT = "./fix_linux.sh"

LOG_DIR = "/var/log/sys_hardener"
LOG_FILE = f"{LOG_DIR}/runner.log"
RESULT_FILE = f"{LOG_DIR}/results.json"

os.makedirs(LOG_DIR, exist_ok=True)


# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{ts}  {msg}"
    print(entry)
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\n")


# -----------------------------------------------------------------------------
# Command execution
# -----------------------------------------------------------------------------
def run_command(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, text=True, capture_output=True
        )
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), 1


# -----------------------------------------------------------------------------
# Check rule
# -----------------------------------------------------------------------------
def execute_check(rule):
    check = rule.get("check", {})
    cmd = check.get("cmd")
    expected = check.get("expect", "").strip()

    log(f"[{rule['id']}] Running check: {cmd}")

    output, code = run_command(cmd)

    if code != 0:
        log(f"[{rule['id']}] Check command failed: {output}")
        return False, output

    is_pass = (output.strip() == expected)
    return is_pass, output


# -----------------------------------------------------------------------------
# Apply fix
# -----------------------------------------------------------------------------
def apply_fix(rule):
    fix = rule.get("fix", {})
    script_content = fix.get("script", "")

    log(f"[{rule['id']}] Applying fix...")

    cmd = f'{FIX_SCRIPT} "{rule["id"]}" "{script_content}"'
    output, code = run_command(cmd)

    if code == 0:
        log(f"[{rule['id']}] Fix applied successfully.")
        return True, output

    log(f"[{rule['id']}] Fix FAILED.")
    return False, output


# -----------------------------------------------------------------------------
# Main execution
# -----------------------------------------------------------------------------
def main():
    log("------------------------------------------------------------")
    log("Linux Hardening Runner Started")

    with open(RULE_FILE, "r") as f:
        data = yaml.safe_load(f)

    rules = data.get("rules", [])
    results = []

    for rule in rules:
        rid = rule["id"]
        title = rule["title"]

        log(f"[{rid}] Checking rule: {title}")

        passed, out = execute_check(rule)

        # If check passed -> nothing to fix
        if passed:
            results.append({
                "id": rid,
                "title": title,
                "status": "PASS",
                "details": out
            })
            log(f"[{rid}] PASS")
        else:
            log(f"[{rid}] FAIL  → Fixing...")

            fixed, fix_out = apply_fix(rule)

            results.append({
                "id": rid,
                "title": title,
                "status": "FIXED" if fixed else "FAILED",
                "details": fix_out
            })

    # Save results
    with open(RESULT_FILE, "w") as f:
        json.dump(results, f, indent=4)

    log(f"Scan results written to {RESULT_FILE}")
    log("Linux Hardening Runner Completed")
    log("------------------------------------------------------------")


if __name__ == "__main__":
    main()
