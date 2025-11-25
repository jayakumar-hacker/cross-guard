#!/usr/bin/env python3
"""
Engine - Cross-Guard
Loads YAML rule packs and executes checks and fixes on Linux/Windows.

Usage (examples):
  # Audit only (no fixes)
  python3 src/engine.py --rules ../rules --mode audit --out ../reports

  # Apply fixes (requires sudo on Linux / Admin on Windows)
  python3 src/engine.py --rules ../rules --mode apply --out ../reports

Notes:
- YAML structure expected: top-level key "rules", each rule contains:
  id, title, platform (linux/windows), severity, check{type,cmd/file,regex,expect}, fix{type,script}
- fix.type values: "bash", "powershell", "inline", "script" (script is path to executable)
- check.type values: "command", "powershell", "file_contains"
"""

import argparse
import os
import sys
import yaml
import subprocess
import platform
import json
from datetime import datetime

# -------------------------
# Utilities
# -------------------------

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def is_windows():
    return platform.system().lower().startswith("win")

def is_linux():
    return platform.system().lower().startswith("linux")

def find_executable(names):
    """Return first found executable from names list or None."""
    from shutil import which
    for n in names:
        path = which(n)
        if path:
            return path
    return None

# Preferred shells
BASH = find_executable(["bash", "sh"])
PWSH = find_executable(["pwsh", "powershell"])

# subprocess helper
def run_command(cmd, shell=True, capture_output=True, timeout=120):
    """
    Run a shell command. Returns tuple (rc, stdout, stderr).
    - cmd: string or list (if shell=False)
    """
    try:
        if shell:
            p = subprocess.run(cmd, shell=True, check=False,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        else:
            p = subprocess.run(cmd, shell=False, check=False,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        out = p.stdout.strip() if p.stdout else ""
        err = p.stderr.strip() if p.stderr else ""
        return p.returncode, out, err
    except subprocess.TimeoutExpired as e:
        return 124, "", f"TimeoutExpired: {str(e)}"
    except Exception as e:
        return 1, "", f"Exception: {str(e)}"

# -------------------------
# Rule loader
# -------------------------

def load_rules_from_path(rules_root):
    """
    Walk rules_root and load YAML files. Supports files with top-level 'rules' list
    or plain list in the file.
    Returns list of rule dicts.
    """
    rules = []
    for root, dirs, files in os.walk(rules_root):
        for f in files:
            if not (f.endswith(".yml") or f.endswith(".yaml")):
                continue
            path = os.path.join(root, f)
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
                    if not doc:
                        continue
                    # flexibility: accept {rules: [...]} or direct list
                    if isinstance(doc, dict) and "rules" in doc and isinstance(doc["rules"], list):
                        rules.extend(doc["rules"])
                    elif isinstance(doc, list):
                        rules.extend(doc)
                    else:
                        # single rule object
                        rules.append(doc)
            except Exception as e:
                print(f"[WARN] Failed to load {path}: {e}", file=sys.stderr)
    return rules

# -------------------------
# Check executors
# -------------------------

def exec_check_command(cmd, platform_hint=None):
    """
    Execute check command string depending on platform_hint (linux/windows) or runtime.
    Returns (rc, stdout, stderr)
    """
    if is_windows() or platform_hint == "windows":
        # prefer pwsh/powershell for reliable PowerShell execution
        if PWSH:
            # Use pwsh -Command "..."
            wrapped = f'{PWSH} -NoProfile -NonInteractive -Command "{cmd}"'
            return run_command(wrapped)
        else:
            # fallback to cmd shell execution (may not handle PS well)
            return run_command(cmd)
    else:
        # linux/mac -> use bash
        if BASH:
            wrapped = f'{BASH} -c "{cmd}"'
            return run_command(wrapped)
        else:
            return run_command(cmd)

def check_file_contains(path, regex):
    """
    Check if a file contains a regex (simple substring or regex).
    Returns (found_bool, output_text)
    """
    if not os.path.exists(path):
        return False, f"file-missing: {path}"
    try:
        # use grep if available for robust regex support
        if BASH:
            cmd = f'grep -E "{regex}" "{path}" || true'
            rc, out, err = run_command(f'{BASH} -c "{cmd}"')
            found = bool(out.strip())
            return found, out or ""
        else:
            # python approach
            import re
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
            m = re.search(regex, text, re.MULTILINE)
            return bool(m), (m.group(0) if m else "")
    except Exception as e:
        return False, f"ex:{e}"

# -------------------------
# Fix executors
# -------------------------

def apply_fix_inline(cmd, platform_hint=None):
    """Run an inline command appropriate to the platform."""
    return exec_check_command(cmd, platform_hint=platform_hint)

def apply_fix_script(script_path):
    """
    Execute a script file. Accepts absolute or relative path.
    Determine interpreter from file extension (.sh -> bash, .ps1 -> pwsh/powershell).
    """
    if not os.path.exists(script_path):
        return 1, "", f"script-not-found: {script_path}"
    _, ext = os.path.splitext(script_path.lower())
    # absolute path safety: use sh -c or pwsh -Command & '{path}'
    if ext in (".sh",):
        if BASH:
            return run_command(f'{BASH} "{script_path}"')
        else:
            return run_command(f'sh "{script_path}"')
    elif ext in (".ps1",):
        if PWSH:
            # PowerShell script execution policy note: expects to be run as admin on Windows
            return run_command(f'{PWSH} -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script_path}"')
        else:
            # fallback - try powershell if present in PATH
            return run_command(f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script_path}"')
    else:
        # try to execute directly
        try:
            return run_command(f'"{script_path}"')
        except Exception as e:
            return 1, "", f"cannot-exec-script: {e}"

# -------------------------
# Engine core
# -------------------------

class RuleResult:
    def __init__(self, rule):
        self.rule = rule
        self.id = rule.get("id", "NOID")
        self.title = rule.get("title", "")
        self.severity = rule.get("severity", "low")
        self.platform = rule.get("platform", "").lower()
        self.status = "UNKNOWN"   # PASS / FAIL / NO_CHECK / ERROR
        self.check_output = ""
        self.fix_applied = False
        self.fix_output = ""
        self.timestamp = now_iso()

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "platform": self.platform,
            "status": self.status,
            "check_output": self.check_output,
            "fix_applied": self.fix_applied,
            "fix_output": self.fix_output,
            "timestamp": self.timestamp
        }

class Engine:
    def __init__(self, rules_root, out_dir=None, dry_run=True, verbose=False):
        self.rules_root = os.path.abspath(rules_root)
        self.out_dir = os.path.abspath(out_dir) if out_dir else os.path.abspath("./reports")
        os.makedirs(self.out_dir, exist_ok=True)
        self.dry_run = dry_run
        self.verbose = verbose
        self.rules = load_rules_from_path(self.rules_root)

    def applicable(self, rule):
        plat = rule.get("platform", "").lower()
        if not plat:
            return True
        if is_linux() and plat == "linux":
            return True
        if is_windows() and plat == "windows":
            return True
        return False

    def run_single_check(self, rule):
        """
        Run 'check' part of a rule. Supports:
          - check.type == command (cmd string)
          - check.type == powershell (powershell cmd)
          - check.type == file_contains (file + regex)
        """
        rr = RuleResult(rule)
        check = rule.get("check")
        if not check:
            rr.status = "NO_CHECK"
            rr.check_output = "no-check-block"
            return rr

        ctype = check.get("type", "command")
        try:
            if ctype == "command":
                cmd = check.get("cmd", "")
                if not cmd:
                    rr.status = "NO_CHECK"
                    rr.check_output = "empty-cmd"
                    return rr
                rc, out, err = exec_check_command(cmd, platform_hint=rule.get("platform"))
                rr.check_output = (out or "") + ("\nERR:" + err if err else "")
                expected = check.get("expect", "").strip()
                # If expect is empty -> expect no output
                if expected == "":
                    rr.status = "PASS" if (out is None or out.strip() == "") else "FAIL"
                else:
                    rr.status = "PASS" if (expected in out) else "FAIL"
                return rr

            elif ctype == "powershell":
                # force pwsh usage when available
                cmd = check.get("cmd", "")
                if not cmd:
                    rr.status = "NO_CHECK"
                    rr.check_output = "empty-ps-cmd"
                    return rr
                # if runtime is linux but checking windows rules (unlikely) exec with pwsh if available
                rc, out, err = exec_check_command(cmd, platform_hint=rule.get("platform"))
                rr.check_output = (out or "") + ("\nERR:" + err if err else "")
                expected = check.get("expect", "").strip()
                rr.status = "PASS" if (expected in out) else "FAIL"
                return rr

            elif ctype == "file_contains":
                filepath = check.get("file")
                regex = check.get("regex", "")
                found, out = check_file_contains(filepath, regex)
                rr.check_output = out
                rr.status = "PASS" if found else "FAIL"
                return rr

            else:
                rr.status = "UNKNOWN_CHECK_TYPE"
                rr.check_output = f"unsupported-check-type: {ctype}"
                return rr

        except Exception as e:
            rr.status = "ERROR"
            rr.check_output = f"exception: {e}"
            return rr

    def apply_fix_for_rule(self, rule):
        """
        Handle fix block. fix.type = bash|powershell|inline|script
        For inline/bach/powershell the content might be:
         - fix.script -> multiline script (execute with appropriate interpreter)
         - fix.cmd -> single-line command
         - fix (string) -> path to script if fix_type == script
        """
        fix = rule.get("fix")
        if not fix:
            return 1, "", "no-fix-block"

        ftype = fix.get("type", "inline")
        # script content vs script path
        script_content = fix.get("script")
        script_path = fix.get("script_path") or fix.get("path") or fix.get("file") or fix.get("script_file")
        # If rule uses 'fix' directly as string (compat)
        if not script_content and not script_path and isinstance(fix, str):
            script_path = fix

        if ftype in ("bash", "powershell"):
            # write temporary script and execute with interpreter
            if not script_content:
                return 1, "", "empty-fix-script"
            # create temp file
            import tempfile, stat
            suffix = ".sh" if ftype == "bash" else ".ps1"
            fd, tmp = tempfile.mkstemp(suffix=suffix, prefix="cg_fix_")
            os.close(fd)
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(script_content)
            try:
                # make executable for bash
                if ftype == "bash" and is_linux():
                    os.chmod(tmp, stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)
                    rc, out, err = apply_fix_script(tmp)
                elif ftype == "powershell":
                    rc, out, err = apply_fix_script(tmp)
                else:
                    # cross-platform attempt
                    rc, out, err = apply_fix_script(tmp)
            finally:
                try:
                    os.remove(tmp)
                except:
                    pass
            return rc, out, err

        elif ftype == "inline":
            # single-line inline command
            cmd = fix.get("script") or fix.get("cmd") or fix.get("command") or ""
            if not cmd:
                return 1, "", "empty-inline-cmd"
            return apply_fix_inline(cmd, platform_hint=rule.get("platform"))

        elif ftype == "script":
            # path to script relative to repo or absolute
            path = script_path
            if not path:
                return 1, "", "missing-script-path"
            # allow relative paths from rules_root
            if not os.path.isabs(path):
                # try relative to rules root, then current working dir
                candidate = os.path.join(self.rules_root, path)
                if os.path.exists(candidate):
                    path = candidate
            return apply_fix_script(path)

        else:
            return 1, "", f"unsupported-fix-type:{ftype}"

    def audit(self):
        results = []
        for rule in self.rules:
            if not self.applicable(rule):
                continue
            rr = self.run_single_check(rule)
            results.append(rr)
            if self.verbose:
                print(f"[AUDIT] {rr.id} {rr.title} -> {rr.status}")
        return results

    def apply(self):
        results = []
        for rule in self.rules:
            if not self.applicable(rule):
                continue
            rr = self.run_single_check(rule)
            if rr.status == "FAIL":
                if self.dry_run:
                    rr.fix_output = "dry-run: not applied"
                    rr.fix_applied = False
                else:
                    rc, out, err = self.apply_fix_for_rule(rule)
                    rr.fix_output = (out or "") + ("\nERR:" + err if err else "")
                    rr.fix_applied = (rc == 0)
                    # re-check after attempted fix
                    rr2 = self.run_single_check(rule)
                    rr.status = rr2.status
            results.append(rr)
            if self.verbose:
                print(f"[APPLY] {rr.id} {rr.title} -> {rr.status} fix_applied={rr.fix_applied}")
        return results

    def save_reports(self, results, outname_prefix="crossguard"):
        # JSON report
        json_path = os.path.join(self.out_dir, f"{outname_prefix}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")
        arr = [r.to_dict() for r in results]
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump({"generated": now_iso(), "results": arr}, fh, indent=2)
        # simple HTML
        try:
            html_path = os.path.join(self.out_dir, f"{outname_prefix}.html")
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write("<html><head><meta charset='utf-8'><title>Cross-Guard Report</title></head><body>")
                fh.write(f"<h1>Cross-Guard Report</h1><p>Generated: {now_iso()}</p>")
                fh.write("<table border='1' cellpadding='6'><tr><th>ID</th><th>Title</th><th>Status</th><th>Severity</th><th>Fix Applied</th><th>Details</th></tr>")
                for r in results:
                    fh.write("<tr>")
                    fh.write(f"<td>{r.id}</td>")
                    fh.write(f"<td>{r.title}</td>")
                    fh.write(f"<td>{r.status}</td>")
                    fh.write(f"<td>{r.severity}</td>")
                    fh.write(f"<td>{'Yes' if r.fix_applied else 'No'}</td>")
                    details = (r.check_output or "") + "\n" + (r.fix_output or "")
                    fh.write(f"<td><pre>{details}</pre></td>")
                    fh.write("</tr>")
                fh.write("</table></body></html>")
        except Exception as e:
            print(f"[WARN] failed to write html report: {e}", file=sys.stderr)

        return json_path, html_path

# -------------------------
# CLI
# -------------------------

def parse_args():
    ap = argparse.ArgumentParser(prog="engine.py")
    ap.add_argument("--rules", "-r", required=True, help="Path to rules folder (contains YAML files)")
    ap.add_argument("--mode", "-m", choices=["audit", "apply"], default="audit", help="audit=check only, apply=apply fixes")
    ap.add_argument("--out", "-o", default="./reports", help="Output reports directory")
    ap.add_argument("--dry", action="store_true", help="Dry run when applying fixes (no changes will be made)")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return ap.parse_args()

def main():
    args = parse_args()
    dry = args.dry or (args.mode == "audit")
    eng = Engine(rules_root=args.rules, out_dir=args.out, dry_run=dry, verbose=args.verbose)
    print(f"[INFO] Loaded {len(eng.rules)} rules from {eng.rules_root}")
    if args.mode == "audit":
        results = eng.audit()
    else:
        # apply mode
        if is_linux() and os.geteuid() != 0 and not args.dry:
            print("[ERROR] apply mode on Linux requires root privileges (sudo). Use --dry to simulate.", file=sys.stderr)
            sys.exit(2)
        if is_windows() and not args.dry:
            # best-effort admin detection on Windows: try to create folder in systemroot - may fail on some configs
            # skip strict enforcement to avoid false negatives in varied environments
            pass
        results = eng.apply()
    json_path, html_path = eng.save_reports(results)
    print(f"[INFO] Reports: {json_path}, {html_path}")
    # Print short summary
    pass_count = sum(1 for r in results if r.status == "PASS")
    fail_count = sum(1 for r in results if r.status == "FAIL")
    print(f"[SUMMARY] PASS={pass_count} FAIL={fail_count} TOTAL={len(results)}")

if __name__ == "__main__":
    main()
