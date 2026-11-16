#!/usr/bin/env python3
"""
LocalAudit - Local Security Misconfiguration Auditor
Category: Auditing
Checks common security misconfigurations on the local system.
"""

import argparse
import json
import os
import signal
import stat
import sys
import socket
from datetime import datetime
from pathlib import Path

# Global kill switch
KILL_SWITCH = False

def signal_handler(sig, frame):
    """Clean abort on Ctrl+C."""
    global KILL_SWITCH
    print("\n[!] Kill switch activated. Aborting cleanly...")
    KILL_SWITCH = True
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

DISCLAIMER = """
================================================================================
LEGAL DISCLAIMER - COMPUTER CRIMES ACT 1997 (MALAYSIA)
================================================================================
This tool is intended for educational and authorized ethical auditing purposes only.
Unauthorized access or modification of systems is a criminal offence under the
Computer Crimes Act 1997 (Act 563), including Section 3 (Unauthorised Access).

This tool only inspects the local system by default. You must have explicit
authorization before using it on any system. By continuing, you confirm that you
have proper authorization and will not misuse this tool.

The authors accept no liability for misuse.
================================================================================
"""

def display_disclaimer():
    """Show disclaimer and require confirmation."""
    print(DISCLAIMER)
    confirm = input("Do you have explicit authorization to audit this system? (yes/no): ").strip().lower()
    if confirm not in ("yes", "y"):
        print("[!] Authorization not confirmed. Exiting.")
        sys.exit(1)
    print("[+] Authorization confirmed. Starting local audit only.\n")

def check_file_permissions(path, max_mode=0o644):
    """Check if a file has overly permissive permissions."""
    if KILL_SWITCH or not os.path.exists(path):
        return None
    try:
        mode = os.stat(path).st_mode
        perms = stat.S_IMODE(mode)
        is_world_writable = bool(perms & stat.S_IWOTH)
        is_group_writable = bool(perms & stat.S_IWGRP)
        issue = None
        if is_world_writable:
            issue = "world-writable"
        elif is_group_writable and perms > max_mode:
            issue = "group-writable and overly permissive"
        return {
            "path": path,
            "permissions": oct(perms),
            "issue": issue,
            "severity": "High" if is_world_writable else "Medium" if issue else "OK"
        }
    except PermissionError:
        return {"path": path, "permissions": "N/A", "issue": "Permission denied", "severity": "Info"}

def check_sensitive_files():
    """Audit permissions on common sensitive files."""
    sensitive = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/root/.ssh/authorized_keys"
    ]
    results = []
    print("[*] Checking sensitive file permissions...")
    for path in sensitive:
        if KILL_SWITCH:
            break
        result = check_file_permissions(path, max_mode=0o640 if "shadow" in path or "sudoers" in path else 0o644)
        if result:
            results.append(result)
            status = result["severity"]
            print(f"  [{status}] {path}: {result['permissions']} {result['issue'] or ''}")
    return results

def check_world_writable_dirs(base_dirs=None):
    """Find world-writable directories under common paths (limited depth)."""
    if base_dirs is None:
        base_dirs = ["/tmp", "/var/tmp", "/home"]
    findings = []
    print("[*] Scanning for world-writable directories (limited scope)...")
    for base in base_dirs:
        if KILL_SWITCH or not os.path.exists(base):
            continue
        try:
            for root, dirs, files in os.walk(base, topdown=True):
                if KILL_SWITCH:
                    break
                # Limit depth for performance
                depth = root[len(base):].count(os.sep)
                if depth > 2:
                    dirs[:] = []
                    continue
                for d in dirs[:]:
                    full = os.path.join(root, d)
                    try:
                        mode = os.stat(full).st_mode
                        if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:  # world-writable and no sticky bit
                            findings.append({
                                "path": full,
                                "issue": "world-writable directory without sticky bit",
                                "severity": "Medium"
                            })
                            print(f"  [Medium] {full}")
                    except (PermissionError, OSError):
                        continue
        except PermissionError:
            continue
    return findings

def check_open_ports(ports=None):
    """Check if common ports are listening locally."""
    if ports is None:
        ports = [22, 80, 443, 3306, 5432, 6379, 27017]
    open_ports = []
    print("[*] Checking common listening ports (localhost only)...")
    for port in ports:
        if KILL_SWITCH:
            break
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex(("127.0.0.1", port))
        sock.close()
        if result == 0:
            open_ports.append({"port": port, "status": "open", "severity": "Info"})
            print(f"  [Info] Port {port} is open on localhost")
    return open_ports

def check_umask():
    """Check current umask."""
    try:
        current = os.umask(0)
        os.umask(current)  # restore
        recommended = 0o022
        issue = None if current <= recommended else "umask is less restrictive than recommended"
        return {
            "umask": oct(current),
            "recommended": oct(recommended),
            "issue": issue,
            "severity": "Low" if issue else "OK"
        }
    except Exception:
        return None

def run_audit():
    """Run all local audit checks."""
    findings = {
        "sensitive_files": check_sensitive_files(),
        "world_writable": check_world_writable_dirs(),
        "open_ports": check_open_ports(),
        "umask": check_umask()
    }
    return findings

def save_results(findings, output_dir="output"):
    """Save audit results locally."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"audit_report_{timestamp}.json")
    report = {
        "timestamp": datetime.now().isoformat(),
        "hostname": socket.gethostname(),
        "findings": findings
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Audit results saved to {filename}")
    return filename

def main():
    parser = argparse.ArgumentParser(
        description="LocalAudit - Local Security Misconfiguration Auditor (Auditing Category)",
        epilog="Only audits the local system. Safe defaults. Educational use only."
    )
    parser.add_argument("-o", "--output", default="output",
                        help="Output directory (default: output)")
    parser.add_argument("--skip-writable", action="store_true",
                        help="Skip world-writable directory scan")
    args = parser.parse_args()

    display_disclaimer()

    print("[*] Starting local security audit (localhost only)...")
    findings = run_audit()

    # Summary
    total_issues = sum(
        1 for cat in findings.values()
        if isinstance(cat, list)
        for item in cat
        if isinstance(item, dict) and item.get("severity") in ("High", "Medium")
    )
    print(f"\n[*] Audit complete. Potential issues found: {total_issues}")

    save_results(findings, args.output)
    print("[!] Review findings locally. Do not use on unauthorized systems.")

if __name__ == "__main__":
    main()
