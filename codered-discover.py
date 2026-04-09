#!/usr/bin/env python3
"""
CodeRed Server Agent — Log Discovery Engine
Cross-platform: Windows + Linux
Scans the endpoint for log files/event channels, scores by security relevance,
and lets the customer pick which ones to monitor.
"""

import os
import sys
import json
import subprocess
import glob
import shutil
from pathlib import Path

IS_WIN = sys.platform == "win32"

# ── Paths (cross-platform) ────────────────────────────────────────────────────
if IS_WIN:
    _base      = os.path.dirname(os.path.abspath(__file__))
    AGENT_CONF = r"C:\Program Files (x86)\ossec-agent\ossec.conf"
    STATE_FILE = os.path.join(_base, "state.json")
else:
    AGENT_CONF = "/var/ossec/etc/ossec.conf"
    STATE_FILE = "/etc/codered/state.json"

# ── Colours ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── Priority helpers ──────────────────────────────────────────────────────────
PRIORITY_ORDER  = {"high": 0, "medium": 1, "low": 2}
PRIORITY_LABELS = {
    "high"  : f"{RED}🔴 HIGH PRIORITY{RESET}",
    "medium": f"{YELLOW}🟡 MEDIUM PRIORITY{RESET}",
    "low"   : f"{DIM}🟢 LOW PRIORITY{RESET}",
}
PRIORITY_DEFAULT = {"high": True, "medium": True, "low": False}

# ── Log catalogue — LINUX ─────────────────────────────────────────────────────
LINUX_CATALOGUE = [
    # System / Auth
    {"path": "/var/log/auth.log",       "label": "Authentication Log",        "service": "ssh/sudo/pam", "priority": "high",   "format": "syslog",    "reason": "SSH logins, sudo usage, PAM auth failures"},
    {"path": "/var/log/secure",         "label": "Secure Log (RHEL/CentOS)",  "service": "ssh/sudo/pam", "priority": "high",   "format": "syslog",    "reason": "SSH logins, sudo usage on RHEL/CentOS"},
    {"path": "/var/log/syslog",         "label": "System Log",                "service": "system",       "priority": "high",   "format": "syslog",    "reason": "General system events, daemon start/stop"},
    {"path": "/var/log/messages",       "label": "System Messages (RHEL)",    "service": "system",       "priority": "high",   "format": "syslog",    "reason": "General system messages on RHEL/CentOS"},
    {"path": "/var/log/kern.log",       "label": "Kernel Log",                "service": "kernel",       "priority": "high",   "format": "syslog",    "reason": "Kernel events, OOM killer, hardware errors"},
    {"path": "/var/log/audit/audit.log","label": "Linux Audit Log",           "service": "auditd",       "priority": "high",   "format": "audit",     "reason": "Kernel-level syscall auditing, privilege escalation"},
    # Firewall
    {"path": "/var/log/ufw.log",        "label": "UFW Firewall Log",          "service": "ufw",          "priority": "high",   "format": "syslog",    "reason": "Firewall block/allow events, port scans"},
    {"path": "/var/log/iptables.log",   "label": "iptables Log",              "service": "iptables",     "priority": "high",   "format": "syslog",    "reason": "Raw iptables packet drop/accept events"},
    {"path": "/var/log/firewalld",      "label": "FirewallD Log",             "service": "firewalld",    "priority": "high",   "format": "syslog",    "reason": "Firewall events on RHEL/CentOS"},
    # Intrusion
    {"path": "/var/log/fail2ban.log",   "label": "Fail2ban Log",              "service": "fail2ban",     "priority": "medium", "format": "syslog",    "reason": "Banned IPs and brute-force detection"},
    # Web
    {"path": "/var/log/apache2/access.log", "label": "Apache Access Log",     "service": "apache2",     "priority": "medium", "format": "apache",    "reason": "HTTP requests — detect web attacks, scanning"},
    {"path": "/var/log/apache2/error.log",  "label": "Apache Error Log",      "service": "apache2",     "priority": "medium", "format": "apache",    "reason": "Apache errors — misconfigurations and attacks"},
    {"path": "/var/log/httpd/access_log",   "label": "Apache Access (RHEL)",  "service": "httpd",       "priority": "medium", "format": "apache",    "reason": "HTTP requests on RHEL/CentOS Apache"},
    {"path": "/var/log/httpd/error_log",    "label": "Apache Error (RHEL)",   "service": "httpd",       "priority": "medium", "format": "apache",    "reason": "Apache errors on RHEL/CentOS"},
    {"path": "/var/log/nginx/access.log",   "label": "Nginx Access Log",      "service": "nginx",       "priority": "medium", "format": "nginx",     "reason": "HTTP requests — detect web attacks, scanning"},
    {"path": "/var/log/nginx/error.log",    "label": "Nginx Error Log",       "service": "nginx",       "priority": "medium", "format": "nginx",     "reason": "Nginx errors and upstream failures"},
    # Databases
    {"path": "/var/log/mysql/error.log",    "label": "MySQL Error Log",       "service": "mysql",       "priority": "medium", "format": "mysql_log", "reason": "MySQL errors — failed auth, connection floods"},
    {"path": "/var/log/mariadb/mariadb.log","label": "MariaDB Log",           "service": "mariadb",     "priority": "medium", "format": "mysql_log", "reason": "MariaDB errors and auth events"},
    {"path": "/var/log/postgresql/postgresql-*.log","label": "PostgreSQL Log","service": "postgresql",  "priority": "medium", "format": "syslog",    "reason": "PostgreSQL auth failures and errors"},
    {"path": "/var/log/mongodb/mongod.log", "label": "MongoDB Log",           "service": "mongodb",     "priority": "medium", "format": "json",      "reason": "MongoDB auth and connection events"},
    {"path": "/var/log/redis/redis-server.log","label": "Redis Log",          "service": "redis",       "priority": "medium", "format": "syslog",    "reason": "Redis connection and auth events"},
    # System utils
    {"path": "/var/log/dpkg.log",       "label": "Package Manager (dpkg)",    "service": "dpkg",         "priority": "medium", "format": "syslog",    "reason": "Package installs/removals — detect unauthorized changes"},
    {"path": "/var/log/yum.log",        "label": "Package Manager (yum)",     "service": "yum",          "priority": "medium", "format": "syslog",    "reason": "Package installs/removals on RHEL/CentOS"},
    {"path": "/var/log/dnf.log",        "label": "Package Manager (dnf)",     "service": "dnf",          "priority": "medium", "format": "syslog",    "reason": "Package installs/removals on Fedora/RHEL 8+"},
    {"path": "/var/log/cron.log",       "label": "Cron Log",                  "service": "cron",         "priority": "medium", "format": "syslog",    "reason": "Scheduled jobs — detect persistence via cron"},
    {"path": "/var/log/cron",           "label": "Cron Log (RHEL)",           "service": "cron",         "priority": "medium", "format": "syslog",    "reason": "Scheduled jobs on RHEL/CentOS"},
    # Mail
    {"path": "/var/log/mail.log",       "label": "Mail Log",                  "service": "postfix/exim", "priority": "low",    "format": "syslog",    "reason": "Mail delivery — detect spam relay abuse"},
    {"path": "/var/log/mail.err",       "label": "Mail Error Log",            "service": "postfix/exim", "priority": "low",    "format": "syslog",    "reason": "Mail server errors"},
    {"path": "/var/log/dmesg",          "label": "Boot/Device Messages",      "service": "kernel",       "priority": "low",    "format": "syslog",    "reason": "Hardware and driver events during boot"},
]

# ── Log catalogue — WINDOWS ───────────────────────────────────────────────────
WINDOWS_CATALOGUE = [
    # Windows Event Log channels (format: eventchannel)
    {"path": "Security",                             "label": "Security Event Log",              "service": "eventlog", "priority": "high",   "format": "eventchannel", "reason": "Logon/logoff, privilege use, account management, audit policy changes"},
    {"path": "System",                               "label": "System Event Log",                "service": "eventlog", "priority": "high",   "format": "eventchannel", "reason": "Service start/stop, driver errors, system crashes"},
    {"path": "Application",                          "label": "Application Event Log",           "service": "eventlog", "priority": "medium", "format": "eventchannel", "reason": "Application errors, crashes, and warnings"},
    {"path": "Microsoft-Windows-PowerShell/Operational","label": "PowerShell Operational Log",   "service": "eventlog", "priority": "high",   "format": "eventchannel", "reason": "PowerShell command execution — detect malicious scripts"},
    {"path": "Microsoft-Windows-Sysmon/Operational", "label": "Sysmon Operational Log",         "service": "Sysmon",   "priority": "high",   "format": "eventchannel", "reason": "Process creation, network connections, registry changes (requires Sysmon)"},
    {"path": "Microsoft-Windows-Windows Defender/Operational","label": "Windows Defender Log",  "service": "WinDefend","priority": "high",   "format": "eventchannel", "reason": "Malware detections and quarantine events"},
    {"path": "Microsoft-Windows-TaskScheduler/Operational","label": "Task Scheduler Log",       "service": "eventlog", "priority": "medium", "format": "eventchannel", "reason": "Scheduled task creation/modification — detect persistence"},
    {"path": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational","label": "RDP Session Log","service": "eventlog","priority": "high","format": "eventchannel","reason": "RDP logon/logoff events — detect remote access"},
    {"path": "Microsoft-Windows-Bits-Client/Operational","label": "BITS Client Log",            "service": "eventlog", "priority": "medium", "format": "eventchannel", "reason": "Background file transfers — detect data exfiltration"},
    {"path": "Microsoft-Windows-WMI-Activity/Operational","label": "WMI Activity Log",          "service": "eventlog", "priority": "medium", "format": "eventchannel", "reason": "WMI activity — detect lateral movement and persistence"},
    {"path": "Microsoft-Windows-DNSClient/Operational","label": "DNS Client Log",               "service": "eventlog", "priority": "medium", "format": "eventchannel", "reason": "DNS queries — detect C2 communication and tunneling"},
    {"path": "Microsoft-Windows-Firewall With Advanced Security/Firewall","label": "Windows Firewall Log","service": "eventlog","priority": "high","format": "eventchannel","reason": "Firewall rule changes and blocked connections"},
    # File-based logs on Windows
    {"path": r"C:\inetpub\logs\LogFiles\W3SVC1\*.log", "label": "IIS Web Server Log", "service": "W3SVC", "priority": "medium", "format": "iis", "reason": "IIS HTTP requests — detect web attacks and scanning"},
]

LOG_CATALOGUE = WINDOWS_CATALOGUE if IS_WIN else LINUX_CATALOGUE

# ── Service / package detection ───────────────────────────────────────────────
def get_active_services() -> set:
    services = set()
    if IS_WIN:
        try:
            r = subprocess.check_output(
                ["sc", "query", "type=", "all", "state=", "all"],
                stderr=subprocess.DEVNULL, text=True
            )
            for line in r.splitlines():
                if "SERVICE_NAME:" in line:
                    services.add(line.split(":")[-1].strip().lower())
        except Exception:
            pass
    else:
        try:
            out = subprocess.check_output(
                ["systemctl", "list-units", "--type=service", "--state=active",
                 "--no-pager", "--plain", "--no-legend"],
                stderr=subprocess.DEVNULL, text=True
            )
            services = {line.split()[0].replace(".service", "") for line in out.splitlines() if line.strip()}
        except Exception:
            pass
    return services


def get_installed_packages() -> set:
    pkgs = set()
    if IS_WIN:
        # Query installed software from registry via wmic
        try:
            out = subprocess.check_output(
                ["wmic", "product", "get", "name"],
                stderr=subprocess.DEVNULL, text=True
            )
            pkgs = {line.strip().lower() for line in out.splitlines() if line.strip() and line.strip() != "Name"}
        except Exception:
            pass
        # Also check common service names
        try:
            r = subprocess.check_output(
                ["sc", "query", "type=", "all", "state=", "all"],
                stderr=subprocess.DEVNULL, text=True
            )
            for line in r.splitlines():
                if "SERVICE_NAME:" in line:
                    pkgs.add(line.split(":")[-1].strip().lower())
        except Exception:
            pass
    else:
        for cmd in [["dpkg", "--get-selections"], ["rpm", "-qa", "--qf", "%{NAME}\n"]]:
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
                pkgs.update(line.split()[0] for line in out.splitlines() if line.strip())
            except Exception:
                continue
    return pkgs


def check_win_event_channel(channel: str) -> bool:
    """Check if a Windows Event Log channel exists and has events."""
    try:
        r = subprocess.run(
            ["wevtutil", "gl", channel],
            capture_output=True, text=True
        )
        return r.returncode == 0
    except Exception:
        return False


def check_win_service_exists(svc: str) -> bool:
    """Check if a Windows service exists."""
    try:
        r = subprocess.run(["sc", "query", svc], capture_output=True, text=True)
        return r.returncode == 0
    except Exception:
        return False

# ── Discovery ─────────────────────────────────────────────────────────────────
def discover_logs(active_services: set, installed_packages: set) -> list:
    results = []
    for entry in LOG_CATALOGUE:
        path = entry["path"]
        fmt  = entry["format"]

        if IS_WIN:
            if fmt == "eventchannel":
                # Check Windows Event Log channel via wevtutil
                exists = check_win_event_channel(path)
                svc    = entry["service"].lower()
                svc_ok = check_win_service_exists(entry["service"]) if entry["service"] != "eventlog" else True
                if exists or svc_ok:
                    results.append({"entry": entry, "found_paths": [path],
                                    "source": "file" if exists else "service"})
            else:
                # File-based log on Windows
                matches = [p for p in glob.glob(path) if os.path.isfile(p)]
                if not matches and os.path.isfile(path):
                    matches = [path]
                if matches:
                    results.append({"entry": entry, "found_paths": matches, "source": "file"})
                elif entry["service"].lower() in active_services:
                    results.append({"entry": entry, "found_paths": [path], "source": "service"})
        else:
            matches = [p for p in glob.glob(path) if os.path.isfile(p)]
            if not matches and os.path.isfile(path):
                matches = [path]
            if matches:
                results.append({"entry": entry, "found_paths": matches, "source": "file"})
                continue
            svc = entry["service"].split("/")[0]
            if svc in active_services or svc in installed_packages:
                results.append({"entry": entry, "found_paths": [path], "source": "service"})

    results.sort(key=lambda r: PRIORITY_ORDER[r["entry"]["priority"]])
    return results


def scan_custom_logs() -> list:
    """Find additional log files not in the catalogue."""
    if IS_WIN:
        known   = {e["path"] for e in LOG_CATALOGUE}
        custom  = []
        search_dirs = [
            r"C:\inetpub\logs",
            r"C:\Program Files",
            r"C:\ProgramData",
        ]
        for base in search_dirs:
            if not os.path.exists(base):
                continue
            for root, dirs, files in os.walk(base):
                # Limit depth
                depth = root.replace(base, "").count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue
                for f in files:
                    if f.endswith(".log") or f.endswith(".txt"):
                        full = os.path.join(root, f)
                        try:
                            if full not in known and os.path.getsize(full) > 0:
                                custom.append(full)
                        except Exception:
                            continue
        return sorted(custom[:50])  # cap at 50 custom logs on Windows
    else:
        known  = {e["path"] for e in LOG_CATALOGUE}
        custom = []
        for root, dirs, files in os.walk("/var/log"):
            dirs[:] = [d for d in dirs if d not in ("journal",)]
            for f in files:
                if f.endswith(".log") or f.endswith(".err"):
                    full = os.path.join(root, f)
                    try:
                        if full not in known and os.path.getsize(full) > 0:
                            custom.append(full)
                    except Exception:
                        continue
        return sorted(custom)

# ── Cross-platform keyboard input ─────────────────────────────────────────────
def getch():
    if IS_WIN:
        import msvcrt
        ch = msvcrt.getwch()

        # Classic Windows console: extended key prefix \x00 or \xe0
        if ch in ('\x00', '\xe0'):
            ch2 = msvcrt.getwch()
            if ch2 == 'H': return "UP"
            if ch2 == 'P': return "DOWN"
            if ch2 == 'K': return "LEFT"
            if ch2 == 'M': return "RIGHT"
            return ''

        # Windows Terminal sends ANSI escape sequences — handle \x1b[A/B
        if ch == '\x1b':
            # Try to read next chars non-blocking
            try:
                next1 = msvcrt.getwch()  # expect '['
                if next1 == '[':
                    next2 = msvcrt.getwch()
                    if next2 == 'A': return "UP"
                    if next2 == 'B': return "DOWN"
                    if next2 == 'C': return "RIGHT"
                    if next2 == 'D': return "LEFT"
            except Exception:
                pass
            return '\x1b'

        return ch
    else:
        import tty, termios
        fd  = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            if ch == "\x1b":
                sys.stdin.read(1)
                arrow = sys.stdin.read(1)
                if arrow == "A": return "UP"
                if arrow == "B": return "DOWN"
                return ''
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

def clear_screen():
    # ANSI: move cursor to top-left + clear screen — works on both
    # Windows Terminal and Linux without causing auto-scroll to bottom
    if IS_WIN:
        # Enable ANSI on Windows if not already enabled
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

# Valid log_format values per OS (from Wazuh agent documentation)
VALID_FORMATS_WIN = {
    "eventchannel", "eventlog", "syslog",
    "iis", "command", "full_command",
}
VALID_FORMATS_LINUX = {
    "syslog", "auth", "apache", "nginx", "mysql_log",
    "postgresql_log", "audit", "json", "iis",
    "command", "full_command", "multi-line",
    "snort-full", "snort-fast", "squid", "ossec",
    "djb-multilog", "cisco-ios", "cisco-asa",
    # NOTE: 'plain', 'journald' are NOT valid Wazuh log_format values
    # journald is read via <wodle name="journald"> not <localfile>
}

def safe_format(fmt: str) -> str:
    """Return a valid log_format for the current OS. Falls back to syslog."""
    valid = VALID_FORMATS_WIN if IS_WIN else VALID_FORMATS_LINUX
    return fmt if fmt in valid else "syslog"

def validate_ossec_conf(conf_path: str) -> tuple:
    """
    Run wazuh-logtest or ossec-logtest dry-run to validate ossec.conf.
    Returns (ok: bool, error: str).
    Falls back to basic XML check if test binary not available.
    """
    # Try Wazuh agent config test
    test_bins = [
        "/var/ossec/bin/wazuh-agentd",
        "/var/ossec/bin/ossec-agentd",
    ]
    for binary in test_bins:
        if os.path.exists(binary):
            r = subprocess.run(
                [binary, "-t"],
                capture_output=True, text=True
            )
            if r.returncode != 0:
                # Extract meaningful error from stderr/stdout
                err = (r.stderr or r.stdout or "").strip()
                return False, err
            return True, ""

    # Fallback: basic XML validity check using Python
    try:
        import xml.etree.ElementTree as ET
        ET.parse(conf_path)
        return True, ""
    except Exception as e:
        return False, str(e)

# ── ossec.conf injection ──────────────────────────────────────────────────────
def inject_into_conf(selected: list):
    if not os.path.exists(AGENT_CONF):
        print(f"{YELLOW}  Agent config not found at {AGENT_CONF}. Skipping.{RESET}")
        return

    # Step 1: heal any pre-existing invalid formats in the config first
    heal_ossec_conf()

    with open(AGENT_CONF) as f:
        conf = f.read()

    # Step 2: remove previous discovery block
    start_tag = "<!-- CodeRed Discovered Logs -->"
    end_tag   = "<!-- END:discovered-logs -->"
    s = conf.find(start_tag)
    e = conf.find(end_tag)
    if s != -1 and e != -1:
        conf = conf[:s] + conf[e + len(end_tag):]

    # Step 3: build new block — normalise format per OS
    lines = [f"  {start_tag}"]
    skipped = 0
    for item in selected:
        fmt = safe_format(item["format"])
        if fmt != item["format"]:
            skipped += 1
        lines.append(
            f"  <localfile>\n"
            f"    <log_format>{fmt}</log_format>\n"
            f"    <location>{item['path']}</location>\n"
            f"  </localfile>"
        )
    lines.append(f"  {end_tag}")
    block    = "\n".join(lines)
    new_conf = conf.replace("</ossec_config>", block + "\n</ossec_config>")

    if skipped:
        print(f"{YELLOW}  ⚠ {skipped} log format(s) normalised to 'syslog' for compatibility.{RESET}")

    # Step 4: write to temp, validate full config, then atomically replace
    tmp_path = AGENT_CONF + ".tmp"
    with open(tmp_path, "w") as f:
        f.write(new_conf)

    ok, err = validate_ossec_conf(tmp_path)
    if not ok and err:
        os.remove(tmp_path)
        print(f"{RED}  ✖ Config validation failed — agent config NOT updated.{RESET}")
        print(f"  {DIM}{err[:200]}{RESET}")
        return

    # Validation passed — apply
    shutil.copy2(AGENT_CONF, AGENT_CONF + ".bak")
    shutil.move(tmp_path, AGENT_CONF)
    print(f"{GREEN}  ✔ Config validated and written successfully.{RESET}")

# ── Interactive UI (viewport-based — only renders visible items) ──────────────
def present_ui(discovered: list, custom_logs: list) -> list:
    items = []

    for r in discovered:
        for path in r["found_paths"]:
            items.append({
                "path"    : path,
                "label"   : r["entry"]["label"],
                "priority": r["entry"]["priority"],
                "format"  : r["entry"]["format"],
                "reason"  : r["entry"]["reason"],
                "source"  : r["source"],
                "selected": PRIORITY_DEFAULT[r["entry"]["priority"]],
            })

    for path in custom_logs:
        items.append({
            "path"    : path,
            "label"   : os.path.basename(path),
            "priority": "low",
            "format"  : "eventchannel" if IS_WIN and os.path.sep not in path else "syslog",
            "reason"  : "Custom log detected on this system",
            "source"  : "file",
            "selected": False,
        })

    if not items:
        print(f"{YELLOW}  No logs found on this system.{RESET}")
        return []

    cursor     = 0
    view_start = 0  # index of first visible item

    def get_viewport_size() -> int:
        """How many items fit on screen after header/footer."""
        try:
            rows = os.get_terminal_size().lines
        except Exception:
            rows = 24
        # Reserve: 5 header lines + 3 footer lines + 2 per item (path + reason/blank)
        return max(3, (rows - 8) // 2)

    def render():
        nonlocal view_start
        viewport = get_viewport_size()

        # Scroll view to keep cursor visible
        if cursor < view_start:
            view_start = cursor
        elif cursor >= view_start + viewport:
            view_start = cursor - viewport + 1

        clear_screen()
        total    = len(items)
        selected = sum(1 for it in items if it["selected"])
        view_end = min(view_start + viewport, total)

        # Header
        sys.stdout.write(f"\n{CYAN}{BOLD}  CodeRed Log Discovery{RESET}\n")
        sys.stdout.write(f"  {DIM}↑↓ move · Space toggle · A all · N none · Enter confirm · Q cancel{RESET}\n\n")

        # Scroll indicator
        if total > viewport:
            sys.stdout.write(f"  {DIM}Showing {view_start+1}–{view_end} of {total} items{RESET}\n\n")

        # Visible items only
        prev_priority = None
        for i in range(view_start, view_end):
            item = items[i]

            # Priority header — only show when priority changes within view
            if item["priority"] != prev_priority:
                prev_priority = item["priority"]
                sys.stdout.write(f"\n  {PRIORITY_LABELS[item['priority']]}\n\n")

            tick  = f"{GREEN}✔{RESET}" if item["selected"] else f"{RED}✖{RESET}"
            arrow = f"{CYAN}▶{RESET}" if i == cursor else " "
            src   = f"{DIM}(service){RESET}" if item["source"] == "service" else ""
            hi    = BOLD if i == cursor else ""

            sys.stdout.write(f"  {arrow} [{tick}] {hi}{item['path']}{RESET} {src}\n")
            if i == cursor:
                sys.stdout.write(f"       {DIM}{item['reason']}{RESET}\n")

        # Footer
        sys.stdout.write(f"\n  {CYAN}{'─'*54}{RESET}\n")
        sys.stdout.write(f"  {selected} of {total} log(s) selected\n")
        sys.stdout.flush()

    render()
    while True:
        ch = getch()
        if   ch == "UP"   and cursor > 0:              cursor -= 1
        elif ch == "DOWN" and cursor < len(items) - 1: cursor += 1
        elif ch == " ":
            items[cursor]["selected"] = not items[cursor]["selected"]
        elif ch.lower() == "a":
            for it in items: it["selected"] = True
        elif ch.lower() == "n":
            for it in items: it["selected"] = False
        elif ch in ("\r", "\n"):
            break
        elif ch == "q":
            print("\n  Cancelled.")
            return []
        render()

    return [it for it in items if it["selected"]]

# ── Self-heal: fix invalid formats already in ossec.conf ─────────────────────
def heal_ossec_conf() -> bool:
    """
    Scan existing ossec.conf for invalid log_format values and fix them.
    Returns True if any fixes were made.
    """
    if not os.path.exists(AGENT_CONF):
        return False

    valid = VALID_FORMATS_WIN if IS_WIN else VALID_FORMATS_LINUX
    fixed = 0

    try:
        with open(AGENT_CONF, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("<log_format>") and stripped.endswith("</log_format>"):
                fmt = stripped[len("<log_format>"):-len("</log_format>")].strip()
                if fmt not in valid:
                    indent = line[: len(line) - len(line.lstrip())]
                    line = f"{indent}<log_format>syslog</log_format>\n"
                    fixed += 1
            new_lines.append(line)

        if fixed:
            shutil.copy2(AGENT_CONF, AGENT_CONF + ".bak")
            with open(AGENT_CONF, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            print(f"{GREEN}  ✔ Auto-fixed {fixed} invalid log format(s) in ossec.conf.{RESET}")
            return True
    except Exception as e:
        print(f"{YELLOW}  Could not auto-heal ossec.conf: {e}{RESET}")

    return False

# ── Main entrypoint ───────────────────────────────────────────────────────────
def run_discovery(auto_apply=False):
    print(f"\n{CYAN}{BOLD}  CodeRed Log Discovery{RESET}")
    platform_label = "Windows" if IS_WIN else "Linux"
    print(f"  Scanning {platform_label} endpoint...\n")

    # Auto-fix any invalid formats from previous scans before doing anything
    heal_ossec_conf()

    active_svc = get_active_services()
    installed  = get_installed_packages()

    print(f"  {GREEN}✔{RESET} Active services detected : {len(active_svc)}")
    print(f"  {GREEN}✔{RESET} Installed packages       : {len(installed)}")

    discovered = discover_logs(active_svc, installed)
    custom     = scan_custom_logs()

    print(f"  {GREEN}✔{RESET} Known logs found         : {len(discovered)}")
    print(f"  {GREEN}✔{RESET} Custom logs found        : {len(custom)}")
    print()

    input(f"  Press {BOLD}Enter{RESET} to review recommendations...")

    selected = present_ui(discovered, custom)

    if not selected:
        print(f"\n{YELLOW}  No logs selected. Nothing changed.{RESET}\n")
        return

    print(f"\n{CYAN}  Applying {len(selected)} log source(s) to agent config...{RESET}")
    inject_into_conf(selected)
    print(f"{GREEN}  ✔ Agent config updated.{RESET}")

    if not auto_apply:
        ans = input(f"\n  Restart agent now to apply changes? (y/N): ").strip().lower()
        auto_apply = ans == "y"

    if auto_apply:
        print(f"{CYAN}  Restarting agent...{RESET}")
        try:
            if IS_WIN:
                # Try common Windows service names
                for svc in ["WazuhSvc", "Wazuh", "wazuh"]:
                    r = subprocess.run(["sc", "query", svc], capture_output=True, text=True)
                    if r.returncode == 0:
                        subprocess.run(["sc", "stop",  svc], capture_output=True)
                        import time; time.sleep(2)
                        subprocess.run(["sc", "start", svc], capture_output=True)
                        break
            else:
                subprocess.run(["systemctl", "restart", "wazuh-agent"], check=True)
            print(f"{GREEN}  ✔ Agent restarted.{RESET}")
        except Exception as e:
            print(f"{YELLOW}  Could not restart agent: {e}{RESET}")

    print(f"\n{GREEN}{BOLD}  Log discovery complete!{RESET}")
    print(f"  {len(selected)} log source(s) now monitored.\n")


if __name__ == "__main__":
    # Admin check
    try:
        if IS_WIN:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print(f"{RED}Please run as Administrator.{RESET}")
                sys.exit(1)
        else:
            if os.geteuid() != 0:
                print(f"{RED}Please run as root (sudo).{RESET}")
                sys.exit(1)
    except Exception:
        pass
    run_discovery()
