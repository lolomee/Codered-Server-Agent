#!/usr/bin/env python3
"""
CodeRed Server Agent — Log Discovery Engine
Scans the endpoint for log files, scores them by security relevance,
and lets the customer pick which ones to monitor.
"""

import os
import sys
import json
import subprocess
import glob
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
OSSEC_CONF   = "/var/ossec/etc/ossec.conf"
STATE_FILE   = "/etc/codered/state.json"

# ── Colours ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── Known log catalogue ───────────────────────────────────────────────────────
# Format:
#   path        : exact path or glob pattern
#   label       : human-readable name
#   service     : associated service/package
#   priority    : high / medium / low
#   format      : wazuh log_format value
#   reason      : why this matters (shown to customer)

LOG_CATALOGUE = [
    # ── System / Auth ─────────────────────────────────────────────────────────
    {
        "path": "/var/log/auth.log",
        "label": "Authentication Log",
        "service": "ssh/sudo/pam",
        "priority": "high",
        "format": "syslog",
        "reason": "SSH logins, sudo usage, PAM auth failures — critical for intrusion detection",
    },
    {
        "path": "/var/log/secure",
        "label": "Secure Log (RHEL/CentOS)",
        "service": "ssh/sudo/pam",
        "priority": "high",
        "format": "syslog",
        "reason": "SSH logins, sudo usage on RHEL/CentOS systems",
    },
    {
        "path": "/var/log/syslog",
        "label": "System Log",
        "service": "system",
        "priority": "high",
        "format": "syslog",
        "reason": "General system events, daemon start/stop, kernel messages",
    },
    {
        "path": "/var/log/messages",
        "label": "System Messages (RHEL/CentOS)",
        "service": "system",
        "priority": "high",
        "format": "syslog",
        "reason": "General system messages on RHEL/CentOS",
    },
    {
        "path": "/var/log/kern.log",
        "label": "Kernel Log",
        "service": "kernel",
        "priority": "high",
        "format": "syslog",
        "reason": "Kernel events including OOM killer, hardware errors, network drops",
    },
    {
        "path": "/var/log/dmesg",
        "label": "Boot/Device Messages",
        "service": "kernel",
        "priority": "medium",
        "format": "syslog",
        "reason": "Hardware and driver events during boot and runtime",
    },
    # ── Firewall ──────────────────────────────────────────────────────────────
    {
        "path": "/var/log/ufw.log",
        "label": "UFW Firewall Log",
        "service": "ufw",
        "priority": "high",
        "format": "syslog",
        "reason": "Firewall block/allow events — detect port scans and blocked attacks",
    },
    {
        "path": "/var/log/firewalld",
        "label": "FirewallD Log",
        "service": "firewalld",
        "priority": "high",
        "format": "syslog",
        "reason": "Firewall events on RHEL/CentOS systems",
    },
    {
        "path": "/var/log/iptables.log",
        "label": "iptables Log",
        "service": "iptables",
        "priority": "high",
        "format": "syslog",
        "reason": "Raw iptables packet drop/accept events",
    },
    # ── Intrusion Prevention ──────────────────────────────────────────────────
    {
        "path": "/var/log/fail2ban.log",
        "label": "Fail2ban Log",
        "service": "fail2ban",
        "priority": "medium",
        "format": "syslog",
        "reason": "Banned IPs and brute-force detection events",
    },
    # ── Web Servers ───────────────────────────────────────────────────────────
    {
        "path": "/var/log/apache2/access.log",
        "label": "Apache Access Log",
        "service": "apache2",
        "priority": "medium",
        "format": "apache",
        "reason": "HTTP requests — detect web attacks, scanning, path traversal",
    },
    {
        "path": "/var/log/apache2/error.log",
        "label": "Apache Error Log",
        "service": "apache2",
        "priority": "medium",
        "format": "apache",
        "reason": "Apache errors and warnings — detect misconfigurations and attacks",
    },
    {
        "path": "/var/log/httpd/access_log",
        "label": "Apache Access Log (RHEL)",
        "service": "httpd",
        "priority": "medium",
        "format": "apache",
        "reason": "HTTP requests on RHEL/CentOS Apache",
    },
    {
        "path": "/var/log/httpd/error_log",
        "label": "Apache Error Log (RHEL)",
        "service": "httpd",
        "priority": "medium",
        "format": "apache",
        "reason": "Apache errors on RHEL/CentOS",
    },
    {
        "path": "/var/log/nginx/access.log",
        "label": "Nginx Access Log",
        "service": "nginx",
        "priority": "medium",
        "format": "nginx",
        "reason": "HTTP requests — detect web attacks, scanning, path traversal",
    },
    {
        "path": "/var/log/nginx/error.log",
        "label": "Nginx Error Log",
        "service": "nginx",
        "priority": "medium",
        "format": "nginx",
        "reason": "Nginx errors — detect misconfigurations and upstream failures",
    },
    # ── Databases ─────────────────────────────────────────────────────────────
    {
        "path": "/var/log/mysql/error.log",
        "label": "MySQL Error Log",
        "service": "mysql",
        "priority": "medium",
        "format": "mysql_log",
        "reason": "MySQL errors — detect failed auth, connection floods",
    },
    {
        "path": "/var/log/mariadb/mariadb.log",
        "label": "MariaDB Log",
        "service": "mariadb",
        "priority": "medium",
        "format": "mysql_log",
        "reason": "MariaDB errors and auth events",
    },
    {
        "path": "/var/log/postgresql/postgresql-*.log",
        "label": "PostgreSQL Log",
        "service": "postgresql",
        "priority": "medium",
        "format": "syslog",
        "reason": "PostgreSQL auth failures and errors",
    },
    {
        "path": "/var/log/mongodb/mongod.log",
        "label": "MongoDB Log",
        "service": "mongodb",
        "priority": "medium",
        "format": "json",
        "reason": "MongoDB auth and connection events",
    },
    {
        "path": "/var/log/redis/redis-server.log",
        "label": "Redis Log",
        "service": "redis",
        "priority": "medium",
        "format": "syslog",
        "reason": "Redis connection and auth events",
    },
    # ── Mail ──────────────────────────────────────────────────────────────────
    {
        "path": "/var/log/mail.log",
        "label": "Mail Log",
        "service": "postfix/exim",
        "priority": "low",
        "format": "syslog",
        "reason": "Mail delivery events — detect spam relay abuse",
    },
    {
        "path": "/var/log/mail.err",
        "label": "Mail Error Log",
        "service": "postfix/exim",
        "priority": "low",
        "format": "syslog",
        "reason": "Mail server errors",
    },
    # ── Cron ──────────────────────────────────────────────────────────────────
    {
        "path": "/var/log/cron.log",
        "label": "Cron Log",
        "service": "cron",
        "priority": "medium",
        "format": "syslog",
        "reason": "Scheduled job execution — detect persistence via cron",
    },
    {
        "path": "/var/log/cron",
        "label": "Cron Log (RHEL)",
        "service": "cron",
        "priority": "medium",
        "format": "syslog",
        "reason": "Scheduled job execution on RHEL/CentOS",
    },
    # ── Docker / Containers ───────────────────────────────────────────────────
    {
        "path": "/var/log/docker.log",
        "label": "Docker Daemon Log",
        "service": "docker",
        "priority": "medium",
        "format": "syslog",
        "reason": "Docker daemon events — container starts, stops, errors",
    },
    # ── Application / Custom ──────────────────────────────────────────────────
    {
        "path": "/var/log/dpkg.log",
        "label": "Package Manager Log (dpkg)",
        "service": "dpkg",
        "priority": "medium",
        "format": "syslog",
        "reason": "Package installs/removals — detect unauthorized software changes",
    },
    {
        "path": "/var/log/yum.log",
        "label": "Package Manager Log (yum)",
        "service": "yum",
        "priority": "medium",
        "format": "syslog",
        "reason": "Package installs/removals on RHEL/CentOS",
    },
    {
        "path": "/var/log/dnf.log",
        "label": "Package Manager Log (dnf)",
        "service": "dnf",
        "priority": "medium",
        "format": "syslog",
        "reason": "Package installs/removals — Fedora/RHEL 8+",
    },
    {
        "path": "/var/log/audit/audit.log",
        "label": "Linux Audit Log",
        "service": "auditd",
        "priority": "high",
        "format": "audit",
        "reason": "Kernel-level syscall auditing — detect privilege escalation, file access",
    },
    {
        "path": "/var/log/wtmp",
        "label": "Login Records (wtmp)",
        "service": "system",
        "priority": "medium",
        "format": "syslog",
        "reason": "User login/logout records",
    },
]

PRIORITY_ORDER  = {"high": 0, "medium": 1, "low": 2}
PRIORITY_LABELS = {
    "high"  : f"{RED}🔴 HIGH PRIORITY{RESET}",
    "medium": f"{YELLOW}🟡 MEDIUM PRIORITY{RESET}",
    "low"   : f"{DIM}🟢 LOW PRIORITY{RESET}",
}
PRIORITY_DEFAULT = {"high": True, "medium": True, "low": False}

# ── Service detection ─────────────────────────────────────────────────────────
def get_active_services() -> set:
    """Return set of active systemd service names."""
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--state=active",
             "--no-pager", "--plain", "--no-legend"],
            stderr=subprocess.DEVNULL, text=True
        )
        return {line.split()[0].replace(".service", "") for line in out.splitlines() if line.strip()}
    except Exception:
        return set()


def get_installed_packages() -> set:
    """Return set of installed package names."""
    pkgs = set()
    for cmd in [["dpkg", "--get-selections"], ["rpm", "-qa", "--qf", "%{NAME}\n"]]:
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
            pkgs.update(line.split()[0] for line in out.splitlines() if line.strip())
        except Exception:
            continue
    return pkgs

# ── Discovery ─────────────────────────────────────────────────────────────────
def discover_logs(active_services: set, installed_packages: set) -> list:
    """
    Scan each catalogue entry.
    Returns list of dicts with 'entry' and 'found_paths'.
    """
    results = []
    for entry in LOG_CATALOGUE:
        pattern  = entry["path"]
        # Resolve glob
        matches  = [p for p in glob.glob(pattern) if os.path.isfile(p)]
        # Also check exact path
        if not matches and os.path.isfile(pattern):
            matches = [pattern]

        if matches:
            results.append({"entry": entry, "found_paths": matches, "source": "file"})
            continue

        # Service/package heuristic — if service is running, flag even if log not yet created
        svc = entry["service"].split("/")[0]
        if svc in active_services or svc in installed_packages:
            results.append({"entry": entry, "found_paths": [pattern], "source": "service"})

    # Sort by priority
    results.sort(key=lambda r: PRIORITY_ORDER[r["entry"]["priority"]])
    return results


def scan_custom_logs() -> list:
    """Find any .log files under /var/log not in catalogue."""
    known = {e["path"] for e in LOG_CATALOGUE}
    custom = []
    for root, dirs, files in os.walk("/var/log"):
        # Skip noisy dirs
        dirs[:] = [d for d in dirs if d not in ("journal",)]
        for f in files:
            if f.endswith(".log") or f.endswith(".err"):
                full = os.path.join(root, f)
                if full not in known and os.path.getsize(full) > 0:
                    custom.append(full)
    return sorted(custom)

# ── Interactive UI ────────────────────────────────────────────────────────────
def present_ui(discovered: list, custom_logs: list) -> list:
    """
    Interactive checklist. Returns list of selected log paths.
    """
    import tty, termios

    # Build item list
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
            "format"  : "syslog",
            "reason"  : "Custom log detected on this system",
            "source"  : "file",
            "selected": False,
        })

    if not items:
        print(f"{YELLOW}  No logs found on this system.{RESET}")
        return []

    cursor = 0

    def render():
        os.system("clear")
        print(f"\n{CYAN}{BOLD}  CodeRed Log Discovery{RESET}")
        print(f"  {DIM}↑↓ move · Space toggle · A select all · N deselect all · Enter confirm{RESET}\n")

        current_priority = None
        for i, item in enumerate(items):
            # Print priority header
            if item["priority"] != current_priority:
                current_priority = item["priority"]
                print(f"\n  {PRIORITY_LABELS[current_priority]}\n")

            tick  = f"{GREEN}✔{RESET}" if item["selected"] else f"{RED}✖{RESET}"
            arrow = f"{CYAN}▶{RESET}" if i == cursor else " "
            src   = f"{DIM}(service detected){RESET}" if item["source"] == "service" else ""
            hi    = BOLD if i == cursor else ""

            print(f"  {arrow} [{tick}] {hi}{item['path']}{RESET} {src}")
            if i == cursor:
                print(f"         {DIM}{item['reason']}{RESET}")
            print()

        selected_count = sum(1 for it in items if it["selected"])
        print(f"  {CYAN}──────────────────────────────────────────────────────{RESET}")
        print(f"  {selected_count} log(s) selected for monitoring\n")

    def getch():
        fd  = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            return sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    render()
    while True:
        ch = getch()
        if ch == "\x1b":
            getch()
            arrow = getch()
            if arrow == "A" and cursor > 0:
                cursor -= 1
            elif arrow == "B" and cursor < len(items) - 1:
                cursor += 1
        elif ch == " ":
            items[cursor]["selected"] = not items[cursor]["selected"]
        elif ch.lower() == "a":
            for it in items:
                it["selected"] = True
        elif ch.lower() == "n":
            for it in items:
                it["selected"] = False
        elif ch in ("\r", "\n"):
            break
        elif ch == "q":
            print("\n  Cancelled.")
            sys.exit(0)
        render()

    return [it for it in items if it["selected"]]

# ── ossec.conf injection ──────────────────────────────────────────────────────
def build_localfile_block(selected: list) -> str:
    lines = ["  <!-- CodeRed Discovered Logs -->"]
    for item in selected:
        lines.append(f"""  <localfile>
    <log_format>{item['format']}</log_format>
    <location>{item['path']}</location>
  </localfile>""")
    return "\n".join(lines)


def inject_into_ossec(selected: list):
    if not os.path.exists(OSSEC_CONF):
        print(f"{YELLOW}  ossec.conf not found at {OSSEC_CONF}. Skipping injection.{RESET}")
        return

    with open(OSSEC_CONF) as f:
        conf = f.read()

    # Remove previous discovery block
    start_tag = "<!-- CodeRed Discovered Logs -->"
    end_tag   = "<!-- END:discovered-logs -->"
    s = conf.find(start_tag)
    e = conf.find(end_tag)
    if s != -1 and e != -1:
        conf = conf[:s] + conf[e + len(end_tag):]

    block = build_localfile_block(selected) + "\n  " + end_tag
    conf  = conf.replace("</ossec_config>", block + "\n</ossec_config>")

    import shutil
    shutil.copy2(OSSEC_CONF, OSSEC_CONF + ".bak")
    with open(OSSEC_CONF, "w") as f:
        f.write(conf)


def restart_agent():
    r = subprocess.run(["systemctl", "restart", "wazuh-agent"],
                       capture_output=True, text=True)
    if r.returncode == 0:
        print(f"{GREEN}  ✔ Agent restarted.{RESET}")
    else:
        print(f"{YELLOW}  Could not restart agent: {r.stderr.strip()}{RESET}")

# ── Main entrypoint ───────────────────────────────────────────────────────────
def run_discovery(auto_apply=False):
    print(f"\n{CYAN}{BOLD}  CodeRed Log Discovery{RESET}")
    print(f"  Scanning endpoint...\n")

    active_svc  = get_active_services()
    installed   = get_installed_packages()

    print(f"  {GREEN}✔{RESET} Active services detected : {len(active_svc)}")
    print(f"  {GREEN}✔{RESET} Installed packages       : {len(installed)}")

    discovered  = discover_logs(active_svc, installed)
    custom      = scan_custom_logs()

    print(f"  {GREEN}✔{RESET} Known logs found         : {len(discovered)}")
    print(f"  {GREEN}✔{RESET} Custom logs found        : {len(custom)}")
    print()

    input(f"  Press {BOLD}Enter{RESET} to review recommendations...")

    selected = present_ui(discovered, custom)

    if not selected:
        print(f"\n{YELLOW}  No logs selected. Nothing changed.{RESET}\n")
        return

    print(f"\n{CYAN}  Applying {len(selected)} log source(s) to agent config...{RESET}")
    inject_into_ossec(selected)
    print(f"{GREEN}  ✔ ossec.conf updated.{RESET}")

    if auto_apply:
        restart_agent()
    else:
        ans = input(f"\n  Restart agent now to apply changes? (y/N): ").strip().lower()
        if ans == "y":
            restart_agent()

    print(f"\n{GREEN}{BOLD}  Log discovery complete!{RESET}")
    print(f"  {len(selected)} log source(s) now monitored by CodeRed Agent.\n")


if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{RED}Please run as root (sudo){RESET}")
        sys.exit(1)
    run_discovery()
