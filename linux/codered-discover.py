#!/usr/bin/env python3
"""
CodeRed Server Agent - Log Discovery Engine
Scans for known log files and adds them to ossec.conf monitoring.
"""
import os, sys, re, subprocess, json

OSSEC_CONF   = "/var/ossec/etc/ossec.conf"
STATE_FILE   = "/etc/codered/state.json"

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

# Valid Wazuh log_format values only
LOG_SOURCES = [
    {"path":"/var/log/auth.log",                         "label":"Authentication Log",     "service":"ssh",        "priority":"high",   "format":"syslog", "reason":"SSH logins, sudo, PAM auth failures"},
    {"path":"/var/log/secure",                            "label":"Secure Log (RHEL)",      "service":"ssh",        "priority":"high",   "format":"syslog", "reason":"SSH/sudo on RHEL/CentOS"},
    {"path":"/var/log/syslog",                            "label":"System Log",             "service":"system",     "priority":"high",   "format":"syslog", "reason":"General system events"},
    {"path":"/var/log/messages",                          "label":"System Messages (RHEL)", "service":"system",     "priority":"high",   "format":"syslog", "reason":"System messages on RHEL/CentOS"},
    {"path":"/var/log/kern.log",                          "label":"Kernel Log",             "service":"kernel",     "priority":"high",   "format":"syslog", "reason":"Kernel events, OOM killer"},
    {"path":"/var/log/audit/audit.log",                   "label":"Linux Audit Log",        "service":"auditd",     "priority":"high",   "format":"audit",  "reason":"Syscall auditing, privilege escalation"},
    {"path":"/var/log/ufw.log",                           "label":"UFW Firewall Log",       "service":"ufw",        "priority":"high",   "format":"syslog", "reason":"Firewall block/allow events"},
    {"path":"/var/log/iptables.log",                      "label":"iptables Log",           "service":"iptables",   "priority":"high",   "format":"syslog", "reason":"Raw iptables packet events"},
    {"path":"/var/log/fail2ban.log",                      "label":"Fail2ban Log",           "service":"fail2ban",   "priority":"medium", "format":"syslog", "reason":"Banned IPs, brute-force events"},
    {"path":"/var/log/apache2/access.log",                "label":"Apache Access Log",      "service":"apache2",    "priority":"medium", "format":"apache", "reason":"HTTP requests - detect web attacks"},
    {"path":"/var/log/apache2/error.log",                 "label":"Apache Error Log",       "service":"apache2",    "priority":"medium", "format":"apache", "reason":"Apache errors"},
    {"path":"/var/log/httpd/access_log",                  "label":"Apache Access (RHEL)",   "service":"httpd",      "priority":"medium", "format":"apache", "reason":"HTTP requests on RHEL"},
    {"path":"/var/log/nginx/access.log",                  "label":"Nginx Access Log",       "service":"nginx",      "priority":"medium", "format":"syslog", "reason":"HTTP requests - detect web attacks"},
    {"path":"/var/log/nginx/error.log",                   "label":"Nginx Error Log",        "service":"nginx",      "priority":"medium", "format":"syslog", "reason":"Nginx errors"},
    {"path":"/var/log/mysql/error.log",                   "label":"MySQL Error Log",        "service":"mysql",      "priority":"medium", "format":"syslog", "reason":"MySQL auth failures"},
    {"path":"/var/log/postgresql/postgresql-*.log",       "label":"PostgreSQL Log",         "service":"postgresql", "priority":"medium", "format":"syslog", "reason":"PostgreSQL errors"},
    {"path":"/var/log/mongodb/mongod.log",                "label":"MongoDB Log",            "service":"mongodb",    "priority":"medium", "format":"syslog", "reason":"MongoDB auth events"},
    {"path":"/var/log/dpkg.log",                          "label":"Package Manager (dpkg)", "service":"dpkg",       "priority":"medium", "format":"syslog", "reason":"Package installs/removals"},
    {"path":"/var/log/yum.log",                           "label":"Package Manager (yum)",  "service":"yum",        "priority":"medium", "format":"syslog", "reason":"Package changes on RHEL"},
    {"path":"/var/log/dnf.log",                           "label":"Package Manager (dnf)",  "service":"dnf",        "priority":"medium", "format":"syslog", "reason":"Package changes on Fedora/RHEL8+"},
    {"path":"/var/log/cron",                              "label":"Cron Log",               "service":"cron",       "priority":"medium", "format":"syslog", "reason":"Scheduled task execution"},
    {"path":"/var/log/cron.log",                          "label":"Cron Log (Debian)",      "service":"cron",       "priority":"medium", "format":"syslog", "reason":"Scheduled task execution"},
    {"path":"/var/log/docker.log",                        "label":"Docker Log",             "service":"docker",     "priority":"low",    "format":"syslog", "reason":"Container start/stop events"},
    {"path":"/var/log/redis/redis-server.log",            "label":"Redis Log",              "service":"redis",      "priority":"low",    "format":"syslog", "reason":"Redis errors and auth events"},
]

def getch():
    import tty, termios
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            sys.stdin.read(1)
            a = sys.stdin.read(1)
            if a == "A": return "UP"
            if a == "B": return "DOWN"
            return ""
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def scan_existing():
    """Read currently monitored paths from ossec.conf."""
    try:
        with open(OSSEC_CONF, "r") as f:
            content = f.read()
        return set(re.findall(r"<location>([^<]+)</location>", content))
    except:
        return set()

def add_to_ossec(entries):
    """Append localfile entries to ossec.conf."""
    if not entries:
        return
    block = "\n  <!-- CodeRed Discovered Logs -->\n"
    for e in entries:
        block += (
            f"  <localfile>\n"
            f"    <log_format>{e['format']}</log_format>\n"
            f"    <location>{e['path']}</location>\n"
            f"  </localfile>\n"
        )
    try:
        with open(OSSEC_CONF, "r") as f:
            content = f.read()
        # Remove existing CodeRed discovered block to avoid duplicates
        content = re.sub(
            r"\n  <!-- CodeRed Discovered Logs -->.*",
            "", content, flags=re.DOTALL
        )
        # Insert before last </ossec_config>
        idx = content.rfind("</ossec_config>")
        if idx != -1:
            content = content[:idx] + block + content[idx:]
        else:
            content += block
        with open(OSSEC_CONF, "w") as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"{RED}  Error writing ossec.conf: {e}{RESET}")
        return False

def run_discovery():
    """Main discovery UI."""
    existing = scan_existing()
    found = []
    for src in LOG_SOURCES:
        path = src["path"]
        # Handle glob patterns
        if "*" in path:
            import glob
            matches = glob.glob(path)
            if matches:
                found.append({**src, "path": matches[0], "exists": True})
        elif os.path.exists(path):
            found.append({**src, "exists": True})

    if not found:
        print(f"\n{YELLOW}  No known log files found on this system.{RESET}\n")
        return

    # Mark already monitored
    selected = set()
    for i, s in enumerate(found):
        if s["path"] in existing:
            selected.add(i)

    cursor = 0
    vs = 0

    def render():
        nonlocal vs
        try:
            rows = os.get_terminal_size().lines
        except:
            rows = 24
        vp = max(3, rows - 10)
        if cursor < vs: vs = cursor
        elif cursor >= vs + vp: vs = cursor - vp + 1
        ve = min(vs + vp, len(found))

        sys.stdout.write("\033[2J\033[H")
        sys.stdout.write(f"{CYAN}{BOLD}\n  Scan Log Directories{RESET}\n\n")
        sys.stdout.write(f"  {DIM}Found {len(found)} log files. Space=toggle, A=all, N=none, Enter=save, Q=back{RESET}\n\n")

        for i in range(vs, ve):
            s = found[i]
            tick = f"{GREEN}✔{RESET}" if i in selected else f"{DIM}○{RESET}"
            arrow = f"{CYAN}▶{RESET}" if i == cursor else " "
            already = f" {DIM}(already monitored){RESET}" if s["path"] in existing else ""
            pri_col = RED if s["priority"] == "high" else (YELLOW if s["priority"] == "medium" else DIM)
            sys.stdout.write(f"  {arrow} [{tick}] {s['label']}{already}\n")
            if i == cursor:
                sys.stdout.write(f"       {DIM}{s['path']}{RESET}\n")
                sys.stdout.write(f"       {pri_col}{s['priority'].upper()}{RESET}{DIM} — {s['reason']}{RESET}\n")
        sys.stdout.write(f"\n  {DIM}{'─'*44}{RESET}\n")
        sys.stdout.write(f"  {len(selected)} selected\n")
        sys.stdout.flush()

    render()
    while True:
        ch = getch()
        if   ch == "UP"   and cursor > 0:             cursor -= 1
        elif ch == "DOWN" and cursor < len(found) - 1: cursor += 1
        elif ch == " ":
            if cursor in selected: selected.discard(cursor)
            else: selected.add(cursor)
        elif ch.lower() == "a": selected = set(range(len(found)))
        elif ch.lower() == "n": selected = set()
        elif ch in ("\r", "\n"):
            to_add = [found[i] for i in selected if found[i]["path"] not in existing]
            if to_add:
                if add_to_ossec(to_add):
                    sys.stdout.write(f"\n{GREEN}  ✔ Added {len(to_add)} log source(s) to monitoring.{RESET}\n")
                    sys.stdout.write(f"  {DIM}Restart agent to apply: sudo systemctl restart wazuh-agent{RESET}\n")
                else:
                    sys.stdout.write(f"\n{RED}  ✖ Failed to update ossec.conf.{RESET}\n")
            else:
                sys.stdout.write(f"\n{YELLOW}  No new log sources to add.{RESET}\n")
            sys.stdout.flush()
            return
        elif ch.lower() == "q":
            return
        render()

if __name__ == "__main__":
    run_discovery()
