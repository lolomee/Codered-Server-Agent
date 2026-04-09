#!/usr/bin/env python3
"""
CodeRed Server Agent — Log Discovery Engine (Linux)
"""
import os, sys, re, glob, shutil, subprocess

AGENT_CONF = "/var/ossec/etc/ossec.conf"

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

PRIORITY_ORDER   = {"high":0,"medium":1,"low":2}
PRIORITY_LABELS  = {"high":f"{RED}🔴 HIGH PRIORITY{RESET}","medium":f"{YELLOW}🟡 MEDIUM PRIORITY{RESET}","low":f"{DIM}🟢 LOW PRIORITY{RESET}"}
PRIORITY_DEFAULT = {"high":True,"medium":True,"low":False}

VALID_FORMATS = {
    "syslog","auth","apache","nginx","mysql_log","postgresql_log",
    "audit","json","iis","command","full_command","multi-line",
    "snort-full","snort-fast","squid","ossec","djb-multilog",
    "cisco-ios","cisco-asa",
}

LOG_CATALOGUE = [
    {"path":"/var/log/auth.log",            "label":"Authentication Log",        "service":"ssh","priority":"high",   "format":"syslog",    "reason":"SSH logins, sudo, PAM auth failures"},
    {"path":"/var/log/secure",              "label":"Secure Log (RHEL)",         "service":"ssh","priority":"high",   "format":"syslog",    "reason":"SSH/sudo on RHEL/CentOS"},
    {"path":"/var/log/syslog",              "label":"System Log",                "service":"system","priority":"high","format":"syslog",    "reason":"General system events"},
    {"path":"/var/log/messages",            "label":"System Messages (RHEL)",    "service":"system","priority":"high","format":"syslog",    "reason":"System messages on RHEL/CentOS"},
    {"path":"/var/log/kern.log",            "label":"Kernel Log",                "service":"kernel","priority":"high","format":"syslog",    "reason":"Kernel events, OOM killer, hardware errors"},
    {"path":"/var/log/audit/audit.log",     "label":"Linux Audit Log",           "service":"auditd","priority":"high","format":"audit",     "reason":"Syscall auditing, privilege escalation"},
    {"path":"/var/log/ufw.log",             "label":"UFW Firewall Log",          "service":"ufw","priority":"high",   "format":"syslog",    "reason":"Firewall block/allow events"},
    {"path":"/var/log/iptables.log",        "label":"iptables Log",              "service":"iptables","priority":"high","format":"syslog",  "reason":"Raw iptables packet events"},
    {"path":"/var/log/firewalld",           "label":"FirewallD Log",             "service":"firewalld","priority":"high","format":"syslog", "reason":"Firewall events on RHEL/CentOS"},
    {"path":"/var/log/fail2ban.log",        "label":"Fail2ban Log",              "service":"fail2ban","priority":"medium","format":"syslog","reason":"Banned IPs, brute-force events"},
    {"path":"/var/log/apache2/access.log",  "label":"Apache Access Log",         "service":"apache2","priority":"medium","format":"apache", "reason":"HTTP requests — detect web attacks"},
    {"path":"/var/log/apache2/error.log",   "label":"Apache Error Log",          "service":"apache2","priority":"medium","format":"apache", "reason":"Apache errors"},
    {"path":"/var/log/httpd/access_log",    "label":"Apache Access (RHEL)",      "service":"httpd","priority":"medium","format":"apache",   "reason":"HTTP requests on RHEL/CentOS"},
    {"path":"/var/log/nginx/access.log",    "label":"Nginx Access Log",          "service":"nginx","priority":"medium","format":"syslog",    "reason":"HTTP requests — detect web attacks"},
    {"path":"/var/log/nginx/error.log",     "label":"Nginx Error Log",           "service":"nginx","priority":"medium","format":"syslog",    "reason":"Nginx errors"},
    {"path":"/var/log/mysql/error.log",     "label":"MySQL Error Log",           "service":"mysql","priority":"medium","format":"syslog","reason":"MySQL auth failures"},
    {"path":"/var/log/postgresql/postgresql-*.log","label":"PostgreSQL Log","service":"postgresql","priority":"medium","format":"syslog",  "reason":"PostgreSQL auth and errors"},
    {"path":"/var/log/mongodb/mongod.log",  "label":"MongoDB Log",               "service":"mongodb","priority":"medium","format":"syslog",  "reason":"MongoDB auth events"},
    {"path":"/var/log/dpkg.log",            "label":"Package Manager (dpkg)",    "service":"dpkg","priority":"medium","format":"syslog",   "reason":"Package installs/removals"},
    {"path":"/var/log/yum.log",             "label":"Package Manager (yum)",     "service":"yum","priority":"medium","format":"syslog",    "reason":"Package changes on RHEL/CentOS"},
    {"path":"/var/log/dnf.log",             "label":"Package Manager (dnf)",     "service":"dnf","priority":"medium","format":"syslog",    "reason":"Package changes on Fedora/RHEL8+"},
    {"path":"/var/log/cron.log",            "label":"Cron Log",                  "service":"cron","priority":"medium","format":"syslog",   "reason":"Cron jobs — detect persistence"},
    {"path":"/var/log/cron",                "label":"Cron Log (RHEL)",           "service":"cron","priority":"medium","format":"syslog",   "reason":"Cron jobs on RHEL/CentOS"},
    {"path":"/var/log/mail.log",            "label":"Mail Log",                  "service":"postfix","priority":"low","format":"syslog",   "reason":"Mail delivery events"},
]

def get_active_services():
    try:
        out = subprocess.check_output(
            ["systemctl","list-units","--type=service","--state=active","--no-pager","--plain","--no-legend"],
            stderr=subprocess.DEVNULL, text=True)
        return {l.split()[0].replace(".service","") for l in out.splitlines() if l.strip()}
    except: return set()

def get_installed_packages():
    pkgs = set()
    for cmd in [["dpkg","--get-selections"],["rpm","-qa","--qf","%{NAME}\n"]]:
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
            pkgs.update(l.split()[0] for l in out.splitlines() if l.strip())
        except: continue
    return pkgs

def discover_logs(svcs, pkgs):
    results = []
    for entry in LOG_CATALOGUE:
        path    = entry["path"]
        matches = [p for p in glob.glob(path) if os.path.isfile(p)]
        if not matches and os.path.isfile(path): matches = [path]
        if matches:
            results.append({"entry":entry,"found_paths":matches,"source":"file"}); continue
        svc = entry["service"].split("/")[0]
        if svc in svcs or svc in pkgs:
            results.append({"entry":entry,"found_paths":[path],"source":"service"})
    results.sort(key=lambda r: PRIORITY_ORDER[r["entry"]["priority"]])
    return results

def scan_custom_logs():
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
                except: continue
    return sorted(custom)

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

def clear(): sys.stdout.write("\033[2J\033[H"); sys.stdout.flush()

def restore_perms():
    """Restore correct Wazuh file ownership and permissions."""
    try:
        subprocess.run(["chown", "root:wazuh", AGENT_CONF], capture_output=True)
        os.chmod(AGENT_CONF, 0o660)
    except Exception:
        pass

def heal_conf():
    if not os.path.exists(AGENT_CONF): return
    with open(AGENT_CONF) as f: content = f.read()
    def fix(m):
        fmt = m.group(1).strip()
        return f"<log_format>{fmt if fmt in VALID_FORMATS else 'syslog'}</log_format>"
    fixed = re.sub(r"<log_format>(.*?)</log_format>", fix, content)
    # Only normalise closing tag if count is wrong
    # Do NOT normalize </ossec_config> count - Wazuh uses multiple blocks
    if fixed != content:
        shutil.copy2(AGENT_CONF, AGENT_CONF+".bak")
        with open(AGENT_CONF,"w") as f: f.write(fixed)
        restore_perms()
        print(f"{GREEN}  ✔ Auto-fixed invalid log formats in ossec.conf.{RESET}")

def inject_into_conf(selected):
    if not os.path.exists(AGENT_CONF):
        print(f"{YELLOW}  Agent config not found. Skipping.{RESET}"); return
    heal_conf()
    with open(AGENT_CONF) as f: conf = f.read()
    start_tag = "<!-- CodeRed Discovered Logs -->"
    end_tag   = "<!-- END:discovered-logs -->"
    s, e = conf.find(start_tag), conf.find(end_tag)
    if s != -1 and e != -1: conf = conf[:s] + conf[e+len(end_tag):]
    lines = [f"  {start_tag}"]
    fixed = 0
    for item in selected:
        fmt = item["format"] if item["format"] in VALID_FORMATS else "syslog"
        if fmt != item["format"]: fixed += 1
        lines.append(f"  <localfile>\n    <log_format>{fmt}</log_format>\n    <location>{item['path']}</location>\n  </localfile>")
    lines.append(f"  {end_tag}")
    block = "\n".join(lines)
    # Insert block before the closing tag (replace first occurrence only)
    idx = conf.rfind("</ossec_config>")
    if idx != -1:
        conf = conf[:idx] + block + "\n</ossec_config>" + conf[idx+len("</ossec_config>"):]
    else:
        conf = conf.rstrip() + "\n" + block + "\n</ossec_config>\n"
    if fixed: print(f"{YELLOW}  ⚠ {fixed} format(s) normalised to 'syslog'.{RESET}")
    shutil.copy2(AGENT_CONF, AGENT_CONF+".bak")
    with open(AGENT_CONF,"w") as f: f.write(conf)
    restore_perms()
    print(f"{GREEN}  ✔ Config updated.{RESET}")

def present_ui(discovered, custom_logs):
    items = []
    for r in discovered:
        for path in r["found_paths"]:
            items.append({"path":path,"label":r["entry"]["label"],"priority":r["entry"]["priority"],
                          "format":r["entry"]["format"],"reason":r["entry"]["reason"],
                          "source":r["source"],"selected":PRIORITY_DEFAULT[r["entry"]["priority"]]})
    for path in custom_logs:
        items.append({"path":path,"label":os.path.basename(path),"priority":"low",
                      "format":"syslog","reason":"Custom log detected","source":"file","selected":False})
    if not items: print(f"{YELLOW}  No logs found.{RESET}"); return []

    cursor = 0; vs = 0

    def render():
        nonlocal vs
        try: rows = os.get_terminal_size().lines
        except: rows = 24
        vp = max(3, rows - 8)
        if cursor < vs: vs = cursor
        elif cursor >= vs + vp: vs = cursor - vp + 1
        ve = min(vs + vp, len(items))
        clear()
        sys.stdout.write(f"\n{CYAN}{BOLD}  CodeRed Log Discovery{RESET}\n")
        sys.stdout.write(f"  {DIM}↑↓ move · Space toggle · A all · N none · Enter confirm · Q cancel{RESET}\n")
        if len(items) > vp:
            sys.stdout.write(f"  {DIM}Showing {vs+1}–{ve} of {len(items)}{RESET}\n")
        prev_pri = None
        for i in range(vs, ve):
            item = items[i]
            if item["priority"] != prev_pri:
                prev_pri = item["priority"]
                sys.stdout.write(f"\n  {PRIORITY_LABELS[item['priority']]}\n\n")
            tick  = f"{GREEN}✔{RESET}" if item["selected"] else f"{RED}✖{RESET}"
            arrow = f"{CYAN}▶{RESET}" if i == cursor else " "
            src   = f"{DIM}(service){RESET}" if item["source"]=="service" else ""
            hi    = BOLD if i == cursor else ""
            sys.stdout.write(f"  {arrow} [{tick}] {hi}{item['path']}{RESET} {src}\n")
            if i == cursor: sys.stdout.write(f"       {DIM}{item['reason']}{RESET}\n")
        sel = sum(1 for it in items if it["selected"])
        sys.stdout.write(f"\n  {CYAN}{'─'*54}{RESET}\n  {sel} of {len(items)} selected\n")
        sys.stdout.flush()

    render()
    while True:
        ch = getch()
        if   ch=="UP"   and cursor>0:             cursor-=1
        elif ch=="DOWN" and cursor<len(items)-1:  cursor+=1
        elif ch==" ":   items[cursor]["selected"] = not items[cursor]["selected"]
        elif ch.lower()=="a":
            for it in items: it["selected"]=True
        elif ch.lower()=="n":
            for it in items: it["selected"]=False
        elif ch in("\r","\n"): break
        elif ch=="q": return []
        render()
    return [it for it in items if it["selected"]]

def run_discovery(auto_apply=False):
    print(f"\n{CYAN}{BOLD}  CodeRed Log Discovery — Linux{RESET}")
    print(f"  Scanning endpoint...\n")
    svcs  = get_active_services()
    pkgs  = get_installed_packages()
    disc  = discover_logs(svcs, pkgs)
    cust  = scan_custom_logs()
    print(f"  {GREEN}✔{RESET} Active services  : {len(svcs)}")
    print(f"  {GREEN}✔{RESET} Packages         : {len(pkgs)}")
    print(f"  {GREEN}✔{RESET} Known logs found : {len(disc)}")
    print(f"  {GREEN}✔{RESET} Custom logs      : {len(cust)}\n")
    input(f"  Press {BOLD}Enter{RESET} to review...")
    selected = present_ui(disc, cust)
    if not selected:
        print(f"\n{YELLOW}  Nothing selected. No changes.{RESET}\n"); return
    print(f"\n{CYAN}  Applying {len(selected)} log source(s)...{RESET}")
    inject_into_conf(selected)
    if not auto_apply:
        ans = input(f"\n  Restart agent now? (y/N): ").strip().lower()
        auto_apply = ans == "y"
    if auto_apply:
        try:
            subprocess.run(["systemctl","restart","wazuh-agent"], check=True)
            print(f"{GREEN}  ✔ Agent restarted.{RESET}")
        except Exception as e:
            print(f"{YELLOW}  Could not restart: {e}{RESET}")
    print(f"\n{GREEN}{BOLD}  Log discovery complete!{RESET}\n")

if __name__=="__main__":
    if os.geteuid()!=0: print(f"{RED}Please run as root.{RESET}"); sys.exit(1)
    run_discovery()

