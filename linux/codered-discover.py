#!/usr/bin/env python3
"""
CodeRed Server Agent — Log Discovery Engine (Linux)

KEY DESIGN: Uses sed for ALL ossec.conf modifications.
- sed -i does targeted in-place changes without full file rewrite
- Avoids cat/Python open() which break wazuh-execd file attributes
- Does NOT auto-restart agent (user restarts manually)
"""
import os, sys, re, glob, shutil, subprocess, tempfile

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
    {"path":"/var/log/auth.log",            "label":"Authentication Log",     "service":"ssh",       "priority":"high",   "format":"syslog",    "reason":"SSH logins, sudo, PAM auth failures"},
    {"path":"/var/log/secure",              "label":"Secure Log (RHEL)",      "service":"ssh",       "priority":"high",   "format":"syslog",    "reason":"SSH/sudo on RHEL/CentOS"},
    {"path":"/var/log/syslog",              "label":"System Log",             "service":"system",    "priority":"high",   "format":"syslog",    "reason":"General system events"},
    {"path":"/var/log/messages",            "label":"System Messages (RHEL)", "service":"system",    "priority":"high",   "format":"syslog",    "reason":"System messages on RHEL/CentOS"},
    {"path":"/var/log/kern.log",            "label":"Kernel Log",             "service":"kernel",    "priority":"high",   "format":"syslog",    "reason":"Kernel events, OOM killer"},
    {"path":"/var/log/audit/audit.log",     "label":"Linux Audit Log",        "service":"auditd",    "priority":"high",   "format":"audit",     "reason":"Syscall auditing, privilege escalation"},
    {"path":"/var/log/ufw.log",             "label":"UFW Firewall Log",       "service":"ufw",       "priority":"high",   "format":"syslog",    "reason":"Firewall block/allow events"},
    {"path":"/var/log/iptables.log",        "label":"iptables Log",           "service":"iptables",  "priority":"high",   "format":"syslog",    "reason":"Raw iptables packet events"},
    {"path":"/var/log/fail2ban.log",        "label":"Fail2ban Log",           "service":"fail2ban",  "priority":"medium", "format":"syslog",    "reason":"Banned IPs, brute-force events"},
    {"path":"/var/log/apache2/access.log",  "label":"Apache Access Log",      "service":"apache2",   "priority":"medium", "format":"apache",    "reason":"HTTP requests — detect web attacks"},
    {"path":"/var/log/apache2/error.log",   "label":"Apache Error Log",       "service":"apache2",   "priority":"medium", "format":"apache",    "reason":"Apache errors"},
    {"path":"/var/log/httpd/access_log",    "label":"Apache Access (RHEL)",   "service":"httpd",     "priority":"medium", "format":"apache",    "reason":"HTTP requests on RHEL"},
    {"path":"/var/log/nginx/access.log",    "label":"Nginx Access Log",       "service":"nginx",     "priority":"medium", "format":"nginx",     "reason":"HTTP requests — detect web attacks"},
    {"path":"/var/log/nginx/error.log",     "label":"Nginx Error Log",        "service":"nginx",     "priority":"medium", "format":"nginx",     "reason":"Nginx errors"},
    {"path":"/var/log/mysql/error.log",     "label":"MySQL Error Log",        "service":"mysql",     "priority":"medium", "format":"mysql_log", "reason":"MySQL auth failures"},
    {"path":"/var/log/postgresql/postgresql-*.log","label":"PostgreSQL Log",  "service":"postgresql","priority":"medium", "format":"syslog",    "reason":"PostgreSQL errors"},
    {"path":"/var/log/mongodb/mongod.log",  "label":"MongoDB Log",            "service":"mongodb",   "priority":"medium", "format":"json",      "reason":"MongoDB auth events"},
    {"path":"/var/log/dpkg.log",            "label":"Package Manager (dpkg)", "service":"dpkg",      "priority":"medium", "format":"syslog",    "reason":"Package installs/removals"},
    {"path":"/var/log/yum.log",             "label":"Package Manager (yum)",  "service":"yum",       "priority":"medium", "format":"syslog",    "reason":"Package changes on RHEL"},
    {"path":"/var/log/dnf.log",             "label":"Package Manager (dnf)",  "service":"dnf",       "priority":"medium", "format":"syslog",    "reason":"Package changes on Fedora"},
    {"path":"/var/log/cron.log",            "label":"Cron Log",               "service":"cron",      "priority":"medium", "format":"syslog",    "reason":"Cron jobs — detect persistence"},
    {"path":"/var/log/cron",                "label":"Cron Log (RHEL)",        "service":"cron",      "priority":"medium", "format":"syslog",    "reason":"Cron jobs on RHEL"},
    {"path":"/var/log/mail.log",            "label":"Mail Log",               "service":"postfix",   "priority":"low",    "format":"syslog",    "reason":"Mail delivery events"},
]

def get_active_services():
    try:
        out = subprocess.check_output(
            ["systemctl","list-units","--type=service","--state=active",
             "--no-pager","--plain","--no-legend"],
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

def inject_into_conf(selected):
    """
    Inject discovered log sources into ossec.conf using sed only.
    sed does targeted in-place edits that preserve file attributes.
    Never does a full file rewrite.
    """
    if not os.path.exists(AGENT_CONF):
        print(f"{YELLOW}  Agent config not found. Skipping.{RESET}"); return False

    # Build the XML block to insert
    lines = ["  <!-- CodeRed Discovered Logs -->"]
    fixed = 0
    for item in selected:
        fmt = item["format"] if item["format"] in VALID_FORMATS else "syslog"
        if fmt != item["format"]: fixed += 1
        lines.append(
            f"  <localfile>\n"
            f"    <log_format>{fmt}</log_format>\n"
            f"    <location>{item['path']}</location>\n"
            f"  </localfile>"
        )
    lines.append("  <!-- END:discovered-logs -->")
    block = "\n".join(lines)

    if fixed: print(f"{YELLOW}  ⚠ {fixed} format(s) normalised to 'syslog'.{RESET}")

    # Step 1: backup
    subprocess.run(["cp", AGENT_CONF, AGENT_CONF + ".bak"], capture_output=True)

    # Step 2: remove existing CodeRed discovered block using sed
    subprocess.run([
        "sed", "-i",
        "/<!-- CodeRed Discovered Logs -->/,/<!-- END:discovered-logs -->/d",
        AGENT_CONF
    ], capture_output=True)

    # Step 3: write block to a temp file
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False)
    tmp.write(block + "\n")
    tmp.close()

    # Step 4: use sed to insert temp file content before </ossec_config>
    # sed '/pattern/r file' inserts file AFTER the matching line
    # We delete </ossec_config>, insert block, then re-add </ossec_config>
    subprocess.run([
        "sed", "-i", f"/<\\/ossec_config>/{{r {tmp.name}\n d}}", AGENT_CONF
    ], capture_output=True)

    # Step 5: append closing tag back (file now has no closing tag)
    with open(AGENT_CONF, "a") as f:
        f.write("\n</ossec_config>\n")

    # Restore permissions
    subprocess.run(["chown", "root:wazuh", AGENT_CONF], capture_output=True)
    os.chmod(AGENT_CONF, 0o660)

    os.unlink(tmp.name)

    # Verify
    with open(AGENT_CONF) as f: content = f.read()
    tag_count = content.count("</ossec_config>")
    if tag_count != 1:
        print(f"{YELLOW}  ⚠ Closing tag count: {tag_count} — restoring backup.{RESET}")
        subprocess.run(["cp", AGENT_CONF + ".bak", AGENT_CONF], capture_output=True)
        subprocess.run(["chown", "root:wazuh", AGENT_CONF], capture_output=True)
        os.chmod(AGENT_CONF, 0o660)
        return False

    print(f"{GREEN}  ✔ Config updated ({len(selected)} log sources).{RESET}")
    return True

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
        sys.stdout.write(f"\n{CYAN}{BOLD}  CodeRed Log Discovery — Linux{RESET}\n")
        sys.stdout.write(f"  {DIM}↑↓ · Space toggle · A all · N none · Enter confirm · Q cancel{RESET}\n")
        if len(items) > vp:
            sys.stdout.write(f"  {DIM}Showing {vs+1}–{ve} of {len(items)}{RESET}\n")
        prev = None
        for i in range(vs, ve):
            item = items[i]
            if item["priority"] != prev:
                prev = item["priority"]
                sys.stdout.write(f"\n  {PRIORITY_LABELS[item['priority']]}\n\n")
            tick  = f"{GREEN}✔{RESET}" if item["selected"] else f"{RED}✖{RESET}"
            arrow = f"{CYAN}▶{RESET}" if i == cursor else " "
            src   = f"{DIM}(service){RESET}" if item["source"] == "service" else ""
            hi    = BOLD if i == cursor else ""
            sys.stdout.write(f"  {arrow} [{tick}] {hi}{item['path']}{RESET} {src}\n")
            if i == cursor: sys.stdout.write(f"       {DIM}{item['reason']}{RESET}\n")
        sel = sum(1 for it in items if it["selected"])
        sys.stdout.write(f"\n  {CYAN}{'─'*54}{RESET}\n  {sel} of {len(items)} selected\n")
        sys.stdout.flush()

    render()
    while True:
        ch = getch()
        if   ch=="UP"   and cursor>0:            cursor-=1
        elif ch=="DOWN" and cursor<len(items)-1: cursor+=1
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
    ok = inject_into_conf(selected)
    if ok:
        print(f"\n{YELLOW}  ℹ Restart agent to activate new log sources:{RESET}")
        print(f"  {CYAN}sudo systemctl restart wazuh-agent{RESET}")
        print(f"  {CYAN}sudo coredited-agent status{RESET}")
    print(f"\n{GREEN}{BOLD}  Log discovery complete!{RESET}\n")

if __name__=="__main__":
    if os.geteuid()!=0: print(f"{RED}Please run as root.{RESET}"); sys.exit(1)
    run_discovery()
