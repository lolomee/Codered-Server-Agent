#!/usr/bin/env python3
"""
CodeRed Server Agent — Windows CLI
"""
import os, sys, re, shutil, subprocess, argparse, json, importlib.util
import xml.etree.ElementTree as ET

# ── Paths ─────────────────────────────────────────────────────────────────────
_BASE         = os.path.dirname(os.path.abspath(__file__))
STATE_FILE    = os.path.join(_BASE, "state.json")
TEMPLATES_DIR = os.path.join(_BASE, "templates", "windows")
DISCOVER_PATH = os.path.join(_BASE, "codered-discover.py")

# Detect ossec.conf
def find_agent_conf():
    candidates = [
        r"C:\Program Files (x86)\ossec-agent\ossec.conf",
        r"C:\Program Files\ossec-agent\ossec.conf",
    ]
    try:
        import winreg
        for root in [winreg.HKEY_LOCAL_MACHINE]:
            for kp in [r"SOFTWARE\WOW6432Node\Ossec", r"SOFTWARE\Ossec",
                       r"SOFTWARE\WOW6432Node\Wazuh", r"SOFTWARE\Wazuh"]:
                try:
                    key  = winreg.OpenKey(root, kp)
                    path = winreg.QueryValueEx(key, "InstallLocation")[0]
                    conf = os.path.join(path, "ossec.conf")
                    if os.path.exists(conf): return conf
                except: continue
    except: pass
    for c in candidates:
        if os.path.exists(c): return c
    return candidates[0]

AGENT_CONF = find_agent_conf()

# ── Colours ───────────────────────────────────────────────────────────────────
RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

# ── Valid log formats (Windows Wazuh agent) ───────────────────────────────────
VALID_FORMATS = {"eventchannel","eventlog","syslog","iis","command","full_command"}

# ── Modules ───────────────────────────────────────────────────────────────────
MODULES = {
    "log-collection": {"label":"Log Collection",          "desc":"Collect Windows Event Logs",                          "template":"log-collection.xml","tag":"<!-- MODULE:log-collection -->"},
    "fim":            {"label":"File Integrity Monitoring","desc":"Detect file changes with SHA-256 checksums",          "template":"fim.xml",           "tag":"<!-- MODULE:fim -->"},
    "inventory":      {"label":"System Inventory",         "desc":"Collect hardware, OS, packages, processes, ports",    "template":"inventory.xml",     "tag":"<!-- MODULE:inventory -->"},
    "threat":         {"label":"Threat Detection",         "desc":"Rootcheck, WMI/Firewall event monitoring",            "template":"threat.xml",        "tag":"<!-- MODULE:threat -->"},
    "vuln":           {"label":"Vulnerability Detection",  "desc":"Map installed packages to CVEs (NVD + MSU feeds)",    "template":"vuln.xml",          "tag":"<!-- MODULE:vuln -->"},
    "compliance":     {"label":"Compliance & Auditing",    "desc":"CIS Benchmark and custom SCA policy checks",          "template":"compliance.xml",    "tag":"<!-- MODULE:compliance -->"},
    "active-response":{"label":"Active Response",          "desc":"Auto-block IPs, kill processes on alert",             "template":"active-response.xml","tag":"<!-- MODULE:active-response -->"},
}
DEFAULT_ENABLED = ["log-collection","fim","inventory","threat"]

# ── Admin check ───────────────────────────────────────────────────────────────
def is_admin():
    import ctypes
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except: return False

# ── Service name ──────────────────────────────────────────────────────────────
_SVC = None
def get_svc():
    global _SVC
    if _SVC: return _SVC
    for name in ["WazuhSvc","Wazuh","wazuh","OssecSvc"]:
        r = subprocess.run(["sc","query",name], capture_output=True, text=True)
        if r.returncode == 0:
            _SVC = name; return _SVC
    _SVC = "WazuhSvc"; return _SVC

# ── Keyboard input ────────────────────────────────────────────────────────────
def getch():
    import msvcrt
    ch = msvcrt.getwch()
    if ch in('\x00','\xe0'):
        ch2 = msvcrt.getwch()
        if ch2=='H': return "UP"
        if ch2=='P': return "DOWN"
        return ''
    if ch=='\x1b':
        try:
            n1 = msvcrt.getwch()
            if n1=='[':
                n2 = msvcrt.getwch()
                if n2=='A': return "UP"
                if n2=='B': return "DOWN"
        except: pass
        return '\x1b'
    return ch

def clear():
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11),7)
    except: pass
    sys.stdout.write("\033[2J\033[H"); sys.stdout.flush()

def banner(sub=""):
    clear()
    sys.stdout.write(f"{CYAN}{BOLD}\n")
    sys.stdout.write("  ____          _      ____          _\n")
    sys.stdout.write(" / ___|___   __| | ___|  _ \\ ___  __| |\n")
    sys.stdout.write("| |   / _ \\ / _` |/ _ \\ |_) / _ \\/ _` |\n")
    sys.stdout.write("| |__| (_) | (_| |  __/  _ <  __/ (_| |\n")
    sys.stdout.write(" \\____\\___/ \\__,_|\\___|_| \\_\\___|\\__,_|\n")
    sys.stdout.write(f"{RESET}\n")
    if sub: sys.stdout.write(f"  {DIM}{sub}{RESET}\n\n")
    sys.stdout.flush()

# ── State ─────────────────────────────────────────────────────────────────────
def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f: return json.load(f)
    return {"enabled":list(DEFAULT_ENABLED),"manager_ip":""}

def save_state(s):
    with open(STATE_FILE,"w") as f: json.dump(s,f,indent=2)

# ── Config helpers ────────────────────────────────────────────────────────────
def read_conf():
    if not os.path.exists(AGENT_CONF): return ""
    with open(AGENT_CONF,encoding="utf-8",errors="replace") as f: return f.read()

def write_conf(content):
    # Validate formats
    try:
        root = ET.fromstring(content)
        for lf in root.iter("localfile"):
            fmt = lf.find("log_format")
            if fmt is not None and fmt.text and fmt.text.strip() not in VALID_FORMATS:
                print(f"\n{RED}  ✖ Invalid log_format: '{fmt.text.strip()}'{RESET}")
                return False
    except ET.ParseError as e:
        print(f"\n{RED}  ✖ XML error: {e}{RESET}"); return False
    # Normalise closing tag
    content = content.replace("</ossec_config>","").rstrip() + "\n</ossec_config>\n"
    tmp = AGENT_CONF + ".tmp"
    shutil.copy2(AGENT_CONF, AGENT_CONF+".bak")
    with open(tmp,"w",encoding="utf-8") as f: f.write(content)
    shutil.move(tmp, AGENT_CONF)
    return True

def remove_module(mid, conf):
    tag=MODULES[mid]["tag"]; end_tag=f"<!-- END:{mid} -->"
    s,e = conf.find(tag), conf.find(end_tag)
    if s==-1 or e==-1: return conf
    return conf[:s] + conf[e+len(end_tag):]

def inject_module(mid, conf):
    mod  = MODULES[mid]; tag=mod["tag"]
    tmpl = os.path.join(TEMPLATES_DIR, mod["template"])
    if tag in conf: return conf
    if not os.path.exists(tmpl):
        print(f"{YELLOW}  [warn] Template not found: {tmpl}{RESET}"); return conf
    with open(tmpl) as f:
        block = f"\n  {tag}\n{f.read()}\n  <!-- END:{mid} -->\n"
    conf = conf.replace("</ossec_config>","").rstrip()
    return conf + block + "\n</ossec_config>\n"

def apply_state(state):
    conf = read_conf()
    if not conf: print(f"{YELLOW}  Config not found: {AGENT_CONF}{RESET}"); return False
    for mid in MODULES: conf = remove_module(mid, conf)
    for mid in state["enabled"]: conf = inject_module(mid, conf)
    return write_conf(conf)

# ── Service ───────────────────────────────────────────────────────────────────
def svc_status():
    r = subprocess.run(["sc","query",get_svc()], capture_output=True, text=True)
    return "active" if "RUNNING" in r.stdout else "inactive"

def restart_agent():
    svc = get_svc()
    print(f"\n{CYAN}  Restarting CodeRed Agent (service: {svc})...{RESET}")
    subprocess.run(["sc","stop",svc], capture_output=True)
    import time; time.sleep(2)
    r = subprocess.run(["sc","start",svc], capture_output=True, text=True)
    if r.returncode==0: print(f"{GREEN}  ✔ Agent restarted.{RESET}")
    else: print(f"{YELLOW}  ⚠ Check Agent Status to confirm.{RESET}")

# ── Viewport ──────────────────────────────────────────────────────────────────
def viewport(reserved=10):
    try: rows = os.get_terminal_size().lines
    except: rows = 24
    return max(3, rows-reserved)

# ── Main Menu ─────────────────────────────────────────────────────────────────
MENU = [
    ("scan",      "Scan Log Directories","Discover logs and choose which to monitor"),
    ("setup",     "Module Setup",        "Enable or disable monitoring modules"),
    ("status",    "Agent Status",        "View service status and active modules"),
    ("settings",  "Agent Settings",      "Configure manager IP and connection"),
    ("uninstall", "Uninstall Agent",     "Remove CodeRed Server Agent from this system"),
    ("exit",      "Exit",""),
]

def show_main_menu():
    cursor=0
    while True:
        banner("Management Console")
        svc=svc_status(); col=GREEN if svc=="active" else RED
        sys.stdout.write(f"  Agent Service : {col}{BOLD}{svc}{RESET}\n")
        sys.stdout.write(f"  Config        : {DIM}{AGENT_CONF}{RESET}\n\n")
        sys.stdout.write(f"  {DIM}↑↓ move · Enter select · 1-5 shortcut{RESET}\n\n")
        for i,(key,label,desc) in enumerate(MENU):
            arrow=f"{CYAN}▶{RESET}" if i==cursor else " "
            num  =f"{DIM}[0]{RESET}" if key=="exit" else f"{CYAN}[{i+1}]{RESET}"
            hi   =BOLD if i==cursor else ""
            sys.stdout.write(f"  {arrow} {num} {hi}{label}{RESET}\n")
            if desc and i==cursor: sys.stdout.write(f"       {DIM}{desc}{RESET}\n")
            sys.stdout.write("\n")
        sys.stdout.flush()
        ch=getch()
        if   ch=="UP"   and cursor>0:           cursor-=1
        elif ch=="DOWN" and cursor<len(MENU)-1: cursor+=1
        elif ch in("\r","\n"):
            k=MENU[cursor][0]
            if   k=="exit":      clear(); sys.exit(0)
            elif k=="scan":      menu_scan()
            elif k=="setup":     menu_setup()
            elif k=="status":    menu_status()
            elif k=="settings":  menu_settings()
            elif k=="uninstall": menu_uninstall()
        elif ch=="1": menu_scan()
        elif ch=="2": menu_setup()
        elif ch=="3": menu_status()
        elif ch=="4": menu_settings()
        elif ch=="5": menu_uninstall()
        elif ch in("0","q"): clear(); sys.exit(0)

def menu_scan():
    try:
        if not os.path.exists(DISCOVER_PATH):
            banner("Scan Log Directories")
            sys.stdout.write(f"{RED}  codered-discover.py not found:\n  {DISCOVER_PATH}{RESET}\n\n")
            input("  Press Enter to return..."); return
        spec=importlib.util.spec_from_file_location("discover",DISCOVER_PATH)
        mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        mod.run_discovery()
        input(f"\n  Press {BOLD}Enter{RESET} to return...")
    except KeyboardInterrupt:
        sys.stdout.write(f"\n{YELLOW}  Cancelled.{RESET}\n")

def menu_setup():
    state=load_state(); enabled=set(state["enabled"]); keys=list(MODULES.keys())
    cursor=0; vs=0
    def render():
        nonlocal vs
        vp=viewport(8)
        if cursor<vs: vs=cursor
        elif cursor>=vs+vp: vs=cursor-vp+1
        ve=min(vs+vp,len(keys))
        banner("Module Setup")
        sys.stdout.write(f"  {DIM}↑↓ · Space toggle · A all · N none · Enter save · Q back{RESET}\n\n")
        for i in range(vs,ve):
            mid=keys[i]; mod=MODULES[mid]
            tick=f"{GREEN}✔{RESET}" if mid in enabled else f"{RED}✖{RESET}"
            arrow=f"{CYAN}▶{RESET}" if i==cursor else " "
            hi=BOLD if i==cursor else ""
            sys.stdout.write(f"  {arrow} [{tick}] {hi}{mod['label']}{RESET}\n")
            if i==cursor: sys.stdout.write(f"       {DIM}{mod['desc']}{RESET}\n")
        sys.stdout.write(f"\n  {DIM}──────────────────────────{RESET}\n  {len(enabled)} module(s) enabled\n")
        sys.stdout.flush()
    render()
    while True:
        ch=getch()
        if   ch=="UP"   and cursor>0:           cursor-=1
        elif ch=="DOWN" and cursor<len(keys)-1: cursor+=1
        elif ch==" ":
            mid=keys[cursor]
            if mid in enabled: enabled.discard(mid)
            else: enabled.add(mid)
        elif ch.lower()=="a": enabled=set(keys)
        elif ch.lower()=="n": enabled=set()
        elif ch in("\r","\n"):
            state["enabled"]=list(enabled); save_state(state)
            sys.stdout.write(f"\n{CYAN}  Applying...{RESET}\n")
            if apply_state(state): restart_agent()
            input(f"\n  Press {BOLD}Enter{RESET} to return..."); return
        elif ch.lower()=="q": return
        render()

def menu_status():
    banner("Agent Status")
    state=load_state(); enabled=set(state["enabled"])
    svc=svc_status(); col=GREEN if svc=="active" else RED
    sys.stdout.write(f"  Service Status : {col}{BOLD}{svc}{RESET}\n")
    sys.stdout.write(f"  Manager IP     : {CYAN}{state.get('manager_ip','(not set)')}{RESET}\n")
    sys.stdout.write(f"  Config File    : {DIM}{AGENT_CONF}{RESET}\n\n")
    sys.stdout.write(f"  {BOLD}{'Module':<30} Status{RESET}\n  {'─'*44}\n")
    for mid,mod in MODULES.items():
        st=f"{GREEN}enabled{RESET}" if mid in enabled else f"{RED}disabled{RESET}"
        sys.stdout.write(f"  {mod['label']:<30} {st}\n")
    sys.stdout.write("\n"); sys.stdout.flush()
    input(f"  Press {BOLD}Enter{RESET} to return...")

def menu_settings():
    while True:
        banner("Agent Settings")
        state=load_state()
        sys.stdout.write(f"  Manager IP  : {CYAN}{state.get('manager_ip','(not set)')}{RESET}\n")
        sys.stdout.write(f"  Config File : {DIM}{AGENT_CONF}{RESET}\n\n")
        sys.stdout.write(f"  {CYAN}[1]{RESET} Change Manager IP\n  {CYAN}[2]{RESET} Test connection\n  {CYAN}[3]{RESET} Restart Agent\n  {DIM}[0]{RESET} Back\n\n")
        sys.stdout.flush()
        ch=input("  Select: ").strip()
        if ch=="1":
            ip=input("\n  Enter Manager IP or hostname: ").strip()
            if ip:
                state["manager_ip"]=ip; save_state(state)
                conf=read_conf()
                if conf:
                    conf=re.sub(r"<address>.*?</address>",f"<address>{ip}</address>",conf)
                    if write_conf(conf):
                        print(f"\n{GREEN}  ✔ Manager IP updated: {ip}{RESET}"); restart_agent()
            input(f"\n  Press {BOLD}Enter{RESET} to continue...")
        elif ch=="2":
            ip=state.get("manager_ip","")
            if not ip: print(f"\n{RED}  No Manager IP set.{RESET}")
            else:
                print(f"\n  Testing {CYAN}{ip}:1514{RESET}...")
                try:
                    import socket; s=socket.create_connection((ip,1514),timeout=5); s.close()
                    print(f"{GREEN}  ✔ Manager is reachable.{RESET}")
                except Exception as e: print(f"{RED}  ✖ {e}{RESET}")
            input(f"\n  Press {BOLD}Enter{RESET} to continue...")
        elif ch=="3":
            if apply_state(load_state()): restart_agent()
            input(f"\n  Press {BOLD}Enter{RESET} to continue...")
        elif ch=="0": return

def menu_uninstall():
    banner("Uninstall Agent")
    sys.stdout.write(f"  {YELLOW}{BOLD}Warning: This will remove CodeRed Server Agent.{RESET}\n\n")
    sys.stdout.write(f"    {RED}•{RESET} Agent service\n    {RED}•{RESET} C:\\Program Files\\CodeRed\\\n\n")
    sys.stdout.flush()
    confirm=input(f"  Type {BOLD}UNINSTALL{RESET} to confirm: ").strip()
    if confirm!="UNINSTALL":
        print(f"\n{YELLOW}  Cancelled.{RESET}"); input(f"  Press {BOLD}Enter{RESET} to return..."); return
    svc=get_svc()
    subprocess.run(["sc","stop",svc], capture_output=True)
    subprocess.run('wmic product where "name like \'%Wazuh%\'" call uninstall /nointeractive',
                   shell=True, capture_output=True)
    shutil.rmtree(r"C:\Program Files\CodeRed", ignore_errors=True)
    print(f"\n{GREEN}{BOLD}  ✔ CodeRed Server Agent removed.{RESET}\n"); sys.exit(0)

def cmd_enable(mod):
    state=load_state()
    if mod in state["enabled"]: print(f"{YELLOW}{MODULES[mod]['label']} already enabled.{RESET}"); return
    state["enabled"].append(mod); save_state(state)
    if apply_state(state): restart_agent(); print(f"{GREEN}✔ Enabled: {MODULES[mod]['label']}{RESET}")

def cmd_disable(mod):
    state=load_state()
    if mod not in state["enabled"]: print(f"{YELLOW}{MODULES[mod]['label']} already disabled.{RESET}"); return
    state["enabled"].remove(mod); save_state(state)
    if apply_state(state): restart_agent(); print(f"{GREEN}✔ Disabled: {MODULES[mod]['label']}{RESET}")

def main():
    if not is_admin():
        print(f"{RED}Please run as Administrator.{RESET}"); sys.exit(1)
    p=argparse.ArgumentParser(prog="codered-agent",description="CodeRed Server Agent — Windows CLI")
    s=p.add_subparsers(dest="cmd")
    s.add_parser("scan"); s.add_parser("setup"); s.add_parser("status")
    s.add_parser("settings"); s.add_parser("uninstall"); s.add_parser("restart")
    pe=s.add_parser("enable");  pe.add_argument("module",choices=MODULES.keys())
    pd=s.add_parser("disable"); pd.add_argument("module",choices=MODULES.keys())
    args=p.parse_args()
    dispatch={"scan":menu_scan,"setup":menu_setup,"status":menu_status,
              "settings":menu_settings,"uninstall":menu_uninstall,
              "restart":lambda:(apply_state(load_state()) and restart_agent())}
    if args.cmd in dispatch: dispatch[args.cmd](); return
    if args.cmd=="enable":  cmd_enable(args.module); return
    if args.cmd=="disable": cmd_disable(args.module); return
    try: show_main_menu()
    except KeyboardInterrupt: clear(); print(f"  {DIM}Goodbye.{RESET}\n"); sys.exit(0)

if __name__=="__main__": main()
