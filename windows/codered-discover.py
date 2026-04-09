#!/usr/bin/env python3
"""
CodeRed Server Agent — Log Discovery Engine (Windows)
"""
import os, sys, re, glob, shutil, subprocess, xml.etree.ElementTree as ET

_BASE      = os.path.dirname(os.path.abspath(__file__))
AGENT_CONF = r"C:\Program Files (x86)\ossec-agent\ossec.conf"

# Try to detect actual install path
def find_agent_conf():
    candidates = [
        r"C:\Program Files (x86)\ossec-agent\ossec.conf",
        r"C:\Program Files\ossec-agent\ossec.conf",
    ]
    try:
        import winreg
        for kp in [r"SOFTWARE\WOW6432Node\Ossec", r"SOFTWARE\Ossec",
                   r"SOFTWARE\WOW6432Node\Wazuh", r"SOFTWARE\Wazuh"]:
            try:
                key  = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, kp)
                path = winreg.QueryValueEx(key, "InstallLocation")[0]
                conf = os.path.join(path, "ossec.conf")
                if os.path.exists(conf): return conf
            except: continue
    except: pass
    for c in candidates:
        if os.path.exists(c): return c
    return candidates[0]

AGENT_CONF = find_agent_conf()

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
CYAN="\033[96m"; BOLD="\033[1m"; DIM="\033[2m"; RESET="\033[0m"

PRIORITY_ORDER   = {"high":0,"medium":1,"low":2}
PRIORITY_LABELS  = {"high":f"{RED}🔴 HIGH PRIORITY{RESET}","medium":f"{YELLOW}🟡 MEDIUM PRIORITY{RESET}","low":f"{DIM}🟢 LOW PRIORITY{RESET}"}
PRIORITY_DEFAULT = {"high":True,"medium":True,"low":False}

VALID_FORMATS = {"eventchannel","eventlog","syslog","iis","command","full_command"}

WIN_CATALOGUE = [
    {"path":"Security",                                                             "label":"Security Event Log",         "service":"eventlog","priority":"high",   "format":"eventchannel","reason":"Logon/logoff, privilege use, account management"},
    {"path":"System",                                                               "label":"System Event Log",           "service":"eventlog","priority":"high",   "format":"eventchannel","reason":"Service crashes, driver errors, system events"},
    {"path":"Microsoft-Windows-PowerShell/Operational",                            "label":"PowerShell Operational",     "service":"eventlog","priority":"high",   "format":"eventchannel","reason":"PowerShell execution — detect malicious scripts"},
    {"path":"Microsoft-Windows-Sysmon/Operational",                                "label":"Sysmon Operational",         "service":"Sysmon",  "priority":"high",   "format":"eventchannel","reason":"Process creation, network connections (requires Sysmon)"},
    {"path":"Microsoft-Windows-Windows Defender/Operational",                      "label":"Windows Defender",           "service":"WinDefend","priority":"high",  "format":"eventchannel","reason":"Malware detections and quarantine events"},
    {"path":"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",  "label":"RDP Session Log",            "service":"eventlog","priority":"high",   "format":"eventchannel","reason":"RDP logon/logoff — detect remote access"},
    {"path":"Microsoft-Windows-Firewall With Advanced Security/Firewall",          "label":"Windows Firewall",           "service":"eventlog","priority":"high",   "format":"eventchannel","reason":"Firewall rule changes and blocked connections"},
    {"path":"Application",                                                          "label":"Application Event Log",     "service":"eventlog","priority":"medium", "format":"eventchannel","reason":"Application errors and warnings"},
    {"path":"Microsoft-Windows-TaskScheduler/Operational",                         "label":"Task Scheduler",             "service":"eventlog","priority":"medium", "format":"eventchannel","reason":"Scheduled tasks — detect persistence"},
    {"path":"Microsoft-Windows-Bits-Client/Operational",                           "label":"BITS Client",                "service":"eventlog","priority":"medium", "format":"eventchannel","reason":"Background transfers — detect exfiltration"},
    {"path":"Microsoft-Windows-WMI-Activity/Operational",                          "label":"WMI Activity",               "service":"eventlog","priority":"medium", "format":"eventchannel","reason":"WMI activity — detect lateral movement"},
    {"path":"Microsoft-Windows-DNSClient/Operational",                             "label":"DNS Client",                 "service":"eventlog","priority":"medium", "format":"eventchannel","reason":"DNS queries — detect C2 communication"},
    {"path":r"C:\inetpub\logs\LogFiles\W3SVC1\*.log",                             "label":"IIS Web Server Log",         "service":"W3SVC",   "priority":"medium", "format":"iis",         "reason":"IIS HTTP requests — detect web attacks"},
]

def check_event_channel(channel):
    try:
        r = subprocess.run(["wevtutil","gl",channel], capture_output=True, text=True)
        return r.returncode == 0
    except: return False

def check_service(svc):
    try:
        r = subprocess.run(["sc","query",svc], capture_output=True, text=True)
        return r.returncode == 0
    except: return False

def discover_logs():
    results = []
    for entry in WIN_CATALOGUE:
        path = entry["path"]
        fmt  = entry["format"]
        if fmt == "eventchannel":
            svc_ok = check_service(entry["service"]) if entry["service"] != "eventlog" else True
            ch_ok  = check_event_channel(path)
            if ch_ok or svc_ok:
                results.append({"entry":entry,"found_paths":[path],"source":"file" if ch_ok else "service"})
        else:
            matches = [p for p in glob.glob(path) if os.path.isfile(p)]
            if matches:
                results.append({"entry":entry,"found_paths":matches,"source":"file"})
            elif check_service(entry["service"]):
                results.append({"entry":entry,"found_paths":[path],"source":"service"})
    results.sort(key=lambda r: PRIORITY_ORDER[r["entry"]["priority"]])
    return results

def scan_custom_logs():
    custom = []
    for base in [r"C:\inetpub\logs", r"C:\ProgramData"]:
        if not os.path.exists(base): continue
        for root, dirs, files in os.walk(base):
            depth = root.replace(base,"").count(os.sep)
            if depth > 3: dirs.clear(); continue
            for f in files:
                if f.endswith(".log"):
                    full = os.path.join(root, f)
                    try:
                        if os.path.getsize(full) > 0: custom.append(full)
                    except: continue
    return sorted(custom[:30])

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
            n1=msvcrt.getwch()
            if n1=='[':
                n2=msvcrt.getwch()
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

def inject_into_conf(selected):
    if not os.path.exists(AGENT_CONF):
        print(f"{YELLOW}  Agent config not found. Skipping.{RESET}"); return
    with open(AGENT_CONF,encoding="utf-8",errors="replace") as f: conf = f.read()
    start_tag="<!-- CodeRed Discovered Logs -->"; end_tag="<!-- END:discovered-logs -->"
    s,e = conf.find(start_tag), conf.find(end_tag)
    if s!=-1 and e!=-1: conf = conf[:s] + conf[e+len(end_tag):]
    lines=[f"  {start_tag}"]; fixed=0
    for item in selected:
        fmt = item["format"] if item["format"] in VALID_FORMATS else "syslog"
        if fmt != item["format"]: fixed+=1
        lines.append(f"  <localfile>\n    <log_format>{fmt}</log_format>\n    <location>{item['path']}</location>\n  </localfile>")
    lines.append(f"  {end_tag}")
    block = "\n".join(lines)
    conf  = conf.replace("</ossec_config>","").rstrip() + "\n" + block + "\n</ossec_config>\n"
    if fixed: print(f"{YELLOW}  ⚠ {fixed} format(s) normalised to 'syslog'.{RESET}")
    # Validate XML before writing
    try: ET.fromstring(conf)
    except ET.ParseError as e: print(f"{RED}  ✖ XML error: {e}{RESET}"); return
    shutil.copy2(AGENT_CONF, AGENT_CONF+".bak")
    with open(AGENT_CONF,"w",encoding="utf-8") as f: f.write(conf)
    print(f"{GREEN}  ✔ Config updated.{RESET}")

def present_ui(discovered, custom_logs):
    items=[]
    for r in discovered:
        for path in r["found_paths"]:
            items.append({"path":path,"label":r["entry"]["label"],"priority":r["entry"]["priority"],
                          "format":r["entry"]["format"],"reason":r["entry"]["reason"],
                          "source":r["source"],"selected":PRIORITY_DEFAULT[r["entry"]["priority"]]})
    for path in custom_logs:
        items.append({"path":path,"label":os.path.basename(path),"priority":"low",
                      "format":"syslog","reason":"Custom log detected","source":"file","selected":False})
    if not items: print(f"{YELLOW}  No logs found.{RESET}"); return []

    cursor=0; vs=0

    def render():
        nonlocal vs
        try: rows=os.get_terminal_size().lines
        except: rows=24
        vp=max(3,rows-8)
        if cursor<vs: vs=cursor
        elif cursor>=vs+vp: vs=cursor-vp+1
        ve=min(vs+vp,len(items))
        clear()
        sys.stdout.write(f"\n{CYAN}{BOLD}  CodeRed Log Discovery — Windows{RESET}\n")
        sys.stdout.write(f"  {DIM}↑↓ · Space toggle · A all · N none · Enter confirm · Q cancel{RESET}\n")
        if len(items)>vp: sys.stdout.write(f"  {DIM}Showing {vs+1}–{ve} of {len(items)}{RESET}\n")
        prev=None
        for i in range(vs,ve):
            item=items[i]
            if item["priority"]!=prev:
                prev=item["priority"]
                sys.stdout.write(f"\n  {PRIORITY_LABELS[item['priority']]}\n\n")
            tick =f"{GREEN}✔{RESET}" if item["selected"] else f"{RED}✖{RESET}"
            arrow=f"{CYAN}▶{RESET}" if i==cursor else " "
            src  =f"{DIM}(service){RESET}" if item["source"]=="service" else ""
            hi   =BOLD if i==cursor else ""
            sys.stdout.write(f"  {arrow} [{tick}] {hi}{item['path']}{RESET} {src}\n")
            if i==cursor: sys.stdout.write(f"       {DIM}{item['reason']}{RESET}\n")
        sel=sum(1 for it in items if it["selected"])
        sys.stdout.write(f"\n  {CYAN}{'─'*54}{RESET}\n  {sel} of {len(items)} selected\n")
        sys.stdout.flush()

    render()
    while True:
        ch=getch()
        if   ch=="UP"   and cursor>0:            cursor-=1
        elif ch=="DOWN" and cursor<len(items)-1: cursor+=1
        elif ch==" ":   items[cursor]["selected"]=not items[cursor]["selected"]
        elif ch.lower()=="a":
            for it in items: it["selected"]=True
        elif ch.lower()=="n":
            for it in items: it["selected"]=False
        elif ch in("\r","\n"): break
        elif ch=="q": return []
        render()
    return [it for it in items if it["selected"]]

def run_discovery(auto_apply=False):
    print(f"\n{CYAN}{BOLD}  CodeRed Log Discovery — Windows{RESET}")
    print(f"  Scanning endpoint...\n")
    disc = discover_logs()
    cust = scan_custom_logs()
    print(f"  {GREEN}✔{RESET} Known event channels : {len(disc)}")
    print(f"  {GREEN}✔{RESET} Custom logs          : {len(cust)}\n")
    input(f"  Press {BOLD}Enter{RESET} to review...")
    selected=present_ui(disc,cust)
    if not selected: print(f"\n{YELLOW}  Nothing selected. No changes.{RESET}\n"); return
    print(f"\n{CYAN}  Applying {len(selected)} log source(s)...{RESET}")
    inject_into_conf(selected)
    if not auto_apply:
        ans=input(f"\n  Restart agent now? (y/N): ").strip().lower()
        auto_apply=ans=="y"
    if auto_apply:
        for svc in ["WazuhSvc","Wazuh","wazuh"]:
            r=subprocess.run(["sc","query",svc],capture_output=True,text=True)
            if r.returncode==0:
                subprocess.run(["sc","stop",svc],capture_output=True)
                import time; time.sleep(2)
                subprocess.run(["sc","start",svc],capture_output=True)
                print(f"{GREEN}  ✔ Agent restarted.{RESET}"); break
    print(f"\n{GREEN}{BOLD}  Log discovery complete!{RESET}\n")

if __name__=="__main__":
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(f"{RED}Please run as Administrator.{RESET}"); sys.exit(1)
    run_discovery()
