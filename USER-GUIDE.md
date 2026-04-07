# CodeRed Server Agent — User Guide

**Version:** 1.0.0  
**Supported OS:** Ubuntu 20.04/22.04, Debian 11/12, CentOS/RHEL 8/9, Windows Server 2016/2019/2022, Windows 10/11

---

## Table of Contents

1. [Overview](#1-overview)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
   - 3.1 [Linux](#31-linux)
   - 3.2 [Windows](#32-windows)
4. [First-Time Setup](#4-first-time-setup)
   - 4.1 [Step 1 — Log Discovery Scan](#41-step-1--log-discovery-scan)
   - 4.2 [Step 2 — Module Setup](#42-step-2--module-setup)
5. [CLI Reference](#5-cli-reference)
6. [Modules](#6-modules)
7. [Log Discovery](#7-log-discovery)
8. [Directory Structure](#8-directory-structure)
9. [Troubleshooting](#9-troubleshooting)
10. [Uninstalling](#10-uninstalling)

---

## 1. Overview

CodeRed Server Agent is a modular endpoint monitoring and security agent that collects logs, monitors files, detects threats, and reports to your CodeRed Manager. It is built on top of the battle-tested Wazuh agent with a custom CLI that makes configuration simple for any customer — no manual config file editing required.

**Key capabilities:**

| Capability | Description |
|------------|-------------|
| Log Collection | Collect system, application, and security logs |
| File Integrity Monitoring (FIM) | Detect unauthorised file changes with SHA-256 |
| System Inventory | Hardware, OS, packages, processes, open ports |
| Threat Detection | Rootkit scanning, brute-force, MITRE ATT&CK |
| Vulnerability Detection | CVE mapping for installed packages |
| Compliance Auditing | CIS Benchmark and custom policy checks |
| Active Response | Auto-block IPs, kill processes on alert |

---

## 2. Requirements

### CodeRed Manager
Your CodeRed Manager must be running and reachable from the endpoint before installing the agent.

| Port | Protocol | Purpose |
|------|----------|---------|
| 1514 | TCP/UDP | Agent communication |
| 1515 | TCP | Agent registration |

### Agent — Linux

| Requirement | Minimum |
|-------------|---------|
| OS | Ubuntu 20.04, Debian 11, CentOS/RHEL 8 or later |
| Python | 3.6+ |
| Access | Root (sudo) |
| Network | Outbound TCP 1514/1515 to CodeRed Manager |

### Agent — Windows

| Requirement | Minimum |
|-------------|---------|
| OS | Windows Server 2016 / Windows 10 or later |
| PowerShell | 5.0+ |
| Python | 3.6+ |
| Access | Administrator |
| Network | Outbound TCP 1514/1515 to CodeRed Manager |

---

## 3. Installation

### 3.1 Linux

Run the one-line installer as root. You will be prompted for your CodeRed Manager IP if not provided.

```bash
curl -s https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main/install-codered-agent.sh | sudo bash
```

To pass the Manager IP directly (useful for scripted/silent deployments):

```bash
CODERED_MANAGER_IP=10.0.0.1 bash <(curl -s https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main/install-codered-agent.sh)
```

**What the installer does:**
1. Detects your Linux distribution
2. Adds the Wazuh package repository
3. Installs the Wazuh agent and points it to your CodeRed Manager
4. Installs the `codered-agent` CLI to `/usr/local/bin/`
5. Downloads module templates and the log discovery engine
6. Starts the agent service
7. Prompts you to run the log discovery scan

---

### 3.2 Windows

Open **PowerShell as Administrator** and run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main/install-codered-agent.ps1 | iex
```

You will be prompted for your CodeRed Manager IP during installation.

**What the installer does:**
1. Downloads the Wazuh agent MSI
2. Installs silently and points to your CodeRed Manager
3. Installs the `codered-agent` CLI
4. Adds CLI to the system PATH
5. Starts the agent service

---

## 4. First-Time Setup

After installation, complete these two steps to fully configure your agent.

### 4.1 Step 1 — Log Discovery Scan

The log discovery scan inspects your endpoint, identifies what services are running, finds log files, and recommends which ones to monitor based on security relevance.

```bash
sudo codered-agent scan
```

**What you will see:**

```
  CodeRed Log Discovery
  Scanning endpoint...

  ✔ Active services detected : 42
  ✔ Installed packages       : 381
  ✔ Known logs found         : 12
  ✔ Custom logs found        : 3

  Press Enter to review recommendations...
```

After pressing Enter, an interactive checklist appears:

```
  CodeRed Log Discovery
  ↑↓ move · Space toggle · A select all · N deselect all · Enter confirm

  🔴 HIGH PRIORITY

  ▶ [✔] /var/log/auth.log
         SSH logins, sudo usage, PAM auth failures — critical for intrusion detection

    [✔] /var/log/syslog
         General system events, daemon start/stop, kernel messages

    [✔] /var/log/ufw.log
         Firewall block/allow events — detect port scans and blocked attacks

  🟡 MEDIUM PRIORITY

    [✔] /var/log/nginx/access.log
         HTTP requests — detect web attacks, scanning, path traversal

    [✔] /var/log/mysql/error.log
         MySQL errors — detect failed auth, connection floods

  🟢 LOW PRIORITY

    [ ] /var/log/mail.log
         Mail delivery events — detect spam relay abuse
```

**Controls:**

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move cursor |
| `Space` | Toggle selected/deselected |
| `A` | Select all |
| `N` | Deselect all |
| `Enter` | Confirm and apply |
| `Q` | Cancel |

After confirming, the selected logs are automatically written into the agent configuration and the agent restarts.

> **Tip:** You can re-run `sudo codered-agent scan` at any time to add or remove monitored logs as your environment changes.

---

### 4.2 Step 2 — Module Setup

After the log scan, configure which security modules to enable using the interactive setup wizard:

```bash
sudo codered-agent setup
```

**What you will see:**

```
  ____          _      ____          _
 / ___|___   __| | ___|  _ \ ___  __| |
| |   / _ \ / _` |/ _ \ |_) / _ \/ _` |
| |__| (_) | (_| |  __/  _ <  __/ (_| |
 \____\___/ \__,_|\___|_| \_\___|__,_|

  Select modules to enable  (↑↓ move · Space toggle · Enter confirm)

  ▶ [✔] Log Collection
         Collect system & application logs

    [✔] File Integrity Monitoring
         Detect file create/modify/delete changes with checksums

    [✔] System Inventory
         Collect hardware, OS, packages, processes and open ports

    [✔] Threat Detection
         Rootkit scanning, brute-force and MITRE ATT&CK detections

    [✖] Vulnerability Detection
         Map installed packages/OS patches to known CVEs (NVD feed)

    [✖] Compliance & Auditing
         CIS Benchmark, PCI-DSS and custom SCA policy checks

    [✖] Active Response
         Auto-block IPs, kill processes, quarantine files on alert
```

Use the same keyboard controls as the log scan. Once you confirm, the agent is reconfigured and restarted automatically.

**Recommended modules by environment:**

| Environment | Recommended Modules |
|-------------|---------------------|
| General server | Log Collection, FIM, Inventory, Threat Detection |
| Web server | + Vulnerability Detection |
| PCI / compliance | + Compliance & Auditing |
| High-security / SOC | All modules including Active Response |

---

## 5. CLI Reference

All commands require root/Administrator privileges.

```bash
sudo codered-agent <command> [options]
```

| Command | Description |
|---------|-------------|
| `scan` | Scan endpoint for logs and choose which to monitor |
| `setup` | Interactive module enable/disable wizard |
| `status` | Show all module states and agent service status |
| `enable <module>` | Enable a specific module |
| `disable <module>` | Disable a specific module |
| `restart` | Apply config changes and restart the agent |

### Examples

```bash
# Run log discovery
sudo codered-agent scan

# Run module setup wizard
sudo codered-agent setup

# Check what is currently enabled
sudo codered-agent status

# Enable vulnerability detection
sudo codered-agent enable vuln

# Disable active response
sudo codered-agent disable active-response

# Restart agent after manual config changes
sudo codered-agent restart
```

### `status` output example

```
  Module Status

  Module                    Status       Description
  ─────────────────────── ──────────── ────────────────────────────────────────
  Log Collection           enabled      Collect system & application logs
  File Integrity Monitor   enabled      Detect file changes with checksums
  System Inventory         enabled      Hardware, OS, packages, processes
  Threat Detection         enabled      Rootkit, brute-force, MITRE ATT&CK
  Vulnerability Detection  disabled     CVE mapping for installed packages
  Compliance & Auditing    disabled     CIS Benchmark and custom SCA checks
  Active Response          disabled     Auto-block IPs, kill processes on alert

  Agent service: active
```

---

## 6. Modules

### Log Collection
Collects logs from system files, application logs, and custom sources. This module enables the `<localfile>` blocks in the agent configuration. Use `codered-agent scan` to manage which log files are included.

### File Integrity Monitoring (FIM)
Monitors critical directories for unauthorised changes. By default monitors `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, and `/sbin` on Linux. Detects file creates, modifications, and deletions using SHA-256 checksums and sends alerts when changes are found.

**Default monitored paths:**
- `/etc` — configuration files
- `/usr/bin`, `/usr/sbin` — system binaries
- `/bin`, `/sbin` — essential binaries

### System Inventory
Periodically collects a snapshot of the endpoint including installed packages, running processes, open ports, network interfaces, and OS patch level. Sent to the manager every hour by default.

### Threat Detection
Scans for rootkits, hidden files, hidden processes, and suspicious ports. Includes detection rules for common attack patterns including SSH brute force, web attacks, and MITRE ATT&CK techniques.

### Vulnerability Detection
Compares the endpoint's installed packages and OS patches against the NVD (National Vulnerability Database) CVE feed. Generates alerts for known vulnerabilities with severity ratings. Supported package managers: `apt`, `yum`, `dnf`, Windows Update.

### Compliance & Auditing
Runs Security Configuration Assessment (SCA) checks against CIS Benchmark policies. Results are scored and sent to the manager with pass/fail details per control. Custom YAML policy files can be added to `/var/ossec/etc/shared/codered-sca/`.

### Active Response
Automatically executes response actions when specific alerts are triggered. Default actions include firewall-blocking attacking IPs on brute-force alerts and web attack alerts. Blocked IPs are automatically unblocked after 5 minutes.

> **Warning:** Enable Active Response only after testing in your environment. Misconfigured rules may block legitimate traffic.

---

## 7. Log Discovery

The log discovery engine (`codered-discover.py`) is the most important first step when deploying the agent. It ensures you are monitoring the logs that matter for your specific environment.

### How It Works

1. **Service detection** — queries `systemctl` for all active services
2. **Package detection** — queries `dpkg` or `rpm` for all installed packages
3. **Log file scan** — checks 30+ known log paths and globs under `/var/log`
4. **Scoring** — assigns priority based on security relevance
5. **Presentation** — shows interactive checklist sorted by priority
6. **Injection** — writes selected paths as `<localfile>` blocks into `ossec.conf`

### Priority Levels

| Priority | Colour | Examples | Auto-selected |
|----------|--------|----------|---------------|
| High | 🔴 Red | auth.log, syslog, audit.log, ufw.log | Yes |
| Medium | 🟡 Yellow | nginx/access.log, mysql/error.log, cron.log | Yes |
| Low | 🟢 Green | mail.log, dmesg | No |

### Custom Logs

Any `.log` or `.err` file found under `/var/log` that is not in the known catalogue is listed under **Custom Logs** at the bottom of the checklist. These are unscored — you decide whether to include them.

### Re-running the Scan

Run the scan again whenever you install new services or applications on the endpoint:

```bash
sudo codered-agent scan
```

The previous discovery configuration is replaced with the new selection.

---

## 8. Directory Structure

### Linux

```
/usr/local/bin/
└── codered-agent               ← CLI binary

/etc/codered/
├── state.json                  ← enabled module state
├── codered-discover.py         ← log discovery engine
└── templates/
    ├── log-collection.xml      ← module config snippets
    ├── fim.xml
    ├── inventory.xml
    ├── threat.xml
    ├── vuln.xml
    ├── compliance.xml
    └── active-response.xml

/var/ossec/
├── etc/
│   └── ossec.conf              ← active agent config (managed by CLI)
└── logs/
    └── ossec.log               ← agent operational log
```

### Windows

```
C:\Program Files\CodeRed\Agent\
├── codered-agent.py            ← CLI script
├── codered-agent.cmd           ← CLI wrapper (run from anywhere)
├── codered-discover.py         ← log discovery engine
└── templates\                  ← module config snippets

C:\Program Files (x86)\ossec-agent\
├── ossec.conf                  ← active agent config
└── logs\
    └── ossec.log               ← agent operational log
```

---

## 9. Troubleshooting

### Agent not connecting to manager

1. Verify the manager IP is correct:
   ```bash
   grep "<address>" /var/ossec/etc/ossec.conf
   ```
2. Test network connectivity:
   ```bash
   nc -zv <manager-ip> 1514
   nc -zv <manager-ip> 1515
   ```
3. Check the agent log:
   ```bash
   tail -f /var/ossec/logs/ossec.log
   ```

---

### Agent service not starting

```bash
# Check service status
systemctl status wazuh-agent

# View recent logs
journalctl -u wazuh-agent -n 50

# Try manual restart
sudo codered-agent restart
```

---

### Module changes not taking effect

Always run `restart` after manually editing config or if the wizard did not restart automatically:

```bash
sudo codered-agent restart
```

---

### Log discovery shows no logs

This may happen on a minimal OS with few services. Check:
1. Are logs in `/var/log`?
   ```bash
   ls -lh /var/log/
   ```
2. Are services running?
   ```bash
   systemctl list-units --type=service --state=active
   ```
3. Run discovery again:
   ```bash
   sudo codered-agent scan
   ```

---

### Config file corrupted

A backup is created automatically before every change:

```bash
# Restore from backup
sudo cp /var/ossec/etc/ossec.conf.bak /var/ossec/etc/ossec.conf
sudo codered-agent restart
```

---

## 10. Uninstalling

### Linux

```bash
# Stop and disable service
sudo systemctl stop wazuh-agent
sudo systemctl disable wazuh-agent

# Remove Wazuh agent
sudo apt-get remove --purge wazuh-agent   # Debian/Ubuntu
sudo yum remove wazuh-agent               # CentOS/RHEL

# Remove CodeRed files
sudo rm -rf /etc/codered
sudo rm -f /usr/local/bin/codered-agent
```

### Windows

1. Go to **Control Panel → Programs → Uninstall a program**
2. Find **Wazuh Agent** and uninstall
3. Delete `C:\Program Files\CodeRed\` manually

---

*For support, visit the [CodeRed Server Agent repository](https://github.com/lolomee/Codered-Server-Agent).*
