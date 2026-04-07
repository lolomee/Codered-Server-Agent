# CodeRed Server Agent

A modular server monitoring and security agent based on Wazuh, with a custom CLI for easy module management.

## Features

| Module | Description |
|--------|-------------|
| `log-collection` | Collect system & application logs |
| `fim` | File Integrity Monitoring with SHA-256 checksums |
| `inventory` | Hardware, OS, packages, processes, open ports |
| `threat` | Rootkit scanning, brute-force & MITRE ATT&CK detection |
| `vuln` | CVE mapping for installed packages (NVD feed) |
| `compliance` | CIS Benchmark & custom SCA policy checks |
| `active-response` | Auto-block IPs, kill processes on alert |

---

## Quick Install

### Linux (Ubuntu / Debian / CentOS / RHEL)

```bash
curl -s https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main/install-codered-agent.sh | sudo bash
```

Or with manager IP pre-set:

```bash
CODERED_MANAGER_IP=10.0.0.1 bash <(curl -s https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main/install-codered-agent.sh)
```

### Windows (PowerShell — Run as Administrator)

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main/install-codered-agent.ps1 | iex
```

---

## CLI Usage

After installation, run the interactive setup wizard:

```bash
sudo codered-agent setup
```

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

    [✖] Vulnerability Detection
       Map installed packages/OS patches to known CVEs (NVD feed)
    ...
```

### Other Commands

```bash
# Show all modules and agent service status
sudo codered-agent status

# Enable a specific module
sudo codered-agent enable vuln

# Disable a specific module
sudo codered-agent disable compliance

# Apply config changes and restart agent
sudo codered-agent restart
```

### Available Modules

```
log-collection    active-response
fim               vuln
inventory         compliance
threat
```

---

## Requirements

### Manager
- CodeRed Manager (Wazuh Manager) must be running and reachable
- Default port: TCP 1514 (agent comms), TCP 1515 (registration)

### Agent — Linux
- Ubuntu 20.04 / 22.04, Debian 11 / 12, CentOS/RHEL 8 / 9
- Python 3.6+
- Root access

### Agent — Windows
- Windows Server 2016 / 2019 / 2022 or Windows 10 / 11
- PowerShell 5+
- Python 3.6+ (for CLI)
- Administrator access

---

## Directory Structure

```
/etc/codered/
├── state.json          ← enabled module state
└── templates/          ← module ossec.conf snippets
    ├── log-collection.xml
    ├── fim.xml
    ├── inventory.xml
    ├── threat.xml
    ├── vuln.xml
    ├── compliance.xml
    └── active-response.xml

/usr/local/bin/codered-agent   ← CLI binary
/var/ossec/etc/ossec.conf      ← active Wazuh config (managed by CLI)
```

---

## License

GPLv2 (inherited from Wazuh). See [LICENSE](LICENSE).
