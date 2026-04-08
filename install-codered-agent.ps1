# ─────────────────────────────────────────────────────────────────────────────
# CodeRed Server Agent — Windows Installer
# Supports: Windows Server 2016/2019/2022, Windows 10/11
# Run as Administrator in PowerShell
# ─────────────────────────────────────────────────────────────────────────────

param(
    [string]$ManagerIP   = $env:CODERED_MANAGER_IP,
    [string]$AgentName   = $env:COMPUTERNAME,
    [string]$AgentVersion = "4.7.3"
)

$REPO_BASE     = "https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main"
$INSTALL_DIR   = "C:\Program Files\CodeRed\Agent"
$TEMPLATES_DIR = "$INSTALL_DIR\templates"
$CLI_SCRIPT    = "$INSTALL_DIR\codered-agent.py"
$CLI_WRAPPER   = "$INSTALL_DIR\codered-agent.cmd"
$WAZUH_MSI_URL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-${AgentVersion}-1.msi"
$INSTALLER     = "$env:TEMP\codered-agent-setup.msi"

# ── Colours ───────────────────────────────────────────────────────────────────
function Write-Banner {
    Write-Host ""
    Write-Host "  ____          _      ____          _" -ForegroundColor Cyan
    Write-Host " / ___|___   __| | ___|  _ \ ___  __| |" -ForegroundColor Cyan
    Write-Host "| |   / _ \ / _\` |/ _ \ |_) / _ \/ _\` |" -ForegroundColor Cyan
    Write-Host "| |__| (_) | (_| |  __/  _ <  __/ (_| |" -ForegroundColor Cyan
    Write-Host " \____\___/ \__,_|\___|_| \_\___|__,_|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Server Agent Installer for Windows" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step  { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Error2{ param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# ── Admin check ───────────────────────────────────────────────────────────────
$currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error2 "Please run PowerShell as Administrator."
}

Write-Banner

# ── Prompt for Manager IP ─────────────────────────────────────────────────────
if (-not $ManagerIP) {
    $ManagerIP = Read-Host "  Enter your CodeRed Manager IP or hostname"
    if (-not $ManagerIP) { Write-Error2 "Manager IP is required." }
}

Write-Step "Manager: $ManagerIP"
Write-Step "Agent name: $AgentName"

# ── Check / install Python ────────────────────────────────────────────────────
Write-Step "Checking Python..."
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Warn "Python not found. Installing Python 3.12 via winget..."
    try {
        winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        # Refresh PATH in current session
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        Write-Ok "Python installed."
    } catch {
        Write-Warn "winget install failed. Please install Python manually from https://python.org/downloads"
        Write-Warn "Make sure to tick 'Add Python to PATH' during installation, then re-run this script."
        exit 1
    }
} else {
    $pyVersion = python --version 2>&1
    Write-Ok "Python found: $pyVersion"
}

# ── Download CodeRed MSI ──────────────────────────────────────────────────────
Write-Step "Downloading CodeRed Agent installer..."
try {
    Invoke-WebRequest -Uri $WAZUH_MSI_URL -OutFile $INSTALLER -UseBasicParsing
    Write-Ok "Downloaded installer."
} catch {
    Write-Error2 "Failed to download installer: $_"
}

# ── Install agent ─────────────────────────────────────────────────────────────
Write-Step "Installing CodeRed Agent (silent)..."
$msiArgs = @(
    "/i", $INSTALLER,
    "/q",
    "WAZUH_MANAGER=$ManagerIP",
    "WAZUH_AGENT_NAME=$AgentName",
    "WAZUH_REGISTRATION_SERVER=$ManagerIP"
)
$proc = Start-Process msiexec -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Error2 "MSI install failed with exit code: $($proc.ExitCode)"
}
Write-Ok "CodeRed Agent installed."

# ── Create CodeRed directories ────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $INSTALL_DIR   | Out-Null
New-Item -ItemType Directory -Force -Path $TEMPLATES_DIR | Out-Null

# ── Download CLI, discover engine and templates ───────────────────────────────
Write-Step "Installing CodeRed CLI..."
Invoke-WebRequest -Uri "$REPO_BASE/codered-agent" -OutFile $CLI_SCRIPT -UseBasicParsing

Write-Step "Installing log discovery engine..."
Invoke-WebRequest -Uri "$REPO_BASE/codered-discover.py" -OutFile "$INSTALL_DIR\codered-discover.py" -UseBasicParsing
Write-Ok "Log discovery engine installed."

# Create .cmd wrapper so `codered-agent` works from anywhere
@"
@echo off
python "$CLI_SCRIPT" %*
"@ | Set-Content $CLI_WRAPPER

# Add to PATH if not already there
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$INSTALL_DIR*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$INSTALL_DIR", "Machine")
    Write-Ok "Added CodeRed to system PATH."
}

Write-Step "Downloading module templates..."
$templates = @("log-collection", "fim", "inventory", "threat", "vuln", "compliance", "active-response")
foreach ($tmpl in $templates) {
    Invoke-WebRequest -Uri "$REPO_BASE/templates/$tmpl.xml" `
        -OutFile "$TEMPLATES_DIR\$tmpl.xml" -UseBasicParsing
}
Write-Ok "Templates installed."

# ── Start agent service ───────────────────────────────────────────────────────
Write-Step "Starting CodeRed Agent service..."
Start-Service -Name "Wazuh" -ErrorAction SilentlyContinue
Set-Service  -Name "Wazuh" -StartupType Automatic
Write-Ok "Agent service started."

# ── Cleanup ───────────────────────────────────────────────────────────────────
Remove-Item $INSTALLER -Force -ErrorAction SilentlyContinue

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Run the setup wizard (open new PowerShell as Admin):"
Write-Host "    codered-agent setup" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Other commands:"
Write-Host "    codered-agent status              - view module status" -ForegroundColor Cyan
Write-Host "    codered-agent enable <module>     - enable a module" -ForegroundColor Cyan
Write-Host "    codered-agent disable <module>    - disable a module" -ForegroundColor Cyan
Write-Host ""
