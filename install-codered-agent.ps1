# ─────────────────────────────────────────────────────────────────────────────
# CodeRed Server Agent — Windows Installer
# Run as Administrator in PowerShell
# ─────────────────────────────────────────────────────────────────────────────

param(
    [string]$ManagerIP   = $env:CODERED_MANAGER_IP,
    [string]$AgentName   = $env:COMPUTERNAME,
    [string]$AgentVersion = "4.7.3"
)

$REPO_BASE     = "https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main"
$INSTALL_DIR   = "C:\Program Files\CodeRed\Agent"
$TEMPLATES_DIR = "$INSTALL_DIR\templates\windows"
$CLI_SCRIPT    = "$INSTALL_DIR\codered-agent.py"
$CLI_WRAPPER   = "$INSTALL_DIR\codered-agent.cmd"
$DISCOVER      = "$INSTALL_DIR\codered-discover.py"
$WAZUH_MSI_URL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-${AgentVersion}-1.msi"
$INSTALLER     = "$env:TEMP\codered-agent-setup.msi"

function Write-Banner {
    Write-Host ""
    Write-Host "  ____          _      ____          _" -ForegroundColor Cyan
    Write-Host " / ___|___   __| | ___|  _ \ ___  __| |" -ForegroundColor Cyan
    Write-Host "| |   / _ \ / _`` |/ _ \ |_) / _ \/ _`` |" -ForegroundColor Cyan
    Write-Host "| |__| (_) | (_| |  __/  _ <  __/ (_| |" -ForegroundColor Cyan
    Write-Host " \____\___/ \__,_|\___|_| \_\___|__,_|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Server Agent Installer for Windows" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step  { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok    { param($msg) Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red; exit 1 }

# ── Admin check ───────────────────────────────────────────────────────────────
$currentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "Please run PowerShell as Administrator."
}

Write-Banner

# ── Manager IP ────────────────────────────────────────────────────────────────
if (-not $ManagerIP) {
    $ManagerIP = Read-Host "  Enter your CodeRed Manager IP or hostname"
    if (-not $ManagerIP) { Write-Fail "Manager IP is required." }
}
Write-Step "Manager: $ManagerIP"
Write-Step "Agent name: $AgentName"

# ── Python check ──────────────────────────────────────────────────────────────
Write-Step "Checking Python..."

# Refresh PATH first — picks up Python if just installed in this session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Check python, python3, and common install paths
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) { $python = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $python) {
    # Check common Python install locations directly
    $commonPaths = @(
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python310\python.exe",
        "C:\Python312\python.exe",
        "C:\Python311\python.exe",
        "C:\Python310\python.exe",
        "C:\Program Files\Python312\python.exe",
        "C:\Program Files\Python311\python.exe"
    )
    foreach ($p in $commonPaths) {
        if (Test-Path $p) {
            # Add its directory to PATH for this session
            $pyDir = Split-Path $p
            $env:Path = "$pyDir;$env:Path"
            $python = Get-Command python -ErrorAction SilentlyContinue
            break
        }
    }
}

if (-not $python) {
    Write-Warn "Python not found. Installing via winget..."
    try {
        winget install Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        $python = Get-Command python -ErrorAction SilentlyContinue
        if ($python) { Write-Ok "Python installed." }
        else {
            Write-Warn "Python installed but PATH not updated. Please close and reopen PowerShell as Administrator, then re-run."
            exit 1
        }
    } catch {
        Write-Warn "winget failed. Install Python from https://python.org/downloads (tick Add to PATH), then re-run."
        exit 1
    }
} else {
    $pyVersion = python --version 2>&1
    Write-Ok "Python found: $pyVersion"
}

# ── Download MSI ──────────────────────────────────────────────────────────────
Write-Step "Downloading agent installer..."
try {
    Invoke-WebRequest -Uri $WAZUH_MSI_URL -OutFile $INSTALLER -UseBasicParsing
    Write-Ok "Installer downloaded."
} catch {
    Write-Fail "Failed to download installer: $_"
}

# ── Install MSI ───────────────────────────────────────────────────────────────
Write-Step "Installing agent (silent)..."
$msiArgs = @("/i", $INSTALLER, "/q",
             "WAZUH_MANAGER=$ManagerIP",
             "WAZUH_AGENT_NAME=$AgentName",
             "WAZUH_REGISTRATION_SERVER=$ManagerIP")
$proc = Start-Process msiexec -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Fail "MSI install failed (exit code $($proc.ExitCode))"
}
Write-Ok "Agent installed."

# ── Create directories ────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $INSTALL_DIR   | Out-Null
New-Item -ItemType Directory -Force -Path $TEMPLATES_DIR | Out-Null

# ── Download CLI and discover engine ──────────────────────────────────────────
Write-Step "Installing CodeRed CLI..."
Invoke-WebRequest -Uri "$REPO_BASE/windows/codered-agent.py"    -OutFile $CLI_SCRIPT -UseBasicParsing
Write-Ok "CLI installed."

Write-Step "Installing log discovery engine..."
Invoke-WebRequest -Uri "$REPO_BASE/windows/codered-discover.py" -OutFile $DISCOVER -UseBasicParsing
Write-Ok "Discovery engine installed."

# ── CMD wrapper ───────────────────────────────────────────────────────────────
$wrapperContent = "@echo off`npython `"$CLI_SCRIPT`" %*"
Set-Content -Path $CLI_WRAPPER -Value $wrapperContent

# ── Add to PATH ───────────────────────────────────────────────────────────────
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$INSTALL_DIR*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$INSTALL_DIR", "Machine")
    Write-Ok "Added CodeRed to system PATH."
}

# ── Download templates ────────────────────────────────────────────────────────
Write-Step "Downloading Windows module templates..."
$templates = @("log-collection","fim","inventory","threat","vuln","compliance","active-response")
foreach ($tmpl in $templates) {
    Invoke-WebRequest -Uri "$REPO_BASE/templates/windows/$tmpl.xml" -OutFile "$TEMPLATES_DIR\$tmpl.xml" -UseBasicParsing
}
Write-Ok "Templates installed."

# ── Start service ─────────────────────────────────────────────────────────────
Write-Step "Starting CodeRed Agent service..."
$svcName = $null
foreach ($name in @("WazuhSvc","Wazuh","wazuh","OssecSvc")) {
    if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
        $svcName = $name
        break
    }
}

if ($svcName) {
    try {
        Set-Service   -Name $svcName -StartupType Automatic -ErrorAction Stop
        Start-Service -Name $svcName -ErrorAction Stop
        Write-Ok "Agent service '$svcName' started."
    } catch {
        Write-Warn "Could not start '$svcName': $_"
        Write-Warn "Try manually: sc start $svcName"
    }
} else {
    Write-Warn "Service not found yet. Try after a moment: sc start WazuhSvc"
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
Remove-Item $INSTALLER -Force -ErrorAction SilentlyContinue

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Open a new PowerShell as Administrator and run:" -ForegroundColor White
Write-Host "    codered-agent" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Direct commands:" -ForegroundColor White
Write-Host "    codered-agent scan      - scan log directories" -ForegroundColor Cyan
Write-Host "    codered-agent setup     - enable/disable modules" -ForegroundColor Cyan
Write-Host "    codered-agent status    - view agent status" -ForegroundColor Cyan
Write-Host ""
