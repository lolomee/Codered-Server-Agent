# ─────────────────────────────────────────────────────────────────────────────
# CodeRed Server Agent — Windows Uninstaller
# Run as Administrator in PowerShell
# ─────────────────────────────────────────────────────────────────────────────

function Write-Banner {
    Write-Host ""
    Write-Host "  ____          _      ____          _" -ForegroundColor Cyan
    Write-Host " / ___|___   __| | ___|  _ \ ___  __| |" -ForegroundColor Cyan
    Write-Host "| |   / _ \ / _`` |/ _ \ |_) / _ \/ _`` |" -ForegroundColor Cyan
    Write-Host "| |__| (_) | (_| |  __/  _ <  __/ (_| |" -ForegroundColor Cyan
    Write-Host " \____\___/ \__,_|\___|_| \_\___|__,_|" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Server Agent - Uninstaller" -ForegroundColor Cyan
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

Write-Host "  This will remove CodeRed Server Agent from this system." -ForegroundColor Yellow
Write-Host "  All agent config and collected state will be deleted.`n"
$confirm = Read-Host "  Are you sure? (y/N)"
if ($confirm.ToLower() -ne "y") {
    Write-Host "`n  Cancelled." -ForegroundColor Yellow
    exit 0
}

Write-Host ""

# ── Stop service ──────────────────────────────────────────────────────────────
Write-Step "Stopping CodeRed Agent service..."
try {
    $svc = Get-Service -Name "Wazuh" -ErrorAction SilentlyContinue
    if ($svc) {
        Stop-Service -Name "Wazuh" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "Wazuh" -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Ok "Service stopped and disabled."
    } else {
        Write-Warn "Service not found, may already be removed."
    }
} catch {
    Write-Warn "Could not stop service: $_"
}

# ── Uninstall via Windows registry ───────────────────────────────────────────
Write-Step "Uninstalling CodeRed Agent package..."
$uninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$found = $false
foreach ($key in $uninstallKeys) {
    $subkeys = Get-ChildItem -Path $key -ErrorAction SilentlyContinue
    foreach ($subkey in $subkeys) {
        $name = (Get-ItemProperty -Path $subkey.PSPath -ErrorAction SilentlyContinue).DisplayName
        if ($name -like "*Wazuh*" -or $name -like "*CodeRed*") {
            $uninstallStr = (Get-ItemProperty -Path $subkey.PSPath).UninstallString
            if ($uninstallStr) {
                Write-Step "Found: $name — running uninstaller..."
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/x", $subkey.PSChildName, "/q" -Wait -ErrorAction SilentlyContinue
                $found = $true
                Write-Ok "Package uninstalled."
            }
        }
    }
}

if (-not $found) {
    Write-Warn "No package found in registry. May already be removed."
}

# ── Remove CodeRed files ──────────────────────────────────────────────────────
Write-Step "Removing CodeRed files..."
$paths = @(
    "C:\Program Files\CodeRed",
    "C:\Program Files (x86)\ossec-agent"
)
foreach ($path in $paths) {
    if (Test-Path $path) {
        Remove-Item -Recurse -Force $path -ErrorAction SilentlyContinue
        Write-Ok "Removed: $path"
    }
}

# ── Remove from PATH ──────────────────────────────────────────────────────────
Write-Step "Cleaning up system PATH..."
$currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
$cleanPath = ($currentPath -split ";" | Where-Object { $_ -notlike "*CodeRed*" }) -join ";"
[Environment]::SetEnvironmentVariable("Path", $cleanPath, "Machine")
Write-Ok "PATH cleaned."

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  CodeRed Server Agent has been removed." -ForegroundColor Green
Write-Host "  All agent files and configuration have been cleaned up.`n"
