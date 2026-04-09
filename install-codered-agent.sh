#!/bin/bash
# CodeRed Server Agent - Linux Installer
set -e

MANAGER_IP="${CODERED_MANAGER_IP:-}"
INSTALL_DIR="/etc/codered"
CLI_BIN="/usr/local/bin/codered-agent"
TEMPLATES_DST="/etc/codered/templates/linux"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
OSSEC_DIR="/var/ossec"
REPO_BASE="https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main"

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

log()  { printf "%b\n" "${CYAN}[*]${RESET} $*"; }
ok()   { printf "%b\n" "${GREEN}[OK]${RESET} $*"; }
warn() { printf "%b\n" "${YELLOW}[!]${RESET} $*"; }
die()  { printf "%b\n" "${RED}[FAIL]${RESET} $*"; exit 1; }

banner() {
  printf "%b\n" "${CYAN}${BOLD}"
  echo "============================================"
  echo "   CodeRed Server Agent - Linux Installer  "
  echo "============================================"
  printf "%b\n" "${RESET}"
}

[[ $EUID -ne 0 ]] && die "Please run as root."

banner

# Dependency check
log "Checking dependencies..."
for dep in curl gpg python3; do
  if ! command -v "$dep" &>/dev/null; then
    warn "$dep not found - installing..."
    if command -v apt-get &>/dev/null; then apt-get install -y "$dep" -qq
    elif command -v dnf &>/dev/null; then dnf install -y "$dep" -q
    elif command -v yum &>/dev/null; then yum install -y "$dep" -q
    else die "Cannot install $dep - install manually and re-run."
    fi
  fi
done
ok "Dependencies OK."

# Manager IP
if [[ -z "$MANAGER_IP" ]]; then
  printf "%b" "${BOLD}  Enter your CodeRed Manager IP or hostname: ${RESET}"
  read -rp "" MANAGER_IP < /dev/tty
  [[ -z "$MANAGER_IP" ]] && die "Manager IP is required."
fi
if [[ "$MANAGER_IP" =~ [[:space:]] ]] || [[ ${#MANAGER_IP} -gt 253 ]]; then
  die "Invalid Manager IP: ${MANAGER_IP}"
fi
log "Manager IP: ${MANAGER_IP}"

# Detect OS
[[ -f /etc/os-release ]] && . /etc/os-release || die "Cannot detect OS."
log "OS: ${ID} ${VERSION_ID}"

# Stop and purge old agent
systemctl stop wazuh-agent 2>/dev/null || true
if dpkg -l wazuh-agent &>/dev/null 2>&1; then
  log "Removing existing wazuh-agent..."
  apt-get remove --purge -y wazuh-agent -qq 2>/dev/null || true
  rm -rf /var/ossec /etc/ossec-init.conf
  ok "Old agent removed."
fi

# Install Wazuh agent
install_deb() {
  log "Adding Wazuh repository (apt)..."
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="${MANAGER_IP}" apt-get install -y wazuh-agent
}

install_rpm() {
  log "Adding Wazuh repository (rpm)..."
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
  cat > /etc/yum.repos.d/wazuh.repo << REPOEOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPOEOF
  if command -v dnf &>/dev/null; then
    WAZUH_MANAGER="${MANAGER_IP}" dnf install -y wazuh-agent
  else
    WAZUH_MANAGER="${MANAGER_IP}" yum install -y wazuh-agent
  fi
}

case "$ID" in
  ubuntu|debian)                       install_deb ;;
  centos|rhel|rocky|almalinux|fedora) install_rpm ;;
  *) die "Unsupported OS: ${ID}" ;;
esac
ok "Wazuh agent installed."

# Verify ossec.conf
[[ ! -f "$OSSEC_CONF" ]] && die "ossec.conf not found - Wazuh install failed."
CONF_SIZE=$(wc -c < "$OSSEC_CONF")
[[ "$CONF_SIZE" -lt 100 ]] && die "ossec.conf too small (${CONF_SIZE} bytes)."
ok "ossec.conf: ${CONF_SIZE} bytes."

# Ensure manager IP is present
if grep -q "${MANAGER_IP}" "$OSSEC_CONF"; then
  ok "Manager IP ${MANAGER_IP} confirmed in ossec.conf."
else
  warn "Manager IP missing - injecting..."
  python3 -c "
import re
with open('$OSSEC_CONF', 'r') as f: c = f.read()
c = re.sub(r'<address>[^<]*</address>', '<address>$MANAGER_IP</address>', c)
with open('$OSSEC_CONF', 'w') as f: f.write(c)
"
  grep -q "${MANAGER_IP}" "$OSSEC_CONF" && ok "Manager IP set." || die "Could not set manager IP."
fi

# ── Fix 1: Patch systemd unit to set WorkingDirectory ────────────────────────
# wazuh-execd reads ossec.conf as a relative path 'etc/ossec.conf'.
# Without WorkingDirectory=/var/ossec it fails with "line 0" error after
# the manager pushes a shared config and execd reloads.
log "Patching wazuh-agent systemd unit (WorkingDirectory fix)..."
UNIT_FILE=""
for f in /usr/lib/systemd/system/wazuh-agent.service \
          /lib/systemd/system/wazuh-agent.service \
          /etc/systemd/system/wazuh-agent.service; do
  [[ -f "$f" ]] && UNIT_FILE="$f" && break
done

if [[ -n "$UNIT_FILE" ]]; then
  # Only patch if WorkingDirectory not already set
  if ! grep -q "WorkingDirectory" "$UNIT_FILE"; then
    # Add WorkingDirectory after the [Service] section header
    sed -i '/^\[Service\]/a WorkingDirectory=\/var\/ossec' "$UNIT_FILE"
    ok "Patched $UNIT_FILE with WorkingDirectory=/var/ossec"
  else
    ok "WorkingDirectory already set in unit file."
  fi
else
  warn "Could not find wazuh-agent.service unit file - skipping patch."
fi

# ── Fix 2: Use systemd override to ensure WorkingDirectory survives upgrades ──
mkdir -p /etc/systemd/system/wazuh-agent.service.d
cat > /etc/systemd/system/wazuh-agent.service.d/workdir.conf << 'UNITEOF'
[Service]
WorkingDirectory=/var/ossec
UNITEOF
ok "Systemd override written to /etc/systemd/system/wazuh-agent.service.d/workdir.conf"

# Install CodeRed CLI
log "Installing CodeRed CLI..."
mkdir -p "${INSTALL_DIR}" "${TEMPLATES_DST}"
curl -fsSL "${REPO_BASE}/linux/codered-agent" -o "${CLI_BIN}"
chmod +x "${CLI_BIN}"
PYTHON3_PATH=$(command -v python3)
sed -i "1s|.*|#!${PYTHON3_PATH}|" "${CLI_BIN}"
ok "CLI installed at ${CLI_BIN}"

# Install discovery engine
log "Installing log discovery engine..."
curl -fsSL "${REPO_BASE}/linux/codered-discover.py" -o "${INSTALL_DIR}/codered-discover.py"
chmod +x "${INSTALL_DIR}/codered-discover.py"
ok "Discovery engine installed."

# Download templates
log "Downloading module templates..."
for tmpl in log-collection fim inventory threat vuln compliance active-response; do
  curl -fsSL "${REPO_BASE}/templates/linux/${tmpl}.xml" -o "${TEMPLATES_DST}/${tmpl}.xml"
done
ok "Templates installed."

# Start agent
log "Starting agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
if systemctl start wazuh-agent; then
  ok "Agent service started successfully."
  # Wait for registration then lock client.keys as read-only
  # so it survives restarts without triggering duplicate name
  log "Waiting for agent registration..."
  for i in $(seq 1 15); do
    if [[ -s "/var/ossec/etc/client.keys" ]]; then
      chattr +i /var/ossec/etc/client.keys 2>/dev/null && ok "client.keys locked (immutable) - agent will reuse key on restart." || true
      break
    fi
    sleep 1
  done
  [[ ! -s "/var/ossec/etc/client.keys" ]] && warn "Agent not yet registered - may need manager to accept it first."
else
  warn "Agent failed to start. Last errors:"
  grep -i "error" /var/ossec/logs/ossec.log 2>/dev/null | tail -5 || true
  warn "Run: tail -50 /var/ossec/logs/ossec.log"
fi

printf "\n%b\n" "${GREEN}${BOLD}Installation complete!${RESET}"
printf "  Run: %b\n\n" "${CYAN}${BOLD}sudo codered-agent${RESET}"

read -rp "  Run log discovery scan now? [Y/n]: " RUN_SCAN < /dev/tty
if [[ "${RUN_SCAN,,}" != "n" ]]; then
  echo ""
  "${CLI_BIN}" scan
fi
