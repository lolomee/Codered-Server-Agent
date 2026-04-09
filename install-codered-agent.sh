#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# CodeRed Server Agent — Linux Installer
# ─────────────────────────────────────────────────────────────────────────────
set -e

MANAGER_IP="${CODERED_MANAGER_IP:-}"
INSTALL_DIR="/etc/codered"
CLI_BIN="/usr/local/bin/codered-agent"
TEMPLATES_DST="/etc/codered/templates/linux"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
REPO_BASE="https://raw.githubusercontent.com/lolomee/Codered-Server-Agent/main"

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ____          _      ____          _"
  echo " / ___|___   __| | ___|  _ \\ ___  __| |"
  echo "| |   / _ \\ / _\` |/ _ \\ |_) / _ \\/ _\` |"
  echo "| |__| (_) | (_| |  __/  _ <  __/ (_| |"
  echo " \\____\\___/ \\__,_|\\___|_| \\_\\___|\\__,_|"
  echo ""
  echo "  Server Agent Installer"
  echo -e "${RESET}"
}

log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✔]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[✖]${RESET} $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Please run as root."

banner

# ── Dependency check ──────────────────────────────────────────────────────────
log "Checking dependencies..."
for dep in curl gpg python3; do
  if ! command -v "$dep" &>/dev/null; then
    warn "$dep not found — installing..."
    if command -v apt-get &>/dev/null; then apt-get install -y "$dep" -qq
    elif command -v dnf &>/dev/null; then dnf install -y "$dep" -q
    elif command -v yum &>/dev/null; then yum install -y "$dep" -q
    else die "Cannot install $dep — install it manually and re-run."
    fi
  fi
done
ok "Dependencies OK."

# ── Manager IP ────────────────────────────────────────────────────────────────
if [[ -z "$MANAGER_IP" ]]; then
  echo -e "${BOLD}  Enter your CodeRed Manager IP or hostname:${RESET}"
  read -rp "  > " MANAGER_IP < /dev/tty
  [[ -z "$MANAGER_IP" ]] && die "Manager IP is required."
fi

# Validate IP/hostname (no spaces or special chars)
if [[ "$MANAGER_IP" =~ [[:space:]] ]] || [[ ${#MANAGER_IP} -gt 253 ]]; then
  die "Invalid Manager IP: '${MANAGER_IP}'. Use CODERED_MANAGER_IP=x.x.x.x bash <(curl ...)"
fi
log "Manager IP: ${BOLD}${MANAGER_IP}${RESET}"

# ── Detect OS ─────────────────────────────────────────────────────────────────
[[ -f /etc/os-release ]] && . /etc/os-release || die "Cannot detect OS."
log "OS: ${ID} ${VERSION_ID}"

# ── Install Wazuh agent ───────────────────────────────────────────────────────
install_deb() {
  log "Adding Wazuh repository (apt)..."
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="${MANAGER_IP}" apt-get install -y wazuh-agent
}

install_rpm() {
  log "Adding Wazuh repository (rpm)..."
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
  cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
  if command -v dnf &>/dev/null; then
    WAZUH_MANAGER="${MANAGER_IP}" dnf install -y wazuh-agent
  else
    WAZUH_MANAGER="${MANAGER_IP}" yum install -y wazuh-agent
  fi
}

# Stop existing agent if running
systemctl stop wazuh-agent 2>/dev/null || true

case "$ID" in
  ubuntu|debian)                         install_deb ;;
  centos|rhel|rocky|almalinux|fedora)   install_rpm ;;
  *) die "Unsupported OS: ${ID}" ;;
esac
ok "Wazuh agent installed."

# ── Verify ossec.conf ─────────────────────────────────────────────────────────
[[ ! -f "$OSSEC_CONF" ]] && die "ossec.conf not found — Wazuh install failed."
CONF_SIZE=$(wc -c < "$OSSEC_CONF")
[[ "$CONF_SIZE" -lt 100 ]] && die "ossec.conf is empty (${CONF_SIZE} bytes)."
ok "ossec.conf: ${CONF_SIZE} bytes."

# ── Set manager IP via sed ────────────────────────────────────────────────────
log "Setting manager IP..."
cp "$OSSEC_CONF" "${OSSEC_CONF}.bak"
sed -i "s|<address>.*</address>|<address>${MANAGER_IP}</address>|g" "$OSSEC_CONF"
grep -q "${MANAGER_IP}" "$OSSEC_CONF" && ok "Manager IP set." || warn "Check ${OSSEC_CONF} manually."

# ── Add CodeRed include to ossec.conf (once, via sed) ─────────────────────────
if ! grep -q "codered.conf" "$OSSEC_CONF"; then
  log "Adding CodeRed include to ossec.conf..."
  sed -i "s|</ossec_config>|  <include>codered.conf</include>\n</ossec_config>|" "$OSSEC_CONF"
  ok "Include added."
fi

# ── Create empty codered.conf ─────────────────────────────────────────────────
log "Creating codered.conf..."
cat > /var/ossec/etc/codered.conf << 'EOF'
<ossec_config>
  <!-- CodeRed Server Agent configuration -->
  <!-- Run: sudo codered-agent scan  to add log sources -->
</ossec_config>
EOF
chown root:wazuh /var/ossec/etc/codered.conf
chmod 660 /var/ossec/etc/codered.conf
ok "codered.conf created."

# ── Clear old agent keys to avoid duplicate name error ────────────────────────
log "Clearing agent registration..."
rm -f /var/ossec/etc/client.keys
ok "Agent keys cleared."

# ── Install CodeRed CLI ───────────────────────────────────────────────────────
log "Installing CodeRed CLI..."
mkdir -p "${INSTALL_DIR}" "${TEMPLATES_DST}"
curl -fsSL "${REPO_BASE}/linux/codered-agent" -o "${CLI_BIN}"
chmod +x "${CLI_BIN}"
PYTHON3_PATH="$(command -v python3)"
sed -i "1s|.*|#!${PYTHON3_PATH}|" "${CLI_BIN}"
ok "CLI installed."

# ── Install discovery engine ──────────────────────────────────────────────────
log "Installing log discovery engine..."
curl -fsSL "${REPO_BASE}/linux/codered-discover.py" -o "${INSTALL_DIR}/codered-discover.py"
chmod +x "${INSTALL_DIR}/codered-discover.py"
ok "Discovery engine installed."

# ── Download templates ────────────────────────────────────────────────────────
log "Downloading Linux module templates..."
for tmpl in log-collection fim inventory threat vuln compliance active-response; do
  curl -fsSL "${REPO_BASE}/templates/linux/${tmpl}.xml" -o "${TEMPLATES_DST}/${tmpl}.xml"
done
ok "Templates installed."

# ── Start agent ───────────────────────────────────────────────────────────────
log "Starting agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent && ok "Agent service started." || {
  warn "Agent failed to start. Error:"
  grep -i "error" /var/ossec/logs/ossec.log | tail -3 || true
  warn "Fix with: tail -20 /var/ossec/logs/ossec.log"
}

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
echo ""
echo -e "  Run the management console:"
echo -e "    ${CYAN}${BOLD}sudo codered-agent${RESET}"
echo ""

read -rp "  Run log discovery scan now? [Y/n]: " RUN_SCAN < /dev/tty
if [[ "${RUN_SCAN,,}" != "n" ]]; then
  echo ""
  "${CLI_BIN}" scan
fi
