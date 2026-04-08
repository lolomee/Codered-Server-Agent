#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# CodeRed Server Agent — Linux Installer
# Supports: Ubuntu 20.04/22.04, Debian 11/12, CentOS/RHEL 8/9, Fedora
# ─────────────────────────────────────────────────────────────────────────────
set -e

MANAGER_IP="${CODERED_MANAGER_IP:-}"
INSTALL_DIR="/etc/codered"
CLI_BIN="/usr/local/bin/codered-agent"
TEMPLATES_DST="/etc/codered/templates"
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
[[ $EUID -ne 0 ]] && die "Please run as root: sudo bash install-codered-agent.sh"

banner

# ── Dependency check ──────────────────────────────────────────────────────────
log "Checking dependencies..."
for dep in curl gpg python3; do
  if ! command -v "$dep" &>/dev/null; then
    warn "$dep not found — installing..."
    if command -v apt-get &>/dev/null; then
      apt-get install -y "$dep" -qq
    elif command -v yum &>/dev/null; then
      yum install -y "$dep" -q
    elif command -v dnf &>/dev/null; then
      dnf install -y "$dep" -q
    else
      die "Cannot install $dep — please install it manually and re-run."
    fi
  fi
done
ok "All dependencies satisfied."

# ── Prompt for Manager IP if not set ─────────────────────────────────────────
if [[ -z "$MANAGER_IP" ]]; then
  echo -e "${BOLD}  Enter your CodeRed Manager IP or hostname:${RESET}"
  read -rp "  > " MANAGER_IP
  [[ -z "$MANAGER_IP" ]] && die "Manager IP is required."
fi

log "Manager: ${BOLD}${MANAGER_IP}${RESET}"

# ── Detect OS ─────────────────────────────────────────────────────────────────
detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID=$ID
    OS_VERSION=$VERSION_ID
  else
    die "Cannot detect OS. Unsupported platform."
  fi
}

detect_os
log "Detected OS: ${OS_ID} ${OS_VERSION}"

# ── Install agent ─────────────────────────────────────────────────────────────
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

case "$OS_ID" in
  ubuntu|debian)
    install_deb ;;
  centos|rhel|rocky|almalinux|fedora)
    install_rpm ;;
  *)
    die "Unsupported OS: ${OS_ID}. Supported: Ubuntu, Debian, CentOS, RHEL, Rocky, AlmaLinux, Fedora." ;;
esac

ok "Agent installed."

# ── Configure manager IP ──────────────────────────────────────────────────────
log "Configuring manager IP in ossec.conf..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [[ -f "$OSSEC_CONF" ]]; then
  # Replace existing <address> tag if present, otherwise replace placeholder
  if grep -q "<address>" "$OSSEC_CONF"; then
    sed -i "s|<address>.*</address>|<address>${MANAGER_IP}</address>|g" "$OSSEC_CONF"
  else
    sed -i "s|MANAGER_IP|${MANAGER_IP}|g" "$OSSEC_CONF"
  fi
  ok "Manager IP set to ${MANAGER_IP}"
else
  warn "ossec.conf not found at ${OSSEC_CONF} — skipping IP configuration."
fi

# ── Install CodeRed CLI ───────────────────────────────────────────────────────
log "Installing CodeRed CLI..."
mkdir -p "${INSTALL_DIR}" "${TEMPLATES_DST}"

curl -fsSL "${REPO_BASE}/codered-agent" -o "${CLI_BIN}"
chmod +x "${CLI_BIN}"
ok "CLI installed to ${CLI_BIN}"

# ── Install log discovery engine ──────────────────────────────────────────────
log "Installing log discovery engine..."
curl -fsSL "${REPO_BASE}/codered-discover.py" -o "${INSTALL_DIR}/codered-discover.py"
chmod +x "${INSTALL_DIR}/codered-discover.py"
ok "Log discovery engine installed."

# ── Download module templates ─────────────────────────────────────────────────
log "Downloading module templates..."
TEMPLATES=(log-collection fim inventory threat vuln compliance active-response)
for tmpl in "${TEMPLATES[@]}"; do
  curl -fsSL "${REPO_BASE}/templates/${tmpl}.xml" -o "${TEMPLATES_DST}/${tmpl}.xml"
done
ok "Templates installed to ${TEMPLATES_DST}"

# ── Enable & start agent ──────────────────────────────────────────────────────
log "Enabling agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
ok "Agent service started."

# ── Hash the shebang so Python3 is used ──────────────────────────────────────
PYTHON3_PATH="$(command -v python3)"
sed -i "1s|.*|#!${PYTHON3_PATH}|" "${CLI_BIN}"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
echo ""
echo -e "  Run the management console:"
echo -e "    ${CYAN}${BOLD}sudo codered-agent${RESET}"
echo ""
echo -e "  Or use direct commands:"
echo -e "    ${CYAN}sudo codered-agent scan${RESET}       — Scan & choose log sources"
echo -e "    ${CYAN}sudo codered-agent setup${RESET}      — Enable/disable modules"
echo -e "    ${CYAN}sudo codered-agent status${RESET}     — View agent status"
echo ""

read -rp "  Run log discovery scan now? (recommended) [Y/n]: " RUN_SCAN
if [[ "${RUN_SCAN,,}" != "n" ]]; then
  echo ""
  "${CLI_BIN}" scan
fi
