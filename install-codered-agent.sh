#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# CodeRed Server Agent — Linux Installer
# Supports: Ubuntu 20.04/22.04, Debian 11/12, CentOS/RHEL 8/9
# ─────────────────────────────────────────────────────────────────────────────
set -e

MANAGER_IP="${CODERED_MANAGER_IP:-}"
AGENT_VERSION="4.7.3"
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

# ── Install Wazuh agent ───────────────────────────────────────────────────────
install_wazuh_deb() {
  log "Adding Wazuh repository (apt)..."
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

  apt-get update -qq
  WAZUH_MANAGER="${MANAGER_IP}" apt-get install -y wazuh-agent
}

install_wazuh_rpm() {
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

  WAZUH_MANAGER="${MANAGER_IP}" yum install -y wazuh-agent
}

case "$OS_ID" in
  ubuntu|debian)
    install_wazuh_deb ;;
  centos|rhel|rocky|almalinux|fedora)
    install_wazuh_rpm ;;
  *)
    die "Unsupported OS: ${OS_ID}. Supported: Ubuntu, Debian, CentOS, RHEL, Rocky, AlmaLinux." ;;
esac

ok "Wazuh agent installed."

# ── Set manager IP in ossec.conf ──────────────────────────────────────────────
log "Configuring manager IP..."
sed -i "s|MANAGER_IP|${MANAGER_IP}|g" /var/ossec/etc/ossec.conf
ok "Manager IP configured."

# ── Install CodeRed CLI ───────────────────────────────────────────────────────
log "Installing CodeRed CLI..."
mkdir -p "${INSTALL_DIR}" "${TEMPLATES_DST}"

curl -fsSL "${REPO_BASE}/codered-agent" -o "${CLI_BIN}"
chmod +x "${CLI_BIN}"

# ── Download log discovery script ─────────────────────────────────────────────
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

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
echo ""
echo -e "  Available commands:"
echo -e "    ${CYAN}${BOLD}sudo codered-agent scan${RESET}              — Scan & recommend logs to monitor"
echo -e "    ${CYAN}sudo codered-agent setup${RESET}             — Interactive module setup wizard"
echo -e "    ${CYAN}sudo codered-agent status${RESET}            — View module status"
echo -e "    ${CYAN}sudo codered-agent enable <module>${RESET}   — Enable a module"
echo -e "    ${CYAN}sudo codered-agent disable <module>${RESET}  — Disable a module"
echo ""

read -rp "  Run log discovery scan now? (recommended) [Y/n]: " RUN_SCAN
if [[ "${RUN_SCAN,,}" != "n" ]]; then
  echo ""
  codered-agent scan
fi
