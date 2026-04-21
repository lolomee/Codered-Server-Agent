#!/bin/bash
# CodeRed Server Agent - Linux Installer
set -e

INSTALL_DIR="/etc/codered"
CLI_BIN="/usr/local/bin/codered-agent"
TEMPLATES_DST="/etc/codered/templates/linux"
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

# Detect OS
[[ -f /etc/os-release ]] && . /etc/os-release || die "Cannot detect OS."
log "OS: ${ID} ${VERSION_ID}"

# Stop and purge old agent cleanly
systemctl stop wazuh-agent 2>/dev/null || true
if dpkg -l wazuh-agent &>/dev/null 2>&1; then
  log "Removing existing wazuh-agent..."
  # Remove immutable flag if previously set
  chattr -i /var/ossec/etc/client.keys 2>/dev/null || true
  apt-get remove --purge -y wazuh-agent -qq 2>/dev/null || true
  rm -rf /var/ossec /etc/ossec-init.conf
  ok "Old agent removed."
elif [[ -d /var/ossec ]]; then
  chattr -i /var/ossec/etc/client.keys 2>/dev/null || true
  rm -rf /var/ossec
fi

# Install Wazuh agent WITHOUT manager IP
# Registration will be done after install via the CLI (avoids duplicate name issues)
install_deb() {
  log "Adding Wazuh repository (apt)..."
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  apt-get install -y wazuh-agent
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
    dnf install -y wazuh-agent
  else
    yum install -y wazuh-agent
  fi
}

case "$ID" in
  ubuntu|debian)                       install_deb ;;
  centos|rhel|rocky|almalinux|fedora|ol|oraclelinux) install_rpm ;;
  *) die "Unsupported OS: ${ID}" ;;
esac
ok "Wazuh agent installed."

# Fix systemd WorkingDirectory so wazuh-execd can read ossec.conf via relative path
log "Applying systemd WorkingDirectory fix..."
mkdir -p /etc/systemd/system/wazuh-agent.service.d
cat > /etc/systemd/system/wazuh-agent.service.d/workdir.conf << 'UNITEOF'
[Service]
WorkingDirectory=/var/ossec
UNITEOF
ok "Systemd override written."

# Install CodeRed CLI
log "Installing CodeRed CLI..."
mkdir -p "${INSTALL_DIR}" "${TEMPLATES_DST}"
curl -fsSL "${REPO_BASE}/linux/codered-agent" -o "${CLI_BIN}"
chmod +x "${CLI_BIN}"
PYTHON3_PATH=$(command -v python3)
sed -i "1s|.*|#!${PYTHON3_PATH}|" "${CLI_BIN}"
ok "CLI installed at ${CLI_BIN}"

# On RHEL/CentOS/Oracle Linux, /usr/local/bin is not in sudo secure_path by default
# Create a symlink in /usr/bin so 'sudo codered-agent' works out of the box
if command -v rpm &>/dev/null && [[ ! -f /usr/bin/codered-agent ]]; then
  ln -sf "${CLI_BIN}" /usr/bin/codered-agent
  ok "Symlink created: /usr/bin/codered-agent (fixes sudo secure_path on Oracle/RHEL/CentOS)"
fi

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

systemctl daemon-reload
systemctl enable wazuh-agent

printf "\n%b\n" "${GREEN}${BOLD}Installation complete!${RESET}"
printf "\n  ${YELLOW}Next step: configure your Manager IP and register the agent:${RESET}\n"
printf "    %b\n\n" "${CYAN}${BOLD}sudo codered-agent${RESET}"
printf "  Then go to: ${BOLD}Settings → Set Manager IP${RESET}\n"
printf "  The agent will register and start automatically.\n\n"
