#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# CodeRed Server Agent — Linux Installer
# Supports: Ubuntu 20.04/22.04, Debian 11/12, CentOS/RHEL 8/9, Fedora
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
[[ $EUID -ne 0 ]] && die "Please run as root: sudo bash install-codered-agent.sh"

banner

# ── Dependency check ──────────────────────────────────────────────────────────
log "Checking dependencies..."
for dep in curl gpg python3; do
  if ! command -v "$dep" &>/dev/null; then
    warn "$dep not found — installing..."
    if command -v apt-get &>/dev/null; then
      apt-get install -y "$dep" -qq
    elif command -v dnf &>/dev/null; then
      dnf install -y "$dep" -q
    elif command -v yum &>/dev/null; then
      yum install -y "$dep" -q
    else
      die "Cannot install $dep — please install it manually and re-run."
    fi
  fi
done
ok "All dependencies satisfied."

# ── Prompt for Manager IP ─────────────────────────────────────────────────────
if [[ -z "$MANAGER_IP" ]]; then
  echo -e "${BOLD}  Enter your CodeRed Manager IP or hostname:${RESET}"
  read -rp "  > " MANAGER_IP
  [[ -z "$MANAGER_IP" ]] && die "Manager IP is required."
fi
log "Manager: ${BOLD}${MANAGER_IP}${RESET}"

# ── Detect OS ─────────────────────────────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  OS_ID=$ID
else
  die "Cannot detect OS."
fi
log "Detected OS: ${OS_ID}"

# ── Remove existing agent cleanly ─────────────────────────────────────────────
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
  log "Stopping existing agent..."
  systemctl stop wazuh-agent || true
fi

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

case "$OS_ID" in
  ubuntu|debian)          install_deb ;;
  centos|rhel|rocky|almalinux|fedora) install_rpm ;;
  *) die "Unsupported OS: ${OS_ID}" ;;
esac
ok "Wazuh agent package installed."

# ── Validate ossec.conf was created ──────────────────────────────────────────
if [[ ! -f "$OSSEC_CONF" ]]; then
  die "ossec.conf not found at ${OSSEC_CONF} — Wazuh install may have failed."
fi

CONF_SIZE=$(wc -c < "$OSSEC_CONF")
if [[ "$CONF_SIZE" -lt 100 ]]; then
  die "ossec.conf is empty or too small (${CONF_SIZE} bytes). Wazuh install failed."
fi
ok "ossec.conf exists and has content (${CONF_SIZE} bytes)."

# ── Set manager IP ────────────────────────────────────────────────────────────
log "Setting manager IP to ${MANAGER_IP}..."
if grep -q "<address>" "$OSSEC_CONF"; then
  sed -i "s|<address>.*</address>|<address>${MANAGER_IP}</address>|g" "$OSSEC_CONF"
else
  sed -i "s|MANAGER_IP|${MANAGER_IP}|g" "$OSSEC_CONF"
fi

# Verify the IP was set
if ! grep -q "${MANAGER_IP}" "$OSSEC_CONF"; then
  warn "Could not verify manager IP in config. Adding manually..."
  # Add client block if missing
  python3 -c "
content = open('${OSSEC_CONF}').read()
client_block = '''
  <client>
    <server>
      <address>${MANAGER_IP}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <enrollment>
      <enabled>yes</enabled>
    </enrollment>
  </client>'''
if '<client>' not in content:
    content = content.replace('</ossec_config>', client_block + '\n</ossec_config>')
    open('${OSSEC_CONF}', 'w').write(content)
    print('Client block added.')
"
fi
ok "Manager IP configured."

# ── Fix any invalid log formats in existing config ────────────────────────────
log "Validating ossec.conf log formats..."
python3 -c "
import re, shutil
conf = '${OSSEC_CONF}'
valid = {'syslog','auth','apache','nginx','mysql_log','postgresql_log',
         'audit','json','iis','command','full_command','multi-line',
         'snort-full','snort-fast','squid','ossec','djb-multilog',
         'cisco-ios','cisco-asa'}
with open(conf) as f: content = f.read()
fixed_count = [0]
def fix(m):
    fmt = m.group(1).strip()
    if fmt not in valid:
        fixed_count[0] += 1
        return '<log_format>syslog</log_format>'
    return m.group(0)
fixed = re.sub(r'<log_format>(.*?)</log_format>', fix, content)
# Ensure exactly one closing tag
fixed = fixed.replace('</ossec_config>', '').rstrip()
fixed += '\n</ossec_config>\n'
with open(conf, 'w') as f: f.write(fixed)
if fixed_count[0]:
    print(f'Fixed {fixed_count[0]} invalid log format(s).')
else:
    print('All log formats valid.')
"

# ── Validate with wazuh-agentd -t ────────────────────────────────────────────
log "Running config validation..."
if cd /var/ossec && /var/ossec/bin/wazuh-agentd -t 2>&1; then
  ok "Config validation passed."
else
  die "Config validation failed. Check ${OSSEC_CONF}"
fi
cd - > /dev/null

# ── Remove old agent registration to avoid duplicate name error ───────────────
log "Clearing old agent registration..."
rm -f /var/ossec/etc/client.keys
ok "Agent keys cleared (will re-register with manager)."

# ── Install CodeRed CLI ───────────────────────────────────────────────────────
log "Installing CodeRed CLI..."
mkdir -p "${INSTALL_DIR}" "${TEMPLATES_DST}"
curl -fsSL "${REPO_BASE}/codered-agent" -o "${CLI_BIN}"
chmod +x "${CLI_BIN}"

# Set correct python3 path in shebang
PYTHON3_PATH="$(command -v python3)"
sed -i "1s|.*|#!${PYTHON3_PATH}|" "${CLI_BIN}"
ok "CLI installed to ${CLI_BIN}"

# ── Install log discovery engine ──────────────────────────────────────────────
log "Installing log discovery engine..."
curl -fsSL "${REPO_BASE}/codered-discover.py" -o "${INSTALL_DIR}/codered-discover.py"
chmod +x "${INSTALL_DIR}/codered-discover.py"
ok "Log discovery engine installed."

# ── Download module templates ─────────────────────────────────────────────────
log "Downloading Linux module templates..."
TEMPLATES=(log-collection fim inventory threat vuln compliance active-response)
for tmpl in "${TEMPLATES[@]}"; do
  curl -fsSL "${REPO_BASE}/templates/linux/${tmpl}.xml" -o "${TEMPLATES_DST}/${tmpl}.xml"
done
ok "Templates installed to ${TEMPLATES_DST}"

# ── Enable & start agent ──────────────────────────────────────────────────────
log "Enabling and starting agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Wait a moment and check status
sleep 3
if systemctl is-active --quiet wazuh-agent; then
  ok "Agent service is running."
else
  warn "Agent service failed to start. Checking log..."
  tail -10 /var/ossec/logs/ossec.log
  echo ""
  warn "Run: journalctl -xeu wazuh-agent --no-pager | tail -20"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
echo ""
echo -e "  Launch management console:"
echo -e "    ${CYAN}${BOLD}sudo codered-agent${RESET}"
echo ""
echo -e "  Or direct commands:"
echo -e "    ${CYAN}sudo codered-agent scan${RESET}       — Scan & choose log sources"
echo -e "    ${CYAN}sudo codered-agent setup${RESET}      — Enable/disable modules"
echo -e "    ${CYAN}sudo codered-agent status${RESET}     — View agent status"
echo ""

read -rp "  Run log discovery scan now? (recommended) [Y/n]: " RUN_SCAN
if [[ "${RUN_SCAN,,}" != "n" ]]; then
  echo ""
  "${CLI_BIN}" scan
fi
