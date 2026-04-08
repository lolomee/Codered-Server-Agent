#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# CodeRed Server Agent — Linux Uninstaller
# ─────────────────────────────────────────────────────────────────────────────
set -e

RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"; BOLD="\033[1m"; RESET="\033[0m"

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ____          _      ____          _"
  echo " / ___|___   __| | ___|  _ \\ ___  __| |"
  echo "| |   / _ \\ / _\` |/ _ \\ |_) / _ \\/ _\` |"
  echo "| |__| (_) | (_| |  __/  _ <  __/ (_| |"
  echo " \\____\\___/ \\__,_|\\___|_| \\_\\___|\\__,_|"
  echo ""
  echo "  Server Agent — Uninstaller"
  echo -e "${RESET}"
}

log()  { echo -e "${CYAN}[*]${RESET} $*"; }
ok()   { echo -e "${GREEN}[✔]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
die()  { echo -e "${RED}[✖]${RESET} $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Please run as root: sudo bash uninstall-codered-agent.sh"

banner

echo -e "  ${YELLOW}${BOLD}This will remove CodeRed Server Agent from this system.${RESET}"
echo -e "  All agent config and collected state will be deleted.\n"
read -rp "  Are you sure? (y/N): " CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && echo -e "\n  ${YELLOW}Cancelled.${RESET}\n" && exit 0

echo ""

# ── Stop and disable service ──────────────────────────────────────────────────
log "Stopping CodeRed Agent service..."
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
  systemctl stop wazuh-agent
  ok "Service stopped."
else
  warn "Service was not running."
fi

if systemctl is-enabled --quiet wazuh-agent 2>/dev/null; then
  systemctl disable wazuh-agent
  ok "Service disabled."
fi

# ── Remove agent package ──────────────────────────────────────────────────────
log "Removing agent package..."
if command -v apt-get &>/dev/null; then
  apt-get remove --purge -y wazuh-agent 2>/dev/null || true
  ok "Package removed (apt)."
elif command -v yum &>/dev/null; then
  yum remove -y wazuh-agent 2>/dev/null || true
  ok "Package removed (yum)."
elif command -v dnf &>/dev/null; then
  dnf remove -y wazuh-agent 2>/dev/null || true
  ok "Package removed (dnf)."
else
  warn "Could not detect package manager. Please remove manually."
fi

# ── Remove CodeRed CLI and config ─────────────────────────────────────────────
log "Removing CodeRed CLI..."
rm -f /usr/local/bin/codered-agent
ok "CLI removed."

log "Removing CodeRed config and templates..."
rm -rf /etc/codered
ok "Config directory removed."

# ── Remove repo source ────────────────────────────────────────────────────────
log "Removing package repository..."
rm -f /etc/apt/sources.list.d/wazuh.list 2>/dev/null || true
rm -f /etc/yum.repos.d/wazuh.repo 2>/dev/null || true
rm -f /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
ok "Repository removed."

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}  CodeRed Server Agent has been removed.${RESET}"
echo -e "  All agent files and configuration have been cleaned up.\n"
