#!/usr/bin/env bash

# Includes are normally sourced by harden.sh; do not leak strict mode into the parent shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

# Submenu orchestrator only; no task bodies.
invoke_application_security_menu () {
  while true; do
    echo
    echo "Application Security Menu"
    echo "  1) Secure Firefox"
    echo "  2) Secure Chrome/Chromium"
    echo "  3) Secure OpenSSH"
    echo "  4) Secure Samba"
    echo "  5) Secure DNS (resolvers)"
    echo "  6) Secure NGINX/Apache"
    echo "  7) Return to Main Menu"
    read -rp $'\nEnter choice: ' app_choice
    case "$app_choice" in
      1) appsec_secure_firefox ;;
      2) appsec_secure_chromium ;;
      3) appsec_secure_ssh ;;
      4) appsec_secure_samba ;;
      5) appsec_secure_dns ;;
      6) appsec_secure_web ;;
      7) return ;;
      *) echo "Invalid option";;
    esac
  done
}

# Sub-orchestrators (no bodies yet)
appsec_secure_firefox   () { echo "[AppSec] Firefox orchestrator (TODO)"; }
appsec_secure_chromium  () { echo "[AppSec] Chrome/Chromium orchestrator (TODO)"; }
appsec_secure_ssh       () { echo "[AppSec] OpenSSH orchestrator (TODO)"; }
appsec_secure_samba     () { echo "[AppSec] Samba orchestrator (TODO)"; }
appsec_secure_dns       () { echo "[AppSec] DNS/resolvers orchestrator (TODO)"; }
appsec_secure_web       () { echo "[AppSec] Web server orchestrator (TODO)"; }
