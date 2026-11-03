#!/usr/bin/env bash
#set -euo pipefail

# --- elevation guard (re-exec with sudo if not root) ---
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo -E bash "$0" "$@"
fi

# --- locate repo root / source config & includes ---
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${ROOT_DIR}/config.sh"

# shellcheck source=./includes/*.sh
for f in "${ROOT_DIR}/includes/"*.sh; do source "$f"; done

# Included modules are sourced into this shell. Disable errexit after sourcing
# so one failed remediation step cannot terminate the interactive menu.
set +e

# --- UI helpers ---
C_CYAN="$(tput setaf 6 || true)"; C_GREEN="$(tput setaf 2 || true)"
C_WHITE="$(tput setaf 7 || true)"; C_RED="$(tput setaf 1 || true)"; C_RESET="$(tput sgr0 || true)"

write_menu_item () {
  local num="$1" text="$2" executed="$3"
  if [[ "$executed" == "1" ]]; then
    printf "%b%s. %s%b\n" "$C_GREEN" "$num" "$text" "$C_RESET"
  else
    printf "%b%s. %s%b\n" "$C_WHITE" "$num" "$text" "$C_RESET"
  fi
}

# Track completed tasks in an associative array
declare -A COMPLETED=()

# --- main menu loop ---
while true; do
  printf "\n%bLinux Mint Hardening Menu%b\n" "$C_CYAN" "$C_RESET"
  write_menu_item  1 "Document System"                   "${COMPLETED[1]:-0}"
  write_menu_item  2 "OS Updates"                        "${COMPLETED[2]:-0}"
  write_menu_item  3 "User Auditing"                     "${COMPLETED[3]:-0}"
  write_menu_item  4 "Account Policy"                    "${COMPLETED[4]:-0}"
  write_menu_item  5 "Local Policy"                      "${COMPLETED[5]:-0}"
  write_menu_item  6 "Defensive Countermeasures"         "${COMPLETED[6]:-0}"
  write_menu_item  7 "Uncategorized OS Settings"         "${COMPLETED[7]:-0}"
  write_menu_item  8 "Service Auditing"                  "${COMPLETED[8]:-0}"
  write_menu_item  9 "Application Updates"               "${COMPLETED[9]:-0}"
  write_menu_item 10 "Prohibited Files"                  "${COMPLETED[10]:-0}"
  write_menu_item 11 "Unwanted Software"                 "${COMPLETED[11]:-0}"
  write_menu_item 12 "Malware"                           "${COMPLETED[12]:-0}"
  write_menu_item 13 "Application Security (submenu)"    "${COMPLETED[13]:-0}"
  write_menu_item 14 "Exit"                              "0"

  read -rp $'\nEnter choice: ' choice
  case "$choice" in
    1)  invoke_document_system;                 COMPLETED[1]=1  ;;
    2)  invoke_os_updates;                      COMPLETED[2]=1  ;;
    3)  invoke_user_auditing;                   COMPLETED[3]=1  ;;
    4)  invoke_account_policy;                  COMPLETED[4]=1  ;;
    5)  invoke_local_policy;                    COMPLETED[5]=1  ;;
    6)  invoke_defensive_countermeasures;       COMPLETED[6]=1  ;;
    7)  invoke_uncategorized_os;                COMPLETED[7]=1  ;;
    8)  invoke_service_auditing;                COMPLETED[8]=1  ;;
    9)  invoke_application_updates;             COMPLETED[9]=1  ;;
    10) invoke_prohibited_files;                COMPLETED[10]=1 ;;
    11) invoke_unwanted_software;               COMPLETED[11]=1 ;;
    12) invoke_malware;                         COMPLETED[12]=1 ;;
    13) invoke_application_security_menu;       COMPLETED[13]=1 ;;
    14) printf "%bBye%b\n" "$C_CYAN" "$C_RESET"; exit 0 ;;
    *)  printf "%bInvalid option%b\n" "$C_RED" "$C_RESET" ;;
  esac
done
