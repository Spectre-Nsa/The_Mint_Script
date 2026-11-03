#!/usr/bin/env bash

# Includes are normally sourced by harden.sh; do not leak strict mode into the parent shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

invoke_application_updates () {
  echo -e "${CYAN}[Application Updates] Start${NC}"

  au_apt_update_indexes
  au_apt_full_upgrade
  au_snap_refresh_all
  au_flatpak_update_all

  echo -e "${CYAN}[Application Updates] Done${NC}"
}

# ------------------------------------------------------------
# apt: update package indexes
# ------------------------------------------------------------
au_apt_update_indexes () {
  echo "Updating APT indexes..."

if ! sudo apt update -qq; then
echo "Warning: APT index update encountered an error."
fi

echo "APT index update complete."
}

# ------------------------------------------------------------
# apt: full upgrade (non-interactive)
# ------------------------------------------------------------
au_apt_full_upgrade () {
echo "Running APT full upgrade..."

if ! sudo DEBIAN_FRONTEND=noninteractive apt -o APT::Get::Always-Include-Phased-Updates=true full-upgrade -y -qq; then
echo "Warning: APT full upgrade encountered an error."
fi

echo "APT full upgrade complete."
}

# ------------------------------------------------------------
# snap: refresh all snaps (if snap is installed)
# ------------------------------------------------------------
au_snap_refresh_all () {
  if ! command -v snap >/dev/null 2>&1; then
echo "Snap not installed; skipping."
return
fi

echo "Refreshing Snap packages..."

if ! sudo snap refresh; then
echo "Warning: Snap refresh encountered an error."
fi

echo "Snap refresh complete."
}

# ------------------------------------------------------------
# flatpak: update all (if flatpak is installed)
# ------------------------------------------------------------
au_flatpak_update_all () {
  if ! command -v flatpak >/dev/null 2>&1; then
echo "Flatpak not installed; skipping."
return
fi

echo "Updating Flatpak apps/runtimes..."

if ! flatpak update -y; then
echo "Warning: Flatpak update encountered an error."
fi

echo "Flatpak update complete."
}
