#!/usr/bin/env bash
# Linux Mint-specific OS update handling.
# Mint's normal repository layout uses /etc/apt/sources.list.d/official-package-
# repositories.list rather than the Ubuntu-only /etc/apt/sources.list path.

# Includes are normally sourced by harden.sh; do not leak strict mode into the parent shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

invoke_os_updates () {
  echo -e "${CYAN}[OS Updates - Linux Mint] Start${NC}"

  if ! osu_update_sources_for_mint; then
    echo "Warning: Mint APT source remediation encountered an error."
  fi

  if ! osu_apt_update; then
    echo "Warning: APT index update encountered an error."
  fi

  if ! osu_fix_broken_packages; then
    echo "Warning: Broken-package repair encountered an error."
  fi

  if ! osu_unhold_packages; then
    echo "Warning: Held-package cleanup encountered an error."
  fi

  if ! osu_enable_security_auto_updates; then
    echo "Warning: Automatic security-update configuration encountered an error."
  fi

  if ! osu_install_important_updates; then
    echo "Warning: Important/security update installation encountered an error."
  fi

  echo -e "${CYAN}[OS Updates - Linux Mint] Done${NC}"
  return 0
}

osu_update_sources_for_mint () {
  local mint_codename ubuntu_codename file timestamp backup

  if [[ ! -r /etc/os-release ]]; then
    echo "Error: /etc/os-release is unavailable."
    return 1
  fi

  source /etc/os-release
  mint_codename="${VERSION_CODENAME:-${CODENAME:-}}"
  ubuntu_codename="${UBUNTU_CODENAME:-}"

  if [[ "${ID:-}" != "linuxmint" ]]; then
    echo "Error: This Mint build detected a non-Mint system."
    return 1
  fi

  if [[ -z "$mint_codename" || -z "$ubuntu_codename" ]]; then
    echo "Error: Could not determine Mint/Ubuntu codenames."
    return 1
  fi

  file="/etc/apt/sources.list.d/official-package-repositories.list"
  timestamp="$(date +%Y%m%d_%H%M%S)"
  backup="${file}.${timestamp}.bak"

  if [[ -f "$file" ]]; then
    if ! cp -a "$file" "$backup"; then
      echo "Error: Could not back up $file."
      return 1
    fi
    echo "Mint repository backup: $backup"
  fi

  if ! cat > "$file" <<EOF
# Managed by NOJE Linux Mint hardening script
# Linux Mint repository
deb https://packages.linuxmint.com $mint_codename main upstream import backport
# Ubuntu base repositories used by Linux Mint
deb https://archive.ubuntu.com/ubuntu $ubuntu_codename main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu $ubuntu_codename-updates main restricted universe multiverse
deb https://archive.ubuntu.com/ubuntu $ubuntu_codename-backports main restricted universe multiverse
deb https://security.ubuntu.com/ubuntu $ubuntu_codename-security main restricted universe multiverse
EOF
  then
    echo "Error: Could not write $file."
    return 1
  fi

  chown root:root "$file"
  chmod 0644 "$file"
  echo "Linux Mint sources set for $mint_codename using Ubuntu $ubuntu_codename."

  osu_disable_duplicate_ubuntu_sources "$ubuntu_codename"
}

osu_disable_duplicate_ubuntu_sources () {
  local ubuntu_codename timestamp path tmp
  ubuntu_codename="$1"
  timestamp="$(date +%Y%m%d_%H%M%S)"

  # Remove only duplicate official Ubuntu lines from /etc/apt/sources.list.
  if [[ -f /etc/apt/sources.list ]] &&
     grep -Eq "^[[:space:]]*deb[[:space:]]+https?://(archive\.ubuntu\.com/ubuntu|security\.ubuntu\.com/ubuntu)[[:space:]]+(${ubuntu_codename}|${ubuntu_codename}-updates|${ubuntu_codename}-backports|${ubuntu_codename}-security)([[:space:]]|$)" /etc/apt/sources.list; then
    cp -a /etc/apt/sources.list "/etc/apt/sources.list.${timestamp}.bak"
    tmp="$(mktemp)"
    awk -v base="$ubuntu_codename" '
      function duplicate_line() {
        return ($0 ~ "^[[:space:]]*deb[[:space:]]+https?://archive\\.ubuntu\\.com/ubuntu[[:space:]]+" base "([[:space:]]|$)" ||
                $0 ~ "^[[:space:]]*deb[[:space:]]+https?://archive\\.ubuntu\\.com/ubuntu[[:space:]]+" base "-updates([[:space:]]|$)" ||
                $0 ~ "^[[:space:]]*deb[[:space:]]+https?://archive\\.ubuntu\\.com/ubuntu[[:space:]]+" base "-backports([[:space:]]|$)" ||
                $0 ~ "^[[:space:]]*deb[[:space:]]+https?://security\\.ubuntu\\.com/ubuntu[[:space:]]+" base "-security([[:space:]]|$)")
      }
      { if (duplicate_line()) next; print }
    ' /etc/apt/sources.list > "$tmp"
    mv "$tmp" /etc/apt/sources.list
    echo "Removed duplicate Ubuntu entries from /etc/apt/sources.list; original backed up."
  fi

  # Mint 22.x normally uses official-package-repositories.list. If the common
  # ubuntu.sources file duplicates the same Ubuntu layers, disable only that
  # obvious file and preserve the original as a backup.
  path="/etc/apt/sources.list.d/ubuntu.sources"
  if [[ -f "$path" ]] &&
     grep -Eq "^[[:space:]]*Suites:.*\b${ubuntu_codename}(-updates|-backports|-security)?\b" "$path" &&
     grep -Eq "^[[:space:]]*URIs:[[:space:]]*https?://(archive\.ubuntu\.com|security\.ubuntu\.com)/ubuntu/?[[:space:]]*$" "$path"; then
    mv "$path" "${path}.${timestamp}.bak"
    echo "Disabled duplicate $path; original backed up."
  fi
}

osu_apt_update () {
  echo "Updating APT package indexes..."
  if apt-get update -qq; then
    echo "APT package indexes updated."
    return 0
  fi
  echo "Warning: APT package index update failed."
  return 1
}

osu_install_important_updates () {
  echo "Installing available important/security updates..."

  if DEBIAN_FRONTEND=noninteractive \
    apt-get \
    -o APT::Get::Always-Include-Phased-Updates=true \
    -o Dpkg::Options::="--force-confold" \
    --with-new-pkgs \
    upgrade -y; then
    echo "Important/security updates installed."
    return 0
  fi

  echo "Warning: Important/security update installation failed."
  return 1
}

osu_enable_security_auto_updates () {
  local file="/etc/apt/apt.conf.d/20auto-upgrades"
  local timestamp tmp
  timestamp="$(date +%Y%m%d_%H%M%S)"

  if [[ -f "$file" ]]; then
    cp -a "$file" "${file}.${timestamp}.bak"
  fi

  tmp="$(mktemp)"
  if [[ -f "$file" ]]; then
    grep -vE '^[[:space:]]*APT::Periodic::(Update-Package-Lists|Unattended-Upgrade)[[:space:]]' "$file" > "$tmp" || true
  fi

  cat >> "$tmp" <<'EOF'
# Managed by NOJE Linux Mint hardening script
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

  if ! install -m 0644 -o root -g root "$tmp" "$file"; then
    rm -f "$tmp"
    echo "Error: Could not install $file."
    return 1
  fi
  rm -f "$tmp"

  echo "APT automatic security-update checks enabled via $file."
  return 0
}

osu_fix_broken_packages () {
  echo "Attempting to fix broken package dependencies..."
  if DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y -qq; then
    echo "Broken package dependencies fixed."
    return 0
  fi
  echo "Warning: Failed to fix broken package dependencies."
  return 1
}

osu_unhold_packages () {
  local held_packages package
  held_packages="$(apt-mark showhold)"

  if [[ -z "$held_packages" ]]; then
    echo "No held packages found."
    return 0
  fi

  while IFS= read -r package; do
    [[ -z "$package" ]] && continue
    if apt-mark unhold "$package" >/dev/null 2>&1; then
      echo "Unheld: $package"
    else
      echo "Warning: Failed to unhold $package; continuing."
    fi
  done <<< "$held_packages"
  return 0
}
