#!/usr/bin/env bash

# Includes are normally sourced by harden.sh; do not leak strict mode into the parent shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

invoke_local_policy () {
  echo -e "${CYAN}[Local Policy] Start${NC}"

  # Restore/install sudo first so the remaining tasks can run even if sudo
  # was missing from a previous run. This function runs directly as root.
  if ! lp_secure_sudo; then
    echo "Warning: sudo repair failed; continuing with local policy tasks."
  fi

  if ! lp_sysctl_ipv6_all; then echo "Warning: IPv6 all-interface sysctl task failed; continuing."; fi
  if ! lp_sysctl_ipv6_default; then echo "Warning: IPv6 default sysctl task failed; continuing."; fi
  if ! lp_sysctl_ipv4_all; then echo "Warning: IPv4 all-interface sysctl task failed; continuing."; fi
  if ! lp_sysctl_ipv4_default; then echo "Warning: IPv4 default sysctl task failed; continuing."; fi
  if ! lp_sysctl_ipv4_misc; then echo "Warning: IPv4 miscellaneous sysctl task failed; continuing."; fi
  if ! lp_sysctl_fs_kernel; then echo "Warning: filesystem/kernel sysctl task failed; continuing."; fi
  if ! lp_sysctl_persist_and_reload; then echo "Warning: persistent sysctl task failed; continuing."; fi

  echo -e "${CYAN}[Local Policy] Done${NC}"
}

# -------------------------------------------------------------------
# IPv6 sysctl (all interfaces)
# -------------------------------------------------------------------
lp_sysctl_ipv6_all () {
for key in \
    net.ipv6.conf.all.accept_ra \
    net.ipv6.conf.all.accept_redirects \
    net.ipv6.conf.all.accept_source_route \
    net.ipv6.conf.all.forwarding; do
if sudo sysctl -w "$key=0" >/dev/null 2>&1; then
echo "Set $key=0"
else
echo "Warning: Could not set $key=0"
fi
done
}

# -------------------------------------------------------------------
# IPv6 sysctl (default interface template)
# -------------------------------------------------------------------
lp_sysctl_ipv6_default () {
 for key in \
    net.ipv6.conf.default.accept_ra \
    net.ipv6.conf.default.accept_redirects \
    net.ipv6.conf.default.accept_source_route; do
if sudo sysctl -w "$key=0" >/dev/null 2>&1; then
echo "Set $key=0"
else
echo "Warning: Could not set $key=0"
fi
done
}

# -------------------------------------------------------------------
# IPv4 sysctl (all interfaces)
# -------------------------------------------------------------------
lp_sysctl_ipv4_all () {
for key in \
    net.ipv4.conf.all.accept_redirects \
    net.ipv4.conf.all.accept_source_route \
    net.ipv4.conf.all.log_martians \
    net.ipv4.conf.all.rp_filter \
    net.ipv4.conf.all.secure_redirects \
    net.ipv4.conf.all.send_redirects; do
value=0
[[ "$key" == "net.ipv4.conf.all.log_martians" || "$key" == "net.ipv4.conf.all.rp_filter" ]] && value=1

if sudo sysctl -w "$key=$value" >/dev/null 2>&1; then
    echo "Set $key=$value"
else
    echo "Warning: Could not set $key=$value"
fi

done
}

# -------------------------------------------------------------------
# IPv4 sysctl (default interface template)
# -------------------------------------------------------------------
lp_sysctl_ipv4_default () {
 for key in \
    net.ipv4.conf.default.accept_redirects \
    net.ipv4.conf.default.accept_source_route \
    net.ipv4.conf.default.log_martians \
    net.ipv4.conf.default.rp_filter \
    net.ipv4.conf.default.secure_redirects \
    net.ipv4.conf.default.send_redirects; do
value=0
[[ "$key" == "net.ipv4.conf.default.log_martians" || "$key" == "net.ipv4.conf.default.rp_filter" ]] && value=1

if sudo sysctl -w "$key=$value" >/dev/null 2>&1; then
    echo "Set $key=$value"
else
    echo "Warning: Could not set $key=$value"
fi

done
}

# -------------------------------------------------------------------
# IPv4 misc (ICMP, TCP, forwarding)
# -------------------------------------------------------------------
lp_sysctl_ipv4_misc () {
for key in \
    net.ipv4.icmp_echo_ignore_broadcasts \
    net.ipv4.icmp_ignore_bogus_error_responses \
    net.ipv4.tcp_syncookies \
    net.ipv4.ip_forward; do
if sudo sysctl -w "$key=1" >/dev/null 2>&1; then
echo "Set $key=1"
else
echo "Warning: Could not set $key=1"
fi
done

sudo sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 &&
echo "Set net.ipv4.ip_forward=0" ||
echo "Warning: Could not set net.ipv4.ip_forward=0"
}

# -------------------------------------------------------------------
# Filesystem & kernel hardening
# -------------------------------------------------------------------
lp_sysctl_fs_kernel () {
for key in \
    fs.protected_hardlinks \
    fs.protected_symlinks \
    fs.suid_dumpable \
    kernel.randomize_va_space; do
case "$key" in
fs.protected_hardlinks|fs.protected_symlinks) value=1 ;;
fs.suid_dumpable) value=0 ;;
kernel.randomize_va_space) value=2 ;;
esac

if sudo sysctl -w "$key=$value" >/dev/null 2>&1; then
    echo "Set $key=$value"
else
    echo "Warning: Could not set $key=$value"
fi

done
}

# -------------------------------------------------------------------
# Persist sysctl settings and reload
# -------------------------------------------------------------------
lp_sysctl_persist_and_reload () {
config="/etc/sysctl.d/99-hardening.conf"
timestamp=$(date +%Y%m%d_%H%M%S)

if [[ -f "$config" ]]; then
sudo cp -a "$config" "${config}.${timestamp}.bak"
fi

tmp=$(mktemp)

cat > "$tmp" <<'EOF'
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.ip_forward=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.suid_dumpable=0
kernel.randomize_va_space=2
EOF

sudo install -m 0644 "$tmp" "$config"
rm -f "$tmp"

echo "Wrote sysctl hardening settings to $config."

if sudo sysctl --system >/dev/null 2>&1; then
echo "Sysctl settings reloaded successfully."
else
echo "Warning: Sysctl reload encountered an error."
fi
}

# -------------------------------------------------------------------
# Secure sudo (dangerous if misused; stub only)
# -------------------------------------------------------------------
lp_secure_sudo () {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Warning: sudo hardening requires root; skipping."
    return 1
  fi

  mkdir -p /etc/sudoers.d
  find /etc/sudoers.d/ -mindepth 1 -maxdepth 1 -type f -delete 2>/dev/null || true
  echo "Cleared files under /etc/sudoers.d/."

  # Repair any interrupted package configuration before installing sudo.
  if ! DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null 2>&1; then
    echo "Warning: dpkg configuration repair reported an error; continuing."
  fi

  if ! DEBIAN_FRONTEND=noninteractive apt-get -f install -y -qq >/dev/null 2>&1; then
    echo "Warning: APT dependency repair reported an error; continuing."
  fi

  if dpkg-query -W -f='${Status}' sudo 2>/dev/null | grep -q '^install ok installed$'; then
    echo "Sudo is installed; reinstalling the package..."
    install_cmd=(apt-get install --reinstall -y -qq sudo)
  else
    echo "Sudo is not installed; installing the package..."
    install_cmd=(apt-get install -y -qq sudo)
  fi

  if DEBIAN_FRONTEND=noninteractive "${install_cmd[@]}" >/dev/null 2>&1; then
    echo "Sudo package installed/reinstalled successfully."
  else
    echo "Warning: Sudo installation attempt failed; refreshing APT indexes and retrying..."

    if DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
       DEBIAN_FRONTEND=noninteractive apt-get install -y sudo; then
      echo "Sudo package installed/reinstalled successfully after retry."
    else
      echo "Warning: Final sudo installation attempt failed."
      return 1
    fi
  fi

  if command -v sudo >/dev/null 2>&1; then
    echo "Verified: sudo is installed."
  else
    echo "Warning: sudo is still not available after installation attempts."
    return 1
  fi
}
