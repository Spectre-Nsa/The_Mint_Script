#!/usr/bin/env bash
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    set -euo pipefail
fi

invoke_uncategorized_os () {
  echo -e "${CYAN}[Uncategorized OS] Start${NC}"

  if ! uos_home_dir_permissions; then echo "Warning: Home directory permissions task failed; continuing."; fi
  if ! uos_login_defs_permissions; then echo "Warning: login.defs permissions task failed; continuing."; fi
  if ! uos_shadow_gshadow_permissions; then echo "Warning: shadow/gshadow permissions task failed; continuing."; fi
  if ! uos_passwd_group_permissions; then echo "Warning: passwd/group permissions task failed; continuing."; fi
  if ! uos_grub_permissions; then echo "Warning: GRUB permissions task failed; continuing."; fi
  if ! uos_system_map_permissions; then echo "Warning: System.map permissions task failed; continuing."; fi
  if ! uos_ssh_host_keys_permissions; then echo "Warning: SSH host key permissions task failed; continuing."; fi
  if ! uos_audit_rules_permissions; then echo "Warning: audit rules permissions task failed; continuing."; fi
  if ! uos_remove_world_writable_files; then echo "Warning: world-writable file cleanup failed; continuing."; fi
  if ! uos_report_unowned_files; then echo "Warning: unowned-file report failed; continuing."; fi
  if ! uos_var_log_permissions; then echo "Warning: /var/log permissions task failed; continuing."; fi
  if ! uos_tmp_permissions; then echo "Warning: /tmp permissions task failed; continuing."; fi

  echo -e "${CYAN}[Uncategorized OS] Done${NC}"
}

# -------------------------------------------------------------------
# Home directories: 0700 perms
# -------------------------------------------------------------------
uos_home_dir_permissions () {
find /home -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null |
while IFS= read -r -d '' dir; do
if sudo chmod 700 "$dir" 2>/dev/null; then
    echo "Set permissions to 700: $dir"
else
    echo "Warning: Could not chmod 700: $dir"
fi
done
}

# -------------------------------------------------------------------
# /etc/login.defs: 0600 root:root
# -------------------------------------------------------------------
uos_login_defs_permissions () {
if sudo chown root:root /etc/login.defs && sudo chmod 0600 /etc/login.defs; then
    echo "Secured /etc/login.defs ownership and permissions."
else
    echo "Warning: Could not secure /etc/login.defs."
    return 1
fi
}

# -------------------------------------------------------------------
# shadow/gshadow and backups: 0640 root:shadow
# -------------------------------------------------------------------
uos_shadow_gshadow_permissions () {
for file in /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-; do
if [[ -e "$file" ]]; then
    if sudo chown root:shadow "$file" && sudo chmod 0640 "$file"; then
        echo "Secured $file: root:shadow 0640"
    else
        echo "Warning: Could not secure $file."
    fi
fi
done
}

# -------------------------------------------------------------------
# passwd/group and backups: 0644 root:root
# -------------------------------------------------------------------
uos_passwd_group_permissions () {
for file in /etc/passwd /etc/passwd- /etc/group /etc/group-; do
if [[ -e "$file" ]]; then
    if sudo chown root:root "$file" && sudo chmod 0644 "$file"; then
        echo "Secured $file: root:root 0644"
    else
        echo "Warning: Could not secure $file."
    fi
fi
done
}

# -------------------------------------------------------------------
# GRUB config: 0600 root:root
# -------------------------------------------------------------------
uos_grub_permissions () {
if [[ -e /boot/grub/grub.cfg ]]; then
    if sudo chown root:root /boot/grub/grub.cfg && sudo chmod 0600 /boot/grub/grub.cfg; then
        echo "Secured /boot/grub/grub.cfg: root:root 0600"
    else
        echo "Warning: Could not secure /boot/grub/grub.cfg."
        return 1
    fi
else
    echo "/boot/grub/grub.cfg not found; skipping."
fi
}

# -------------------------------------------------------------------
# System.map (if present): 0600 root:root
# -------------------------------------------------------------------
uos_system_map_permissions () {
for file in /boot/System.map-*; do
if [[ -f "$file" ]]; then
    if sudo chown root:root "$file" 2>/dev/null && sudo chmod 0600 "$file" 2>/dev/null; then
        echo "Secured $file: root:root 0600"
    else
        echo "Warning: Could not secure $file."
    fi
fi
done
}

# -------------------------------------------------------------------
# SSH host keys: secure all private keys (including Ed25519) and public keys
# -------------------------------------------------------------------
uos_ssh_host_keys_permissions () {
for file in /etc/ssh/ssh_host_*_key; do
[[ -f "$file" ]] || continue
    if sudo chown root:root "$file" && sudo chmod 0600 "$file"; then
        echo "Secured SSH host private key: $file (0600)"
    else
        echo "Warning: Could not secure $file."
    fi
done

for file in /etc/ssh/ssh_host_*_key.pub; do
[[ -f "$file" ]] || continue
    if sudo chown root:root "$file" && sudo chmod 0644 "$file"; then
        echo "Secured SSH host public key: $file (0644)"
    else
        echo "Warning: Could not secure $file."
    fi
done
}

# -------------------------------------------------------------------
# Audit rules: remove dangerous bits on /etc/audit/rules.d/*.rules
# -------------------------------------------------------------------
uos_audit_rules_permissions () {
find /etc/audit/rules.d/ -maxdepth 1 -type f -name '*.rules' -print0 2>/dev/null |
while IFS= read -r -d '' file; do
if sudo chmod u-s,g-ws,o-wrx "$file" 2>/dev/null; then
    echo "Normalized permissions: $file"
else
    echo "Warning: Could not normalize permissions: $file"
fi
done
}

# -------------------------------------------------------------------
# Remove world-writable files (clear o+w) on local filesystems
# -------------------------------------------------------------------
uos_remove_world_writable_files () {
while IFS= read -r mount; do
find "$mount" -xdev -type f -perm -0002 -print0 2>/dev/null |
while IFS= read -r -d '' file; do
if sudo chmod o-w "$file" 2>/dev/null; then
    echo "Removed world-write permission: $file"
else
    echo "Warning: Could not remove world-write permission: $file"
fi
done
done < <(df --local -P 2>/dev/null | awk 'NR > 1 {print $6}')
}

# -------------------------------------------------------------------
# Report files without user/group ownership (no destructive fix)
# -------------------------------------------------------------------
uos_report_unowned_files () {
mkdir -p "$DOCS"

report="$DOCS/unowned_files.txt"
: > "$report"

while IFS= read -r mount; do
find "$mount" -xdev \(-nouser -o -nogroup\) -print 2>/dev/null
done < <(df --local -P 2>/dev/null | awk 'NR > 1 {print $6}') > "$report"

count=$(wc -l < "$report")
echo "Found $count unowned files/directories. Report: $report"
}

# -------------------------------------------------------------------
# Normalize /var/log permissions to 0640 for files
# -------------------------------------------------------------------
uos_var_log_permissions () {
find /var/log -type f -print0 2>/dev/null |
while IFS= read -r -d '' file; do
if sudo chmod 0640 "$file" 2>/dev/null; then
    echo "Set permissions to 0640: $file"
else
    echo "Warning: Could not chmod 0640: $file"
fi
done
}

# -------------------------------------------------------------------
# /tmp and /var/tmp: 1777 root:root
# -------------------------------------------------------------------
uos_tmp_permissions () {
for dir in /tmp /var/tmp; do
if sudo chown root:root "$dir" && sudo chmod 1777 "$dir"; then
    echo "Secured $dir: root:root 1777"
else
    echo "Warning: Could not secure $dir."
    return 1
fi
done
}
