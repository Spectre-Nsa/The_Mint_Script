#!/usr/bin/env bash

# Includes are normally sourced by harden.sh; do not leak strict mode into the parent shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

invoke_account_policy () {
  echo -e "${CYAN}[Account Policy] Start${NC}"

  if ! ap_secure_login_defs; then
    echo "Warning: /etc/login.defs policy update failed; continuing."
  fi

  if ! ap_pam_pwquality_inline; then
    echo "Warning: PAM pwquality update failed; continuing."
  fi

  if ! ap_pwquality_conf_file; then
    echo "Warning: /etc/security/pwquality.conf update failed; continuing."
  fi

  if ! ap_lockout_faillock; then
    echo "Warning: pam_faillock update failed; continuing."
  fi

  echo -e "${CYAN}[Account Policy] Done${NC}"
}

# -------------------------------------------------------------------
# /etc/login.defs hardening
# -------------------------------------------------------------------
ap_secure_login_defs () {
  local file="/etc/login.defs"
  local timestamp
  timestamp=$(date +%Y%m%d_%H%M%S)

  if [[ -f "$file" ]]; then
    sudo cp -a "$file" "${file}.${timestamp}.bak"
  else
    echo "Warning: $file not found."
    return 1
  fi

  while read -r key value; do
    if sudo grep -Eq "^[[:space:]]*#?[[:space:]]*${key}([[:space:]]+.*)?$" "$file" 2>/dev/null; then
      sudo sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}([[:space:]]+.*)?$|${key} ${value}|" "$file"
    else
      echo "${key} ${value}" | sudo tee -a "$file" >/dev/null
    fi

    echo "Set ${key} ${value}."
  done <<'SETTINGS'
PASS_MAX_DAYS 60
PASS_MIN_DAYS 10
PASS_WARN_AGE 14
UMASK 077
SETTINGS
}

# -------------------------------------------------------------------
# Insert pam_pwquality inline in common-password
# -------------------------------------------------------------------
ap_pam_pwquality_inline () {
  local file="/etc/pam.d/common-password"
  local timestamp
  local pwquality_line="password requisite pam_pwquality.so retry=3 minlen=10 difok=5 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"
  local tmp
  timestamp=$(date +%Y%m%d_%H%M%S)

  if [[ ! -f "$file" ]]; then
    echo "Warning: $file not found."
    return 1
  fi

  if ! find /lib /usr/lib -type f -name 'pam_pwquality.so' -print -quit 2>/dev/null | grep -q .; then
    echo "Warning: pam_pwquality.so is not installed; leaving $file unchanged."
    return 0
  fi

  sudo cp -a "$file" "${file}.${timestamp}.bak"

  tmp=$(mktemp)
  if sudo awk -v wanted="$pwquality_line" '
    BEGIN { found=0 }
    /^[[:space:]]*\$\{pwquality_line\}[[:space:]]*$/ { next }
    {
      if ($0 == wanted) {
        if (!found) {
          print wanted
          found=1
        }
        next
      }
      if (!found && $0 ~ /pam_unix\.so/) {
        print wanted
        found=1
      }
      print
    }
    END {
      if (!found) exit 2
    }
  ' "$file" > "$tmp"; then
    if sudo install -m 0644 "$tmp" "$file"; then
      echo "Ensured pam_pwquality rule in $file."
      rm -f "$tmp"
      return 0
    fi
  fi

  rm -f "$tmp"
  echo "Warning: Could not safely update $file."
  return 1
}

# -------------------------------------------------------------------
# Configure /etc/security/pwquality.conf
# -------------------------------------------------------------------
ap_pwquality_conf_file () {
  local file="/etc/security/pwquality.conf"
  local timestamp
  local tmp
  timestamp=$(date +%Y%m%d_%H%M%S)

  if [[ -f "$file" ]]; then
    sudo cp -a "$file" "${file}.${timestamp}.bak"
  else
    sudo touch "$file"
  fi

  while read -r key value; do
    if sudo grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=" "$file"; then
      sudo sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=.*$|${key} = ${value}|" "$file"
    else
      echo "${key} = ${value}" | sudo tee -a "$file" >/dev/null
    fi
    echo "Set ${key} = ${value}"
  done <<'SETTINGS'
minlen 10
minclass 2
maxrepeat 2
maxclassrepeat 6
lcredit -1
ucredit -1
dcredit -1
ocredit -1
maxsequence 2
difok 5
gecoscheck 1
SETTINGS
}

# -------------------------------------------------------------------
# Configure pam_faillock in common-auth/common-account
# -------------------------------------------------------------------
ap_lockout_faillock () {
  local auth_file="/etc/pam.d/common-auth"
  local account_file="/etc/pam.d/common-account"
  local timestamp
  local tmp
  local pam_unix_line
  local success_skip=0
  timestamp=$(date +%Y%m%d_%H%M%S)

  if [[ ! -f "$auth_file" || ! -f "$account_file" ]]; then
    echo "Warning: Required PAM files are missing."
    return 1
  fi

  if ! find /lib /usr/lib -type f -name 'pam_faillock.so' -print -quit 2>/dev/null | grep -q .; then
    echo "Warning: pam_faillock.so is not installed; leaving PAM authentication files unchanged."
    return 0
  fi

  pam_unix_line=$(grep -m1 -E '^[[:space:]]*auth[[:space:]]+\[[^]]*\][[:space:]]+pam_unix\.so([[:space:]]|$)' "$auth_file" || true)
  if [[ -z "$pam_unix_line" ]]; then
    echo "Warning: Could not find a bracketed auth pam_unix.so line; leaving $auth_file unchanged."
    return 1
  fi

  if [[ "$pam_unix_line" =~ \[[^]]*success=([0-9]+)[^]]*\] ]]; then
    success_skip="${BASH_REMATCH[1]}"
  else
    echo "Warning: Could not determine the pam_unix success jump count; leaving $auth_file unchanged."
    return 1
  fi

  sudo cp -a "$auth_file" "${auth_file}.${timestamp}.bak"
  sudo cp -a "$account_file" "${account_file}.${timestamp}.bak"

  local preauth_line="auth required pam_faillock.so preauth"
  local authfail_line="auth [default=die] pam_faillock.so authfail"
  local authsucc_line="auth sufficient pam_faillock.so authsucc"
  local account_line="account required pam_faillock.so"

  tmp=$(mktemp)
  if sudo awk \
      -v preauth="$preauth_line" \
      -v authfail="$authfail_line" \
      -v authsucc="$authsucc_line" \
      -v success_skip="$success_skip" '
    BEGIN {
      found=0
      succ_inserted=0
      remaining=success_skip-1
      if (remaining < 0) remaining=0
    }

    /^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]+preauth[[:space:]]*$/ { next }
    /^[[:space:]]*auth[[:space:]]+\[default=die\][[:space:]]+pam_faillock\.so[[:space:]]+authfail[[:space:]]*$/ { next }
    /^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_faillock\.so[[:space:]]+authsucc[[:space:]]*$/ { next }

    {
      if (!found && $0 ~ /^[[:space:]]*auth[[:space:]]+\[[^]]*\][[:space:]]+pam_unix\.so([[:space:]]|$)/) {
        print preauth
        print
        print authfail
        found=1
        next
      }

      if (found && !succ_inserted) {
        # PAM success=N counts PAM rules, not comments or blank lines.
        if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^[[:space:]]*#/) {
          print
          next
        }

        if (remaining == 0) {
          print authsucc
          succ_inserted=1
        } else {
          remaining--
        }
      }

      print
    }

    END {
      if (!found || !succ_inserted) exit 2
    }
  ' "$auth_file" > "$tmp"; then
    if sudo install -m 0644 "$tmp" "$auth_file"; then
      rm -f "$tmp"
    else
      rm -f "$tmp"
      echo "Warning: Could not update $auth_file."
      return 1
    fi
  else
    rm -f "$tmp"
    echo "Warning: Could not safely construct the pam_faillock auth stack; leaving $auth_file unchanged."
    return 1
  fi

  tmp=$(mktemp)
  if sudo awk -v account_line="$account_line" '
    /^[[:space:]]*account[[:space:]]+required[[:space:]]+pam_faillock\.so[[:space:]]*$/ { next }
    { print }
    END { print account_line }
  ' "$account_file" > "$tmp"; then
    if sudo install -m 0644 "$tmp" "$account_file"; then
      rm -f "$tmp"
    else
      rm -f "$tmp"
      echo "Warning: Could not update $account_file."
      return 1
    fi
  else
    rm -f "$tmp"
    echo "Warning: Could not prepare $account_file."
    return 1
  fi

  echo "Ensured pam_faillock rules in common-auth and common-account (preserved pam_unix success jump=$success_skip)."
}
