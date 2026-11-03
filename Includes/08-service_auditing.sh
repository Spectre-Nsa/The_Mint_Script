#!/usr/bin/env bash

# Enable strict mode only when this file is executed directly.
# harden.sh sources includes/*.sh, so strict mode must not leak into the parent shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

invoke_service_auditing () {
  echo -e "${CYAN}[Service Auditing] Start${NC}"

  # SSH is a critical service for this competition round.
  # A failure here is reported but must not terminate the entire hardening script.
  if ! sa_secure_critical_ssh; then
    echo "Warning: Critical SSH remediation encountered an error."
  fi

  if ! sa_purge_unwanted_services; then
    echo "Warning: Unwanted service cleanup encountered an error."
  fi

  echo -e "${CYAN}[Service Auditing] Done${NC}"
}

# -------------------------------------------------------------------
# Critical SSH service: optionally enable it, apply universal SSH
# hardening, and optionally apply scenario-dependent SSH settings.
# -------------------------------------------------------------------
sa_secure_critical_ssh () {
  echo
  echo "============================================================"
  echo "CRITICAL SERVICE: SSH / OPENSSH"
  echo "============================================================"

  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Warning: SSH hardening requires root."
    return 1
  fi

  local enable_answer universal_answer scenario_answer
  local enable_ssh=1
  local apply_universal=1
  local apply_scenario=0

  # ---------------------------------------------------------------
  # Prompt 1: should SSH be enabled/installed and started?
  # ---------------------------------------------------------------
  read -r -p "Enable/install SSH and ensure it is running? [Y/n] " enable_answer
  enable_answer="${enable_answer:-Y}"
  case "$enable_answer" in
    n|N|no|NO) enable_ssh=0 ;;
    *) enable_ssh=1 ;;
  esac

  # ---------------------------------------------------------------
  # Prompt 2: should the universal SSH baseline be applied?
  # ---------------------------------------------------------------
  read -r -p "Apply universal SSH hardening? [Y/n] " universal_answer
  universal_answer="${universal_answer:-Y}"
  case "$universal_answer" in
    n|N|no|NO) apply_universal=0 ;;
    *) apply_universal=1 ;;
  esac

  # ---------------------------------------------------------------
  # Prompt 3: should the current competition/scenario-dependent
  # authentication baseline be applied?
  #
  # This currently means keeping password authentication available,
  # while also explicitly allowing public-key authentication and PAM.
  # Do not force a different authentication method unless the round
  # specifically requires it.
  # ---------------------------------------------------------------
  read -r -p "Apply scenario-dependent SSH settings for this round? [y/N] " scenario_answer
  scenario_answer="${scenario_answer:-N}"
  case "$scenario_answer" in
    y|Y|yes|YES) apply_scenario=1 ;;
    *) apply_scenario=0 ;;
  esac

  local package="openssh-server"
  local config="/etc/ssh/sshd_config"
  local timestamp
  local backup=""
  local tmp=""
  local service=""
  local effective=""
  local value=""
  local port="22"
  local config_changed=0
  local service_was_active=0

  timestamp="$(date +%Y%m%d_%H%M%S)"

  # ---------------------------------------------------------------
  # 1. Ensure OpenSSH is available only when the first prompt allows it.
  # ---------------------------------------------------------------
  if command -v sshd >/dev/null 2>&1; then
    echo "OpenSSH server is already installed."
  elif (( enable_ssh )); then
    echo "OpenSSH server is not installed."
    echo "Installing $package..."

    if ! DEBIAN_FRONTEND=noninteractive \
      apt-get \
      -o Dpkg::Options::="--force-confold" \
      install -y "$package"; then

      echo "Initial OpenSSH installation failed."
      echo "Refreshing APT package indexes and retrying..."

      if ! apt-get update; then
        echo "Warning: APT index refresh failed."
        return 1
      fi

      if ! DEBIAN_FRONTEND=noninteractive \
        apt-get \
        -o Dpkg::Options::="--force-confold" \
        install -y "$package"; then

        echo "Error: Could not install OpenSSH server."
        return 1
      fi
    fi
  else
    echo "OpenSSH server is not installed and the enable/install option was declined."
    echo "SSH installation/startup was skipped."
    return 0
  fi

  # ---------------------------------------------------------------
  # 2. Locate the SSH systemd service.
  # ---------------------------------------------------------------
  if systemctl cat ssh.service >/dev/null 2>&1; then
    service="ssh"
  elif systemctl cat sshd.service >/dev/null 2>&1; then
    service="sshd"
  else
    echo "Error: Could not locate an SSH systemd service."
    return 1
  fi

  echo "SSH service detected: $service"

  if systemctl is-active --quiet "$service"; then
    service_was_active=1
  fi

  # ---------------------------------------------------------------
  # 3. Make sure required configuration directories exist.
  # ---------------------------------------------------------------
  if [[ ! -d /etc/ssh ]]; then
    echo "Error: /etc/ssh does not exist."
    return 1
  fi

  if [[ ! -f "$config" ]]; then
    echo "Error: $config does not exist."
    return 1
  fi

  mkdir -p /etc/ssh/sshd_config.d
  install -d -m 0755 /run/sshd

  # ---------------------------------------------------------------
  # 4. Generate any missing host keys when SSH is being enabled.
  #    If the user declined enabling SSH, do not generate keys just
  #    as a side effect of hardening the config.
  # ---------------------------------------------------------------
  if (( enable_ssh )); then
    echo "Checking SSH host keys..."

    if ! compgen -G "/etc/ssh/ssh_host_*_key" >/dev/null 2>&1; then
      echo "No SSH host private keys found. Generating missing keys..."
      if ! ssh-keygen -A; then
        echo "Error: SSH host key generation failed."
        return 1
      fi
    else
      echo "SSH host keys already exist."
      ssh-keygen -A >/dev/null 2>&1 || true
    fi

    # -------------------------------------------------------------
    # 5. Fix host-key and main-config permissions.
    # -------------------------------------------------------------
    for value in /etc/ssh/ssh_host_*_key; do
      [[ -f "$value" ]] || continue
      chown root:root "$value"
      chmod 0600 "$value"
    done

    for value in /etc/ssh/ssh_host_*_key.pub; do
      [[ -f "$value" ]] || continue
      chown root:root "$value"
      chmod 0644 "$value"
    done
  fi

  # ---------------------------------------------------------------
  # 5b. Universal SSH hardening includes securing sshd_config itself.
  #     This is intentionally tied to the universal-hardening prompt so
  #     declining that prompt does not silently alter the configuration.
  # ---------------------------------------------------------------
  if (( apply_universal )); then
    chown root:root "$config"
    chmod 0600 "$config"
    echo "Secured $config: root:root 0600"
  fi

  # ---------------------------------------------------------------
  # 6. Apply requested SSH configuration baselines.
  # ---------------------------------------------------------------
  if (( apply_universal || apply_scenario )); then
    backup="${config}.${timestamp}.bak"

    if ! cp -a "$config" "$backup"; then
      echo "Error: Could not back up $config."
      return 1
    fi

    echo "Backup created: $backup"

    tmp="$(mktemp /etc/ssh/.sshd_config.XXXXXX)" || {
      echo "Error: Could not create temporary SSH configuration."
      return 1
    }

    if ! awk -v do_universal="$apply_universal" -v do_scenario="$apply_scenario" '
    BEGIN {
        remove["permitrootlogin"] = 1
        remove["permitemptypasswords"] = 1
        remove["maxauthtries"] = 1
        remove["logingracetime"] = 1
        remove["x11forwarding"] = 1
        remove["permituserenvironment"] = 1
        remove["clientaliveinterval"] = 1
        remove["clientalivecountmax"] = 1

        if (do_scenario) {
            remove["passwordauthentication"] = 1
            remove["pubkeyauthentication"] = 1
            remove["usepam"] = 1
        }

        if (do_universal || do_scenario) {
            print "# NOJE Critical SSH Hardening"
        }

        if (do_universal) {
            print "PermitRootLogin no"
            print "PermitEmptyPasswords no"
            print "MaxAuthTries 4"
            print "LoginGraceTime 60"
            print "X11Forwarding no"
            print "PermitUserEnvironment no"
            print "ClientAliveInterval 300"
            print "ClientAliveCountMax 2"
        }

        if (do_scenario) {
            print "PasswordAuthentication yes"
            print "PubkeyAuthentication yes"
            print "UsePAM yes"
        }

        if (do_universal || do_scenario) {
            print ""
        }

        match_seen = 0
    }

    /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+/ {
        match_seen = 1
    }

    {
        key = tolower($1)
        if (!match_seen && key in remove) next
        print
    }
    ' "$config" > "$tmp"; then
      rm -f "$tmp"
      echo "Error: Could not construct the requested SSH configuration."
      return 1
    fi

    chown root:root "$tmp"
    chmod 0600 "$tmp"

    if ! install -m 0600 -o root -g root "$tmp" "$config"; then
      rm -f "$tmp"
      echo "Error: Could not install the requested SSH configuration."
      return 1
    fi

    rm -f "$tmp"
    tmp=""
    config_changed=1
  else
    echo "SSH configuration changes were not requested."
  fi

  # ---------------------------------------------------------------
  # 7. Validate the SSH configuration before touching the running
  #    service.
  # ---------------------------------------------------------------
  if (( config_changed )); then
    echo "Validating SSH configuration..."

    if ! sshd -t; then
      echo "ERROR: sshd configuration validation failed."
      echo "Rolling back $config..."

      if [[ -n "$backup" ]] && cp -a "$backup" "$config"; then
        echo "SSH configuration rolled back successfully."
      else
        echo "CRITICAL ERROR: SSH configuration rollback failed."
      fi

      return 1
    fi

    echo "SSH configuration syntax is valid."
  fi

  # ---------------------------------------------------------------
  # 8. Read the effective configuration if sshd is available.
  # ---------------------------------------------------------------
  effective="$(sshd -T 2>/dev/null)" || {
    echo "Error: Could not read effective SSH configuration."
    if [[ -n "$backup" ]]; then
      cp -a "$backup" "$config" || true
    fi
    return 1
  }

  if (( apply_universal )); then
    if [[ "$(stat -c '%U:%G %a' "$config" 2>/dev/null || true)" != "root:root 600" ]]; then
      echo "Error: $config does not have the required root:root 0600 permissions."
      [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
      return 1
    fi

    value="$(awk '$1=="permitrootlogin"{print $2; exit}' <<< "$effective")"
    if [[ "$value" != "no" ]]; then
      echo "Error: PermitRootLogin is not effectively set to no."
      echo "Effective value: ${value:-unknown}"
      [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
      return 1
    fi

    value="$(awk '$1=="permitemptypasswords"{print $2; exit}' <<< "$effective")"
    if [[ "$value" != "no" ]]; then
      echo "Error: PermitEmptyPasswords is not effectively set to no."
      echo "Effective value: ${value:-unknown}"
      [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
      return 1
    fi

    value="$(awk '$1=="maxauthtries"{print $2; exit}' <<< "$effective")"
    if [[ "$value" != "4" ]]; then
      echo "Warning: MaxAuthTries effective value is ${value:-unknown}."
    fi

    value="$(awk '$1=="x11forwarding"{print $2; exit}' <<< "$effective")"
    if [[ "$value" != "no" ]]; then
      echo "Warning: X11Forwarding effective value is ${value:-unknown}."
    fi
  fi

  if (( apply_scenario )); then
    value="$(awk '$1=="passwordauthentication"{print $2; exit}' <<< "$effective")"
    if [[ "$value" != "yes" ]]; then
      echo "Error: PasswordAuthentication is not effectively set to yes."
      echo "This could prevent competition password authentication."
      echo "Effective value: ${value:-unknown}"
      [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
      return 1
    fi

    value="$(awk '$1=="pubkeyauthentication"{print $2; exit}' <<< "$effective")"
    if [[ "$value" != "yes" ]]; then
      echo "Error: PubkeyAuthentication is not effectively set to yes."
      echo "Effective value: ${value:-unknown}"
      [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
      return 1
    fi

    value="$(awk '$1=="usepam"{print $2; exit}' <<< "$effective")"
    if [[ "$value" != "yes" ]]; then
      echo "Error: UsePAM is not effectively set to yes."
      echo "Effective value: ${value:-unknown}"
      [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
      return 1
    fi
  fi

  port="$(awk '$1=="port"{print $2; exit}' <<< "$effective")"
  [[ -n "$port" ]] || port="22"

  echo "Effective SSH port: $port"

  # ---------------------------------------------------------------
  # 9. Apply the requested service-state change.
  # ---------------------------------------------------------------
  if (( enable_ssh )); then
    echo "Ensuring SSH service is enabled and running..."

    systemctl unmask "$service" >/dev/null 2>&1 || true

    if ! systemctl enable "$service"; then
      echo "Error: Could not enable $service."
      [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
      return 1
    fi

    if systemctl is-active --quiet "$service"; then
      echo "SSH is already running."

      if (( config_changed )); then
        if ! systemctl reload "$service"; then
          echo "Warning: SSH reload failed."
          echo "Rolling back configuration..."

          [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
          systemctl reload "$service" >/dev/null 2>&1 || true

          return 1
        fi
      fi
    else
      echo "SSH is not running. Starting it..."

      if ! systemctl start "$service"; then
        echo "Error: SSH failed to start."
        echo "Rolling back configuration..."

        [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
        systemctl start "$service" >/dev/null 2>&1 || true

        return 1
      fi
    fi
  elif (( config_changed && service_was_active )); then
    echo "SSH enable/start option was declined; reloading the already-running service to apply config changes..."

    if ! systemctl reload "$service"; then
      echo "Warning: SSH reload failed."
      echo "Rolling back configuration..."

      [[ -n "$backup" ]] && cp -a "$backup" "$config" || true
      systemctl reload "$service" >/dev/null 2>&1 || true

      return 1
    fi
  else
    echo "SSH service state was left unchanged."
  fi

  # ---------------------------------------------------------------
  # 10. Final verification.
  # ---------------------------------------------------------------
  if (( enable_ssh )); then
    if ! systemctl is-active --quiet "$service"; then
      echo "ERROR: SSH service is not active after remediation."
      return 1
    fi

    if ! systemctl is-enabled --quiet "$service"; then
      echo "ERROR: SSH service is not enabled."
      return 1
    fi
  fi

  echo
  echo "SSH CONFIGURATION COMPLETE"
  echo "---------------------------"

  if (( enable_ssh )); then
    echo "Service:                $service"
    echo "Status:                 ACTIVE"
    echo "Enabled:                YES"
  else
    echo "Service state:          UNCHANGED"
  fi

  if (( apply_universal )); then
    echo "Universal hardening:    APPLIED"
    echo "PermitRootLogin:        no"
    echo "PermitEmptyPasswords:   no"
    echo "MaxAuthTries:           4"
    echo "X11Forwarding:          no"
  else
    echo "Universal hardening:    SKIPPED"
  fi

  if (( apply_scenario )); then
    echo "Scenario settings:      APPLIED"
    echo "PasswordAuthentication: yes"
    echo "PubkeyAuthentication:   yes"
    echo "UsePAM:                 yes"
  else
    echo "Scenario settings:      SKIPPED"
  fi

  echo "SSH Port:               $port"

  if [[ -n "$backup" ]]; then
    echo "Backup:                 $backup"
  else
    echo "Backup:                 none (no SSH config changes)"
  fi

  echo
  echo "Critical SSH handling complete."

  return 0
}

# -------------------------------------------------------------------
# Interactively purge unwanted packages listed in $UNWANTED
# -------------------------------------------------------------------
sa_purge_unwanted_services () {
  if [[ -z "${UNWANTED+x}" || -z "${UNWANTED}" ]]; then
    echo "No unwanted services configured."
    return 0
  fi

  local -a packages=()
  local pkg answer

  if declare -p UNWANTED 2>/dev/null | grep -q 'declare -a'; then
    packages=("${UNWANTED[@]}")
  else
    read -r -a packages <<< "$UNWANTED"
  fi

  for pkg in "${packages[@]}"; do
    [[ -z "$pkg" ]] && continue

    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q '^install ok installed$'; then
      read -r -p "Is the service ${pkg} a critical service? (Y/n) " answer
      answer="${answer:-Y}"

      if [[ "$answer" == "n" || "$answer" == "N" ]]; then
        echo "Purging ${pkg}..."

        if DEBIAN_FRONTEND=noninteractive apt purge -y -qq "${pkg}*" >/dev/null 2>&1; then
          echo "${pkg} purged."
        else
          echo "Error: Purge failed for ${pkg}; repairing dpkg state..."

          dpkg --configure -a >/dev/null 2>&1 || true

          if DEBIAN_FRONTEND=noninteractive apt purge -y -qq "${pkg}*" >/dev/null 2>&1; then
            echo "${pkg} purged after retry."
          else
            echo "Final failure: Could not purge ${pkg}."
          fi
        fi
      else
        echo "${pkg} kept."
      fi
    else
      echo "${pkg} not installed. Skipping..."
    fi
  done
}
