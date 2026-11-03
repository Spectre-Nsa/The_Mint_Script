#!/usr/bin/env bash

# Includes are normally sourced by harden.sh; do not leak strict mode into the parent shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

invoke_unwanted_software () {
  while true; do
    echo
    echo "============================================================"
    echo "UNWANTED SOFTWARE"
    echo "============================================================"
    echo "1) Scan installed APT packages outside the core baseline"
    echo "2) Run the configured unwanted-software scan"
    echo "3) Audit installed Snap packages (configured flags + non-core review)"
    echo "4) Return to the main menu"
    echo
    if ! IFS= read -r -p "Choose an option [1-4]: " choice; then
      choice=4
    fi

    case "${choice,,}" in
      1)
        if ! us_scan_noncore_apt; then
          echo "[WARNING] The non-core APT scan did not complete successfully."
        fi
        ;;
      2)
        if ! us_purge_unwanted_software; then
          echo "[WARNING] The configured unwanted-software scan did not complete successfully."
        fi
        ;;
      3)
        if ! us_review_unwanted_snaps; then
          echo "[WARNING] The Snap audit did not complete successfully."
        fi
        ;;
      4|q|quit|b|back)
        return 0
        ;;
      *)
        echo "Invalid choice. Enter 1, 2, 3, or 4."
        ;;
    esac
  done
}

# Inventory installed APT packages that are not in the configured vanilla/core
# baseline. This is a baseline comparison, not proof that software is malicious.
# The user can optionally review candidates one at a time. APT removals are
# simulated first, and any transaction that would remove other packages is blocked.
us_scan_noncore_apt () {
  echo
  echo "---------------- Non-core APT package scan ----------------"

  if ! command -v dpkg-query >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1; then
    echo "[ERROR] dpkg-query or apt-get is unavailable."
    return 1
  fi

  if [[ -z "${VANILLA:-}" ]]; then
    echo "[ERROR] The VANILLA core baseline is not configured; refusing to guess."
    return 1
  fi

  local -A baseline=()
  local entry package status base
  for entry in $VANILLA; do
    [[ -n "$entry" ]] || continue
    baseline["$entry"]=1
    # Let architecture-qualified and unqualified baseline entries match safely.
    baseline["${entry%%:*}"]=1
  done

  local -a noncore=()
  while IFS=$'\t' read -r package status; do
    [[ "$status" == "installed" && -n "$package" ]] || continue
    base="${package%%:*}"
    if [[ -z "${baseline[$package]:-}" && -z "${baseline[$base]:-}" ]]; then
      noncore+=("$package")
    fi
  done < <(dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' 2>/dev/null | sort -t $'\t' -k1,1)

  if (( ${#noncore[@]} == 0 )); then
    echo "All installed APT packages matched the configured core baseline."
    return 0
  fi

  echo "Found ${#noncore[@]} installed package(s) outside the core baseline."
  echo "These are candidates for human review, not automatic malware detections."
  printf '\n%-4s %s\n' "No." "Installed package outside baseline"
  printf '%-4s %s\n' "----" "--------------------------------"
  local i
  for i in "${!noncore[@]}"; do
    printf '%-4d %s\n' "$((i + 1))" "${noncore[$i]}"
  done

  echo
  local answer
  if ! IFS= read -r -p "Review these candidates individually for possible removal? [y/N]: " answer; then
    answer="n"
  fi
  case "${answer,,}" in
    y|yes) ;;
    *)
      echo "Inventory only; no packages changed."
      return 0
      ;;
  esac

  local -a apt_cmd=()
  if (( EUID == 0 )); then
    apt_cmd=(apt-get)
  elif command -v sudo >/dev/null 2>&1; then
    apt_cmd=(sudo apt-get)
  else
    echo "[ERROR] Root privileges or sudo are required for package removal."
    return 1
  fi

  local kept=0 removed=0 blocked=0 failed=0 stop_review=0
  local sim_output sim_rc answer_pkg plan_pkg
  local -a planned=()
  for i in "${!noncore[@]}"; do
    package="${noncore[$i]}"
    (( stop_review )) && break

    status="$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)"
    [[ "$status" == "installed" ]] || continue

    printf '\n[%d/%d] Non-core candidate: %s\n' "$((i + 1))" "${#noncore[@]}" "$package"
    if ! IFS= read -r -p 'Keep this package? [Y]es / [n]o (purge) / [q]uit [Y]: ' answer_pkg; then
      answer_pkg=q
    fi
    case "${answer_pkg,,}" in
      ''|y|yes)
        echo "Keeping $package."
        ((kept+=1))
        continue
        ;;
      q|quit)
        echo "Stopping review; remaining packages are unchanged."
        stop_review=1
        continue
        ;;
      n|no|p|purge|remove) ;;
      *)
        echo "Unrecognized response; keeping $package."
        ((kept+=1))
        continue
        ;;
    esac

    if sim_output="$(DEBIAN_FRONTEND=noninteractive "${apt_cmd[@]}" -s purge "$package" 2>&1)"; then
      sim_rc=0
    else
      sim_rc=$?
    fi
    if (( sim_rc != 0 )); then
      echo "[BLOCKED] APT could not simulate removal of $package; nothing was removed."
      printf '%s\n' "$sim_output" | tail -10
      ((blocked+=1))
      continue
    fi

    mapfile -t planned < <(printf '%s\n' "$sim_output" | awk '($1 == "Remv" || $1 == "Purg") && NF >= 2 {print $2}' | sort -u)
    if (( ${#planned[@]} != 1 )) || [[ "${planned[0]:-}" != "$package" ]]; then
      echo "[BLOCKED] APT proposes a multi-package removal for $package: ${planned[*]:-(no parseable removal plan)}"
      echo "Nothing was removed; use manual review for this dependency-sensitive package."
      ((blocked+=1))
      continue
    fi

    echo "APT's simulated plan removes only: $package"
    if DEBIAN_FRONTEND=noninteractive "${apt_cmd[@]}" -y purge "$package"; then
      echo "[PASS] Removed $package."
      ((removed+=1))
    else
      echo "[ERROR] Failed to remove $package."
      ((failed+=1))
    fi
  done

  printf '\nNon-core APT review complete: kept=%d removed=%d blocked=%d errors=%d\n' "$kept" "$removed" "$blocked" "$failed"
  echo "No automatic autoremove was run."
  (( failed == 0 ))
}

# Scan installed APT/dpkg packages matching the configured unwanted-software
# prefixes. Display the full match list first, then ask about every package.
# No wildcard purge and no automatic autoremove are performed.
us_purge_unwanted_software () {
  if [[ -z "${UNWANTED_SOFTWARE+x}" ]]; then
    echo "No unwanted software configured."
    return 0
  fi

  local -a configured=()
  if declare -p UNWANTED_SOFTWARE 2>/dev/null | grep -q 'declare -a'; then
    configured=("${UNWANTED_SOFTWARE[@]}")
  else
    read -r -a configured <<< "$UNWANTED_SOFTWARE"
  fi

  if (( ${#configured[@]} == 0 )); then
    echo "No unwanted software configured."
    return 0
  fi
  if ! command -v dpkg-query >/dev/null 2>&1 || ! command -v apt-get >/dev/null 2>&1; then
    echo "[ERROR] dpkg-query or apt-get is unavailable; cannot audit APT packages."
    return 1
  fi

  local -a apt_cmd=()
  if (( EUID == 0 )); then
    apt_cmd=(apt-get)
  elif command -v sudo >/dev/null 2>&1; then
    apt_cmd=(sudo apt-get)
  else
    echo "[ERROR] Root privileges are required to purge packages. Run the main script with sudo."
    return 1
  fi

  local package status prefix
  local -A matched_by=() decisions=()
  # `${binary:Package}` retains an architecture suffix where dpkg requires it.
  while IFS=$'\t' read -r package status; do
    [[ "$status" == "installed" ]] || continue
    for prefix in "${configured[@]}"; do
      [[ -n "$prefix" ]] || continue
      if [[ "$package" == "$prefix"* ]]; then
        matched_by["$package"]="$prefix"
        break
      fi
    done
  done < <(dpkg-query -W -f='${binary:Package}\t${db:Status-Status}\n' 2>/dev/null)

  local -a matches=()
  if (( ${#matched_by[@]} > 0 )); then
    mapfile -t matches < <(printf '%s\n' "${!matched_by[@]}" | sort -u)
  fi

  if (( ${#matches[@]} == 0 )); then
    echo "No installed APT packages matched the configured unwanted-software prefixes."
    return 0
  fi

  echo "Matching uses the existing configuration's prefix behavior: a configured entry such as 'nmap' can match 'nmap-common'."
  printf '\nFound %d installed package(s) matching the configured list:\n' "${#matches[@]}"
  local i
  for i in "${!matches[@]}"; do
    package="${matches[$i]}"
    printf '  %d. %-40s matched configured entry: %s*\n' "$((i + 1))" "$package" "${matched_by[$package]}"
  done

  echo
  echo "Review each installed package. Keeping is the default; 'q' stops and leaves remaining packages installed."
  local answer sim_output sim_rc plan_pkg target_blocked stop_review=0 kept=0 purged=0 failed=0 blocked=0 skipped=0
  local -a planned=() extra_approved=()

  for i in "${!matches[@]}"; do
    package="${matches[$i]}"
    if (( stop_review )); then
      ((skipped+=1))
      continue
    fi

    # Another explicitly approved APT transaction may have already removed it.
    status="$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)"
    if [[ "$status" != "installed" ]]; then
      if [[ "${decisions[$package]:-}" == "purged" ]]; then
        printf '\n[%d/%d] %s was already removed in an earlier approved transaction.\n' "$((i + 1))" "${#matches[@]}" "$package"
        ((skipped+=1))
      else
        printf '\n[%d/%d] %s is no longer installed; skipping.\n' "$((i + 1))" "${#matches[@]}" "$package"
        ((skipped+=1))
      fi
      continue
    fi

    if [[ -n "${decisions[$package]:-}" ]]; then
      printf '\n[%d/%d] %s: already reviewed (%s).\n' "$((i + 1))" "${#matches[@]}" "$package" "${decisions[$package]}"
      ((skipped+=1))
      continue
    fi

    printf '\n[%d/%d] Installed package: %s (matched by %s*)\n' "$((i + 1))" "${#matches[@]}" "$package" "${matched_by[$package]}"
    while true; do
      if ! IFS= read -r -p 'Keep this package? [Y]es / [n]o (purge) / [q]uit [Y]: ' answer; then
        answer='q'
      fi
      case "${answer,,}" in
        ''|y|yes)
          decisions["$package"]="kept"
          echo "Keeping package installed."
          ((kept+=1))
          break
          ;;
        n|no|p|purge|remove)
          decisions["$package"]="purge-requested"
          break
          ;;
        q|quit)
          echo "Stopping review. Remaining packages will be left installed."
          stop_review=1
          decisions["$package"]="kept"
          ((kept+=1))
          break
          ;;
        *)
          echo "Please enter Y (keep), N (purge), or Q (quit review)."
          ;;
      esac
    done
    (( stop_review )) && break
    [[ "${decisions[$package]:-}" == "purge-requested" ]] || continue

    # Simulate the APT transaction first. If APT would remove additional
    # packages, require an individual approval for each one. Any refusal aborts
    # this transaction so an earlier 'keep' decision cannot be silently ignored.
    if sim_output="$(DEBIAN_FRONTEND=noninteractive "${apt_cmd[@]}" -s purge "$package" 2>&1)"; then
      sim_rc=0
    else
      sim_rc=$?
    fi
    if (( sim_rc != 0 )); then
      echo "[ERROR] APT could not simulate purging ${package}; nothing was removed."
      printf '%s\n' "$sim_output" | tail -12
      decisions["$package"]="blocked"
      ((blocked+=1))
      continue
    fi

    mapfile -t planned < <(printf '%s\n' "$sim_output" | awk '($1 == "Remv" || $1 == "Purg") && NF >= 2 {print $2}' | sort -u)
    if (( ${#planned[@]} == 0 )); then
      echo "[ERROR] APT returned no explicit removal plan for ${package}; refusing to guess."
      decisions["$package"]="blocked"
      ((blocked+=1))
      continue
    fi

    target_blocked=0
    extra_approved=()
    for plan_pkg in "${planned[@]}"; do
      [[ "$plan_pkg" == "$package" ]] && continue
      case "${decisions[$plan_pkg]:-}" in
        kept)
          echo "[CANCELLED] APT also proposes removing ${plan_pkg}, which you previously chose to keep."
          target_blocked=1
          break
          ;;
        purged)
          # Already removed by an earlier individually approved transaction.
          ;;
        purge-requested)
          # It has already had an individual purge approval in this review.
          extra_approved+=("$plan_pkg")
          ;;
        *)
          while true; do
            if ! IFS= read -r -p "APT also proposes to remove '${plan_pkg}'. Allow this individual removal? [y/N/q]: " answer; then
              answer='q'
            fi
            case "${answer,,}" in
              y|yes|remove|purge)
                extra_approved+=("$plan_pkg")
                break
                ;;
              ''|n|no|k|keep)
                echo "Keeping ${plan_pkg}; aborting the ${package} purge so APT cannot remove it indirectly."
                decisions["$plan_pkg"]="kept"
                ((kept+=1))
                target_blocked=1
                break
                ;;
              q|quit)
                echo "Review stopped; no packages in this transaction were removed."
                decisions["$plan_pkg"]="kept"
                target_blocked=1
                stop_review=1
                break
                ;;
              *)
                echo "Please answer Y, N, or Q."
                ;;
            esac
          done
          ;;
      esac
      (( target_blocked )) && break
    done

    if (( target_blocked )); then
      decisions["$package"]="blocked"
      ((blocked+=1))
      (( stop_review )) && break
      continue
    fi

    echo "APT's approved removal plan for ${package}: ${planned[*]}"
    if DEBIAN_FRONTEND=noninteractive "${apt_cmd[@]}" -y purge "$package"; then
      for plan_pkg in "${planned[@]}"; do
        decisions["$plan_pkg"]="purged"
      done
      echo "[PASS] Purge completed for ${package}."
      ((purged+=1))
    else
      echo "[ERROR] APT failed to purge ${package}. No automatic repair or autoremove was run."
      decisions["$package"]="failed"
      ((failed+=1))
    fi
  done

  printf '\nUnwanted-software review complete: keep decisions=%d successful purge transactions=%d blocked transactions=%d errors=%d skipped/already handled=%d\n' \
    "$kept" "$purged" "$blocked" "$failed" "$skipped"
  echo "Automatic 'apt autoremove' was intentionally not run; it can remove packages that were not on this review list."
}


# ------------------------------------------------------------
# Snap audit: display every installed Snap and review configured matches.
# Names in UNWANTED_SOFTWARE are checked by exact name, plus optional
# exact names listed in UNWANTED_SNAPS. Unlisted snaps are inventoried,
# but never automatically classified as unwanted or removed.
# ------------------------------------------------------------
us_review_unwanted_snaps () {
  echo
  echo "---------------- Snap package audit ----------------"

  if ! command -v snap >/dev/null 2>&1; then
    echo "Snap is not installed; skipping Snap package audit."
    return 0
  fi

  local snap_output
  if ! snap_output="$(snap list 2>&1)"; then
    if grep -Eqi 'no snaps are installed|no installed snaps' <<< "$snap_output"; then
      echo "No Snap packages are installed."
      return 0
    fi
    echo "[ERROR] Could not list installed Snap packages:"
    printf '%s\n' "$snap_output"
    return 1
  fi

  local -a rows=() configured=() candidates=()
  mapfile -t rows < <(printf '%s\n' "$snap_output" | awk 'NR > 1 && NF { print }')
  if (( ${#rows[@]} == 0 )); then
    echo "No installed Snap package rows were returned."
    printf '%s\n' "$snap_output"
    return 0
  fi

  # Only these well-known base snaps are auto-classified as platform/runtime
  # components. Everything else is a non-core review candidate, not proof of malware.
  local -A core_snap=()
  local core_name
  for core_name in core core16 core18 core20 core22 core24 snapd bare; do
    core_snap["$core_name"]=1
  done

  if [[ -n "${UNWANTED_SOFTWARE:-}" ]]; then
    read -r -a configured <<< "$UNWANTED_SOFTWARE"
  fi
  if declare -p UNWANTED_SNAPS 2>/dev/null | grep -q 'declare -a'; then
    configured+=("${UNWANTED_SNAPS[@]}")
  fi

  local row name version rev tracking publisher notes candidate label
  local -A matched_by=() is_core=() reviewed=()
  echo "Inventory (configured matches are flagged; other non-core snaps need a human review):"
  printf '\n%-4s %-28s %-22s %s\n' "Type" "Snap name" "Version" "Publisher / notes"
  printf '%-4s %-28s %-22s %s\n' "----" "----------------------------" "----------------------" "-----------------"

  for row in "${rows[@]}"; do
    IFS=$' \t' read -r name version rev tracking publisher notes <<< "$row"
    [[ -n "$name" ]] || continue
    label="NON-CORE/REVIEW"
    if [[ -n "${core_snap[$name]:-}" ]]; then
      label="BASE/CORE"
      is_core["$name"]=1
    fi
    for candidate in "${configured[@]}"; do
      [[ -n "$candidate" ]] || continue
      if [[ "$name" == "$candidate" ]]; then
        matched_by["$name"]="$candidate"
        label="CONFIG-FLAGGED"
        break
      fi
    done
    printf '%-4s %-28s %-22s %s %s\n' "$label" "$name" "$version" "${publisher:--}" "${notes:-}"
    if [[ "$label" != "BASE/CORE" || -n "${matched_by[$name]:-}" ]]; then
      candidates+=("$name")
    fi
  done

  echo
  echo "Meaning: BASE/CORE is a recognized Snap base; CONFIG-FLAGGED matches the configured unwanted list; NON-CORE/REVIEW is not automatically malicious."
  if (( ${#candidates[@]} == 0 )); then
    echo "No non-core Snap packages or configured matches require review."
    return 0
  fi
  echo "Reviewable Snap packages: ${#candidates[@]}"
  echo "Keeping is the default. This scan cannot determine maliciousness on its own; compare names with the competition scenario."

  local -a snap_cmd=()
  if (( EUID == 0 )); then
    snap_cmd=(snap)
  elif command -v sudo >/dev/null 2>&1; then
    snap_cmd=(sudo snap)
  else
    echo "[ERROR] Root privileges or sudo are required to remove Snap packages."
    return 1
  fi

  local answer kept=0 removed=0 failed=0 stop_review=0
  local total="${#candidates[@]}"
  local index=0
  for name in "${candidates[@]}"; do
    (( index+=1 ))
    (( stop_review )) && break

    if [[ -n "${matched_by[$name]:-}" ]]; then
      printf '\n[%d/%d] CONFIG-FLAGGED Snap: %s (matched configured entry: %s)\n' "$index" "$total" "$name" "${matched_by[$name]}"
    else
      printf '\n[%d/%d] Non-core Snap candidate: %s\n' "$index" "$total" "$name"
    fi
    while true; do
      if ! IFS= read -r -p 'Keep this Snap? [Y]es / [n]o (remove) / [q]uit [Y]: ' answer; then
        answer=q
      fi
      case "${answer,,}" in
        ''|y|yes)
          reviewed["$name"]="kept"
          echo "Keeping Snap installed."
          ((kept+=1))
          break
          ;;
        n|no|r|remove)
          echo "Removing Snap '$name' without --purge (Snap data is not forcibly purged)."
          if "${snap_cmd[@]}" remove "$name"; then
            reviewed["$name"]="removed"
            echo "[PASS] Snap '$name' was removed."
            ((removed+=1))
          else
            reviewed["$name"]="failed"
            echo "[ERROR] Failed to remove Snap '$name'."
            ((failed+=1))
          fi
          break
          ;;
        q|quit)
          echo "Stopping Snap review; remaining snaps will be left unchanged."
          stop_review=1
          break
          ;;
        *)
          echo "Please enter Y (keep), N (remove), or Q (quit review)."
          ;;
      esac
    done
  done

  printf '\nSnap review complete: kept=%d removed=%d errors=%d\n' "$kept" "$removed" "$failed"
  (( failed == 0 ))
}
