#!/usr/bin/env bash

# Includes are normally sourced by harden.sh; do not leak strict mode into the parent shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

invoke_prohibited_files () {
  echo -e "${CYAN}[Prohibited Files] Start${NC}"
  pf_remove_prohibited_files
  echo -e "${CYAN}[Prohibited Files] Done${NC}"
}

# Find configured file types, display every match, then ask about each file.
# Keeping is the default; deletion only occurs after an explicit N/no answer.
pf_remove_prohibited_files () {
  if [[ -z "${FILE_EXTENSIONS+x}" ]] || (( ${#FILE_EXTENSIONS[@]} == 0 )); then
    echo "No file extensions configured."
    return 0
  fi

  local -a name_tests=()
  local ext first=1
  for ext in "${FILE_EXTENSIONS[@]}"; do
    ext="${ext#.}"
    [[ -n "$ext" ]] || continue
    if (( first == 0 )); then
      name_tests+=( -o )
    fi
    first=0

    # netrc is commonly a dotfile named exactly .netrc, not just an extension.
    if [[ "${ext,,}" == "netrc" ]]; then
      name_tests+=( '(' -iname 'netrc' -o -iname '.netrc' -o -iname '*.netrc' ')' )
    else
      name_tests+=( -iname "*.${ext}" )
    fi
  done

  if (( ${#name_tests[@]} == 0 )); then
    echo "No usable file extensions configured."
    return 0
  fi

  local results_file errors_file find_rc=0
  results_file="$(mktemp 2>/dev/null)" || { echo "Could not create a temporary results file."; return 1; }
  errors_file="$(mktemp 2>/dev/null)" || { rm -f -- "$results_file"; echo "Could not create a temporary error log."; return 1; }

  echo "Searching the filesystem for configured prohibited-file patterns: ${FILE_EXTENSIONS[*]}"
  # Pseudo-filesystems are excluded to avoid transient virtual files. The search
  # otherwise spans the filesystem tree and uses NUL delimiters for safe paths.
  if find / \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
      -type f \( "${name_tests[@]}" \) -print0 >"$results_file" 2>"$errors_file"; then
    find_rc=0
  else
    find_rc=$?
  fi

  local -a matches=()
  mapfile -d '' -t matches < "$results_file"
  rm -f -- "$results_file"

  if [[ -s "$errors_file" ]]; then
    echo "[WARN] Some paths could not be searched. First diagnostic lines:"
    sed -n '1,8p' "$errors_file"
    echo "Review filesystem access if you need a complete inventory."
  fi
  rm -f -- "$errors_file"
  if (( find_rc != 0 )); then
    echo "[WARN] find returned status ${find_rc}; any results below may be incomplete."
  fi

  if (( ${#matches[@]} == 0 )); then
    echo "No files matched the configured patterns."
    return 0
  fi

  echo
  printf 'Found %d matching file(s):\n' "${#matches[@]}"
  local i file details
  for i in "${!matches[@]}"; do
    file="${matches[$i]}"
    printf '  %d. ' "$((i + 1))"
    printf '%q\n' "$file"
    details="$(stat -c 'mode=%A owner=%U:%G size=%s bytes' -- "$file" 2>/dev/null || true)"
    [[ -n "$details" ]] && printf '     %s\n' "$details"
  done

  echo
  echo "Review each file. Keeping is the default; 'q' stops and leaves remaining files untouched."
  local answer kept=0 removed=0 failed=0 skipped=0 stop_review=0
  for i in "${!matches[@]}"; do
    file="${matches[$i]}"
    if (( stop_review )); then
      ((skipped+=1))
      continue
    fi

    printf '\n[%d/%d] ' "$((i + 1))" "${#matches[@]}"
    printf 'File: %q\n' "$file"
    while true; do
      if ! IFS= read -r -p 'Keep this file? [Y]es / [n]o (delete) / [q]uit [Y]: ' answer; then
        answer='q'
      fi
      case "${answer,,}" in
        ''|y|yes)
          echo "Keeping file."
          ((kept+=1))
          break
          ;;
        n|no|d|delete|remove)
          if [[ ! -f "$file" ]]; then
            echo "File no longer exists; nothing removed."
            ((skipped+=1))
          elif rm -- "$file"; then
            echo "Removed: $(printf '%q' "$file")"
            ((removed+=1))
          else
            echo "[ERROR] Could not remove file: $(printf '%q' "$file")"
            ((failed+=1))
          fi
          break
          ;;
        q|quit)
          echo "Stopping review. Remaining files will be left untouched."
          stop_review=1
          ((skipped+=1))
          break
          ;;
        *)
          echo "Please enter Y (keep), N (delete), or Q (quit review)."
          ;;
      esac
    done
  done

  printf '\nProhibited-file review complete: kept=%d removed=%d errors=%d left_unreviewed=%d\n' \
    "$kept" "$removed" "$failed" "$skipped"
  echo "No files were removed without an individual confirmation."
}
