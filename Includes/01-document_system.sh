# includes/01-document_system.sh (top of file)
#!/usr/bin/env bash
# Enable strict mode only when run directly, not when sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

# Provide a default docs dir if caller didn't export DOCS
: "${DOCS:=/root/system-docs}"

invoke_document_system() {
  echo "Running Documenting System..."
  mkdir -p "$DOCS" || true
  # ...rest of your collection logic, but guard optional tools:
  command -v dpkg   >/dev/null 2>&1 && dpkg -l   > "$DOCS/packages_dpkg.txt"   2>/dev/null || true
  command -v snap   >/dev/null 2>&1 && snap list > "$DOCS/snap.txt"            2>/dev/null || true
  command -v ss     >/dev/null 2>&1 && ss -plnt  > "$DOCS/ss_plnt.txt"         2>/dev/null || true

  # cron (tolerate empty/missing)
  : > "$DOCS/cron.txt"
  cut -f1 -d: /etc/passwd | while read -r u; do
    {
      echo "Cron jobs for user: $u"
      crontab -u "$u" -l 2>/dev/null || true
      echo
    } >> "$DOCS/cron.txt"
  done
  { cat /etc/crontab 2>/dev/null; cat /etc/cron.d/* 2>/dev/null; } >> "$DOCS/cron.txt" || true

  # baseline compare (tolerate unset)
  if [[ -n "${CURDPKG:-}" && -n "${VANILLA:-}" ]]; then
    : > "$DOCS/suspackages.txt"
    for I in ${CURDPKG:-}; do
      [[ "${VANILLA:-}" == *"$I"* ]] || echo "$I" >> "$DOCS/suspackages.txt"
    done
  fi

  echo "Documentation written to: $DOCS"
  return 0
}
