#!/usr/bin/env bash

# Includes are normally sourced by harden.sh; do not leak strict mode into the parent shell.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
fi

invoke_defensive_countermeasures () {
  echo -e "${CYAN}[Defensive Countermeasures] Start${NC}"

  dcm_ufw_reset_factory
  dcm_ufw_enable_and_boot
  dcm_ufw_loopback_policy
  dcm_ufw_deny_ping
  dcm_ufw_allow_ssh

  echo -e "${CYAN}[Defensive Countermeasures] Done${NC}"
}

# ------------------------------------------------------------
# UFW: reset to factory defaults (non-interactive)
# ------------------------------------------------------------
dcm_ufw_reset_factory () {
 sudo ufw --force reset
echo "UFW reset complete."
}

# ------------------------------------------------------------
# UFW: ensure enabled now and on boot
# ------------------------------------------------------------
dcm_ufw_enable_and_boot () {
  sudo ufw enable
echo "UFW enabled."

sudo systemctl enable ufw
echo "UFW enabled at boot."
}

# ------------------------------------------------------------
# UFW: loopback policy (allow lo in/out, deny spoofed loopback)
# ------------------------------------------------------------
dcm_ufw_loopback_policy () {
  sudo ufw allow in on lo
echo "UFW: allowed inbound traffic on lo."

sudo ufw allow out on lo
echo "UFW: allowed outbound traffic on lo."

sudo ufw deny in from 127.0.0.0/8
echo "UFW: denied inbound traffic from 127.0.0.0/8."

sudo ufw deny in from ::1
echo "UFW: denied inbound traffic from ::1."
}

# ------------------------------------------------------------
# UFW: deny ICMP echo-request (ping) responses
# ------------------------------------------------------------
dcm_ufw_deny_ping () {
 timestamp=$(date +%Y%m%d_%H%M%S)

for file in /etc/ufw/before.rules /etc/ufw/before6.rules; do
if [[ -f "$file" ]]; then
sudo cp -a "$file" "${file}.${timestamp}.bak"
fi
done

if [[ -f /etc/ufw/before.rules ]] && ! sudo grep -qF '# CYBERPATRIOT: Drop IPv4 ICMP echo-request' /etc/ufw/before.rules; then
sudo awk '
/-A ufw-before-input/ && /-p icmp/ && /--icmp-type/ && !inserted {
print "# CYBERPATRIOT: Drop IPv4 ICMP echo-request"
print "-A ufw-before-input -p icmp --icmp-type echo-request -j DROP"
inserted=1
}
{ print }
' /etc/ufw/before.rules | sudo tee /tmp/before.rules. >/dev/null && sudo mv /tmp/before.rules. /etc/ufw/before.rules
fi

if [[ -f /etc/ufw/before6.rules ]] && ! sudo grep -qF '# CYBERPATRIOT: Drop IPv6 ICMP echo-request' /etc/ufw/before6.rules; then
sudo awk '
/-A ufw6-before-input/ && /-p icmpv6/ && /--icmpv6-type/ && !inserted {
print "# CYBERPATRIOT: Drop IPv6 ICMP echo-request"
print "-A ufw6-before-input -p icmpv6 --icmpv6-type echo-request -j DROP"
inserted=1
}
{ print }
' /etc/ufw/before6.rules | sudo tee /tmp/before6.rules. >/dev/null && sudo mv /tmp/before6.rules. /etc/ufw/before6.rules
fi

if sudo ufw reload; then
echo "UFW ICMP echo-request drop rules applied and UFW reloaded."
else
echo "Warning: UFW reload failed."
fi

}

# ------------------------------------------------------------
# UFW: allow SSH
# ------------------------------------------------------------
dcm_ufw_allow_ssh () {
 sudo ufw allow OpenSSH
echo "UFW: allowed SSH using the OpenSSH profile."
}
