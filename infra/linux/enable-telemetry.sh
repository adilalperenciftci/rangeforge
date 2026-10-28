#!/usr/bin/env bash
# Install auditd with the RangeForge rule set on a Debian/Ubuntu lab host.
# Idempotent. Run as root (or via sudo). Expects rangeforge.rules next to it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rules_src="${1:-$here/rangeforge.rules}"

echo "==> packages"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq auditd audispd-plugins >/dev/null

echo "==> rules"
install -m 0640 -o root -g root "$rules_src" /etc/audit/rules.d/50-rangeforge.rules
# Immutable flag (-e 2) means a reboot is needed to change rules later; keep it
# out while in the lab so re-provisioning works without reboots.
sed -i 's/^-e 2$/-e 1/' /etc/audit/rules.d/50-rangeforge.rules
augenrules --load >/dev/null 2>&1 || true

echo "==> daemon"
sed -i 's/^max_log_file = .*/max_log_file = 64/' /etc/audit/auditd.conf
sed -i 's/^num_logs = .*/num_logs = 8/' /etc/audit/auditd.conf
sed -i 's/^max_log_file_action = .*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
systemctl enable --now auditd >/dev/null
service auditd restart >/dev/null 2>&1 || systemctl restart auditd

echo "==> summary"
echo "rules loaded: $(auditctl -l | wc -l)"
auditctl -s | sed 's/^/    /'
