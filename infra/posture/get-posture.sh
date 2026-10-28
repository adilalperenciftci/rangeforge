#!/usr/bin/env bash
# Collect a security-posture snapshot of a Linux host as one JSON object.
# Read-only; run as root (sudo) for complete results.
set -u

j() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
sshd_opt() { sshd -T 2>/dev/null | awk -v k="$1" '$1==k {print $2; exit}'; }
sysctl_v() { sysctl -n "$1" 2>/dev/null || echo ""; }
pkg_installed() { dpkg -s "$1" >/dev/null 2>&1 && echo true || echo false; }

host=$(hostname)
os=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")
kernel=$(uname -r)
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

auditd_active=$(systemctl is-active auditd 2>/dev/null | grep -q '^active$' && echo true || echo false)
auditd_rules=$(auditctl -l 2>/dev/null | grep -vc '^No rules' || echo 0)
auditd_immutable=$(auditctl -s 2>/dev/null | awk '/^enabled/ {print $2}')
journald_persistent=$([ -d /var/log/journal ] && echo true || echo false)

ssh_root=$(sshd_opt permitrootlogin)
ssh_pass=$(sshd_opt passwordauthentication)
ssh_maxauth=$(sshd_opt maxauthtries)
ssh_x11=$(sshd_opt x11forwarding)
ssh_empty=$(sshd_opt permitemptypasswords)

sudo_nopasswd=$(grep -rhE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | wc -l)
empty_pw_accounts=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null | wc -l)
uid0_accounts=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | wc -l)
pass_max_days=$(grep -E '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')
umask_default=$(grep -E '^UMASK' /etc/login.defs | awk '{print $2}')

aslr=$(sysctl_v kernel.randomize_va_space)
ptrace_scope=$(sysctl_v kernel.yama.ptrace_scope)
kptr=$(sysctl_v kernel.kptr_restrict)
dmesg_restrict=$(sysctl_v kernel.dmesg_restrict)
ip_forward=$(sysctl_v net.ipv4.ip_forward)
rp_filter=$(sysctl_v net.ipv4.conf.all.rp_filter)
suid_dumpable=$(sysctl_v fs.suid_dumpable)
unpriv_bpf=$(sysctl_v kernel.unprivileged_bpf_disabled)

ufw_active=$(ufw status 2>/dev/null | grep -q 'Status: active' && echo true || echo false)
nft_rules=$(nft list ruleset 2>/dev/null | grep -c 'chain' || echo 0)
listening=$(ss -Hlntu 2>/dev/null | awk '{print $5}' | sed 's/.*://' | sort -un | tr '\n' ',' | sed 's/,$//')

world_writable=$(find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | wc -l)
suid_count=$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l)
cron_allow=$([ -f /etc/cron.allow ] && echo true || echo false)
unattended=$(pkg_installed unattended-upgrades)
apparmor=$(systemctl is-active apparmor 2>/dev/null | grep -q '^active$' && echo true || echo false)
updates_pending=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || echo 0)
reboot_required=$([ -f /var/run/reboot-required ] && echo true || echo false)

cat <<EOF
{"host":"$(j "$host")","os":"$(j "$os")","kernel":"$kernel","collected_at":"$now",
"auditd_active":$auditd_active,"auditd_rules":${auditd_rules:-0},"auditd_enabled_flag":"${auditd_immutable:-}","journald_persistent":$journald_persistent,
"ssh_permit_root_login":"${ssh_root:-}","ssh_password_auth":"${ssh_pass:-}","ssh_max_auth_tries":${ssh_maxauth:-0},"ssh_x11_forwarding":"${ssh_x11:-}","ssh_permit_empty_passwords":"${ssh_empty:-}",
"sudo_nopasswd_entries":${sudo_nopasswd:-0},"empty_password_accounts":${empty_pw_accounts:-0},"uid0_accounts":${uid0_accounts:-1},"pass_max_days":${pass_max_days:-99999},"umask_default":"${umask_default:-}",
"aslr":${aslr:-0},"ptrace_scope":${ptrace_scope:-0},"kptr_restrict":${kptr:-0},"dmesg_restrict":${dmesg_restrict:-0},"ip_forward":${ip_forward:-0},"rp_filter":${rp_filter:-0},"suid_dumpable":${suid_dumpable:-0},"unprivileged_bpf_disabled":${unpriv_bpf:-0},
"ufw_active":$ufw_active,"nft_chains":${nft_rules:-0},"listening_ports":"$(j "$listening")",
"world_writable_files":${world_writable:-0},"suid_binaries":${suid_count:-0},"cron_allow_present":$cron_allow,"unattended_upgrades":$unattended,"apparmor_active":$apparmor,"updates_pending":${updates_pending:-0},"reboot_required":$reboot_required}
EOF
