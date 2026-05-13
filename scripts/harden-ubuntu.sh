#!/usr/bin/env bash
# CIS Ubuntu 24.04 LTS Level 1 Hardening Script
# Run as root on a fresh Ubuntu 24.04 install BEFORE k3s setup.
# Reference: CIS Benchmark for Ubuntu Linux 24.04 LTS v1.0.0

set -euo pipefail
readonly LOG="/var/log/bas-harden.log"
exec > >(tee -a "$LOG") 2>&1

info()  { echo "[INFO]  $*"; }
warn()  { echo "[WARN]  $*"; }
error() { echo "[ERROR] $*"; exit 1; }

[[ $EUID -eq 0 ]] || error "Run as root"
[[ "$(lsb_release -rs)" == "24.04" ]] || warn "Expected Ubuntu 24.04 — continuing anyway"

info "=== BAS Platform: Ubuntu 24.04 CIS Hardening ==="

# ── 1. System Updates ──────────────────────────────────────────────────────────
info "[1] Applying system updates"
apt-get update -qq
apt-get upgrade -y -qq
apt-get install -y -qq \
    unattended-upgrades apt-listchanges auditd aide \
    fail2ban ufw apparmor apparmor-utils libpam-pwquality

# Enable automatic security updates
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Packages "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
systemctl enable --now unattended-upgrades
info "[1] Updates applied"

# ── 2. Remove Unnecessary Services ────────────────────────────────────────────
info "[2] Disabling unnecessary services"
UNUSED_SERVICES=(
    avahi-daemon cups bluetooth ModemManager
    whoopsie apport snapd
)
for svc in "${UNUSED_SERVICES[@]}"; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        systemctl disable --now "$svc" 2>/dev/null || true
        info "  Disabled: $svc"
    fi
done

# ── 3. Kernel Hardening (sysctl) ───────────────────────────────────────────────
info "[3] Applying kernel hardening"
cat > /etc/sysctl.d/99-bas-harden.conf << 'EOF'
# Network hardening
net.ipv4.ip_forward = 1                          # required for k3s
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Kernel hardening
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
sysctl -p /etc/sysctl.d/99-bas-harden.conf
info "[3] Kernel parameters applied"

# ── 4. UFW Firewall ────────────────────────────────────────────────────────────
info "[4] Configuring UFW firewall"
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment 'SSH'
ufw allow 80/tcp    comment 'HTTP (redirect to HTTPS)'
ufw allow 443/tcp   comment 'HTTPS — BAS dashboard + agent'
ufw allow 6443/tcp  comment 'k3s API server'
ufw --force enable
info "[4] UFW enabled"

# ── 5. SSH Hardening ──────────────────────────────────────────────────────────
info "[5] Hardening SSH"
SSH_CFG=/etc/ssh/sshd_config.d/99-bas-harden.conf
cat > "$SSH_CFG" << 'EOF'
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowAgentForwarding no
EOF
sshd -t && systemctl reload sshd
info "[5] SSH hardened"

# ── 6. PAM Password Policy ────────────────────────────────────────────────────
info "[6] Setting PAM password policy"
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
EOF
info "[6] Password policy applied"

# ── 7. Audit Daemon ───────────────────────────────────────────────────────────
info "[7] Configuring auditd"
cat > /etc/audit/rules.d/bas-audit.rules << 'EOF'
# Delete all existing rules
-D
# Buffer size
-b 8192
# Monitor privilege escalation
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
# Monitor user/group modification
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
# Monitor SSH config
-w /etc/ssh/sshd_config -p wa -k sshd
# Monitor k3s config
-w /etc/rancher -p wa -k k3s_config
# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d -p wa -k cron
# Unsuccessful file access
-a always,exit -F arch=b64 -S open,openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
# Privileged commands
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
EOF
augenrules --load
systemctl enable --now auditd
info "[7] auditd configured"

# ── 8. AppArmor ───────────────────────────────────────────────────────────────
info "[8] Ensuring AppArmor is enforcing"
aa-enforce /etc/apparmor.d/* 2>/dev/null || true
systemctl enable --now apparmor
info "[8] AppArmor enabled"

# ── 9. Fail2Ban ───────────────────────────────────────────────────────────────
info "[9] Configuring fail2ban"
cat > /etc/fail2ban/jail.d/bas.conf << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
EOF
systemctl enable --now fail2ban
info "[9] fail2ban enabled"

# ── 10. Core Dumps ────────────────────────────────────────────────────────────
info "[10] Disabling core dumps"
echo '* hard core 0' >> /etc/security/limits.conf
echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-bas-harden.conf

# ── Summary ───────────────────────────────────────────────────────────────────
info ""
info "=== Hardening complete ==="
info "Log: $LOG"
info ""
info "NEXT STEPS:"
info "  1. Create a non-root deploy user:  adduser basadmin && usermod -aG sudo basadmin"
info "  2. Copy your SSH public key:       ssh-copy-id basadmin@this-host"
info "  3. Disable password SSH and test login"
info "  4. Run: ./scripts/setup-postgres.sh"
info "  5. Run: ./scripts/install-k3s.sh"
