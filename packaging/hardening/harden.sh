#!/usr/bin/env bash
# BAS Platform — CIS Level 2 Hardening Script
#
# Applies CIS Ubuntu 24.04 LTS Benchmark Level 2 controls, tuned for BAS
# Platform (Docker Compose deployment).  All changes are logged and idempotent.
#
# Usage:
#   sudo bash harden.sh [--check | --apply] [--section <name>]
#
#   --check          Report current compliance status without making changes
#   --apply          Apply all hardening controls (default when run as root)
#   --section <name> Run only one section: filesystem|ssh|sysctl|ufw|apparmor|
#                                          auditd|services|pam|permissions|misc
#
# Notes:
#   • Docker requires net.ipv4.ip_forward=1 — this script preserves it.
#   • UFW + Docker: Docker manages its own iptables chains; this script applies
#     host-level UFW rules but does NOT disable Docker's iptables management.
#   • Run from the directory containing this script or pass full paths.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/bas-harden.log"
SYSCTL_FILE="/etc/sysctl.d/99-bas-hardening.conf"
SSH_CONFIG="/etc/ssh/sshd_config.d/99-bas-hardening.conf"
AUDIT_RULES_SRC="${SCRIPT_DIR}/audit/bas.rules"
AUDIT_RULES_DEST="/etc/audit/rules.d/bas.rules"
APPARMOR_PROFILE_SRC="${SCRIPT_DIR}/apparmor/bas-orchestrator"
APPARMOR_PROFILE_DEST="/etc/apparmor.d/bas-orchestrator"

# ── Mode + section ─────────────────────────────────────────────────────────────
MODE="apply"
SECTION="all"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)        MODE="check" ;;
    --apply)        MODE="apply" ;;
    --section)      shift; SECTION="${1:-all}" ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
  shift
done

if [[ $EUID -ne 0 && "$MODE" == "apply" ]]; then
  echo "Error: --apply requires root (sudo bash harden.sh)." >&2
  exit 1
fi

# ── Colour / logging ───────────────────────────────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

_log() { echo -e "$*" | tee -a "${LOG_FILE}" 2>/dev/null || echo -e "$*"; }
pass()  { _log "${GREEN}  [PASS]${NC} $*"; }
fail()  { _log "${RED}  [FAIL]${NC} $*"; FAIL_COUNT=$((FAIL_COUNT+1)); }
fix()   { _log "${YELLOW}  [FIX ]${NC} $*"; }
info()  { _log "${BLUE}  [INFO]${NC} $*"; }
section() { _log "\n${BLUE}══ $* ══${NC}"; }

FAIL_COUNT=0
apply() {
  # apply <description> <command...>
  local desc="$1"; shift
  if [[ "$MODE" == "check" ]]; then
    info "${desc} (skipped — check mode)"
  else
    fix "${desc}"
    "$@"
  fi
}

# ── Section dispatcher ─────────────────────────────────────────────────────────
run_section() {
  [[ "$SECTION" == "all" || "$SECTION" == "$1" ]] || return 0
  "harden_${1}"
}

# ══════════════════════════════════════════════════════════════════════════════
# 1. FILESYSTEM
# ══════════════════════════════════════════════════════════════════════════════
harden_filesystem() {
  section "1. Filesystem"

  # Disable uncommon filesystems
  local BLACKLIST_FILE="/etc/modprobe.d/bas-blacklist.conf"
  local MODULES_TO_DISABLE=(cramfs freevxfs jffs2 hfs hfsplus squashfs udf usb-storage)

  if [[ "$MODE" == "apply" ]]; then
    for mod in "${MODULES_TO_DISABLE[@]}"; do
      if ! grep -q "install ${mod}" "${BLACKLIST_FILE}" 2>/dev/null; then
        echo "install ${mod} /bin/true" >> "${BLACKLIST_FILE}"
      fi
    done
    fix "Blacklisted unused filesystem modules in ${BLACKLIST_FILE}"
  else
    for mod in "${MODULES_TO_DISABLE[@]}"; do
      if lsmod | grep -q "^${mod}"; then
        fail "Module ${mod} is loaded"
      else
        pass "Module ${mod} not loaded"
      fi
    done
  fi

  # /tmp — nodev, nosuid, noexec
  if findmnt -n /tmp | grep -q "noexec"; then
    pass "/tmp mounted with noexec"
  else
    apply "Mount /tmp with nodev,nosuid,noexec" \
      bash -c 'systemctl enable tmp.mount 2>/dev/null; \
               mkdir -p /etc/systemd/system/tmp.mount.d; \
               printf "[Mount]\nOptions=mode=1777,strictatime,nosuid,nodev,noexec\n" \
               > /etc/systemd/system/tmp.mount.d/options.conf; \
               systemctl daemon-reload && mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null || true'
    fail "/tmp not mounted noexec — applied (takes effect after remount)"
  fi

  # Sticky bit on world-writable dirs
  local WORLD_WRITABLE
  WORLD_WRITABLE=$(find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -v "^/proc\|^/sys\|^/var/lib/docker" || true)
  if [[ -z "$WORLD_WRITABLE" ]]; then
    pass "All world-writable directories have sticky bit"
  else
    apply "Set sticky bit on world-writable directories" \
      bash -c "find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -v '^/proc\|^/sys\|^/var/lib/docker' | xargs -r chmod +t"
    fail "World-writable directories without sticky bit — applied chmod +t"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 2. SSH HARDENING
# ══════════════════════════════════════════════════════════════════════════════
harden_ssh() {
  section "2. SSH"

  # Write a drop-in config to /etc/ssh/sshd_config.d/ (Ubuntu 24.04 supports this)
  local SSH_SETTINGS=(
    "Protocol 2"
    "LogLevel VERBOSE"
    "MaxAuthTries 4"
    "MaxSessions 4"
    "IgnoreRhosts yes"
    "HostbasedAuthentication no"
    "PermitRootLogin no"
    "PermitEmptyPasswords no"
    "PermitUserEnvironment no"
    "LoginGraceTime 60"
    "ClientAliveInterval 300"
    "ClientAliveCountMax 1"
    "TCPKeepAlive no"
    "AllowTcpForwarding no"
    "X11Forwarding no"
    "Banner /etc/issue.net"
    "Ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
    "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
  )

  local ALL_PASS=true
  for setting in "${SSH_SETTINGS[@]}"; do
    local key="${setting%% *}"
    if sshd -T 2>/dev/null | grep -qi "^${key,,} "; then
      local current
      current=$(sshd -T 2>/dev/null | grep -i "^${key,,} " | head -1)
      local expected_val
      expected_val=$(echo "$setting" | cut -d' ' -f2-)
      # For simple yes/no settings, check exact match
      if [[ "${current,,}" == *"${expected_val,,}"* ]]; then
        pass "sshd: ${setting}"
      else
        fail "sshd: ${key} — current: ${current}"
        ALL_PASS=false
      fi
    fi
  done

  if [[ "$MODE" == "apply" ]]; then
    info "Writing ${SSH_CONFIG}..."
    cat > "${SSH_CONFIG}" <<'SSHEOF'
# BAS Platform SSH hardening — CIS Ubuntu 24.04 Level 2
# Managed by harden.sh — do not edit directly
Protocol 2
LogLevel VERBOSE
MaxAuthTries 4
MaxSessions 4
LoginGraceTime 60
IgnoreRhosts yes
HostbasedAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
ClientAliveInterval 300
ClientAliveCountMax 1
TCPKeepAlive no
AllowTcpForwarding no
X11Forwarding no
Ciphers aes256-ctr,aes192-ctr,aes128-ctr,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
SSHEOF
    systemctl reload ssh 2>/dev/null || true
    fix "SSH hardening config written and sshd reloaded."
  fi

  # Login banner
  if [[ -f /etc/issue.net ]] && grep -q "Authorized" /etc/issue.net; then
    pass "Login banner set"
  else
    apply "Set login banner" \
      bash -c 'cat > /etc/issue.net <<BANNER
Authorized use only. All access is monitored and logged.
Unauthorized access is prohibited and may be subject to prosecution.
BANNER'
    fail "Login banner not set — applied"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 3. KERNEL PARAMETERS (sysctl)
# ══════════════════════════════════════════════════════════════════════════════
harden_sysctl() {
  section "3. Kernel Parameters (sysctl)"

  # NOTE: net.ipv4.ip_forward is intentionally left at 1 — required by Docker.
  declare -A SYSCTL_PARAMS=(
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.conf.default.send_redirects"]="0"
    ["net.ipv4.conf.all.accept_source_route"]="0"
    ["net.ipv4.conf.default.accept_source_route"]="0"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.default.accept_redirects"]="0"
    ["net.ipv4.conf.all.secure_redirects"]="0"
    ["net.ipv4.conf.default.secure_redirects"]="0"
    ["net.ipv4.conf.all.log_martians"]="1"
    ["net.ipv4.conf.default.log_martians"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
    ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
    ["net.ipv4.conf.all.rp_filter"]="1"
    ["net.ipv4.conf.default.rp_filter"]="1"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv6.conf.all.accept_ra"]="0"
    ["net.ipv6.conf.default.accept_ra"]="0"
    ["net.ipv6.conf.all.accept_redirects"]="0"
    ["net.ipv6.conf.default.accept_redirects"]="0"
    ["kernel.randomize_va_space"]="2"
    ["fs.suid_dumpable"]="0"
    ["kernel.dmesg_restrict"]="1"
    ["kernel.perf_event_paranoid"]="3"
    ["kernel.kptr_restrict"]="2"
    ["net.core.bpf_jit_harden"]="2"
    ["net.ipv4.tcp_timestamps"]="0"
  )

  if [[ "$MODE" == "apply" ]]; then
    {
      echo "# BAS Platform kernel hardening — CIS Ubuntu 24.04 Level 2"
      echo "# net.ipv4.ip_forward is deliberately NOT set here (required by Docker)"
      for param in "${!SYSCTL_PARAMS[@]}"; do
        echo "${param} = ${SYSCTL_PARAMS[$param]}"
      done
    } > "${SYSCTL_FILE}"
    sysctl -p "${SYSCTL_FILE}" &>/dev/null
    fix "Applied ${#SYSCTL_PARAMS[@]} sysctl parameters → ${SYSCTL_FILE}"
  else
    for param in "${!SYSCTL_PARAMS[@]}"; do
      local expected="${SYSCTL_PARAMS[$param]}"
      local current
      current=$(sysctl -n "$param" 2>/dev/null || echo "MISSING")
      if [[ "$current" == "$expected" ]]; then
        pass "sysctl ${param} = ${current}"
      else
        fail "sysctl ${param} = ${current} (expected ${expected})"
      fi
    done
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 4. UFW FIREWALL
# ══════════════════════════════════════════════════════════════════════════════
harden_ufw() {
  section "4. Firewall (UFW)"
  info "Note: Docker manages its own iptables chains. UFW rules apply to host traffic only."
  info "Port 9000 is exposed by Docker directly via iptables — UFW FORWARD rules do not block it."

  if ! command -v ufw &>/dev/null; then
    apply "Install UFW" apt-get install -y -qq ufw
  fi

  if ufw status | grep -q "Status: active"; then
    pass "UFW is active"
  else
    apply "Enable UFW" bash -c 'ufw --force enable'
    fail "UFW was not active — enabled"
  fi

  # Check/apply default policies
  if ufw status verbose | grep -q "Default: deny (incoming)"; then
    pass "UFW default deny incoming"
  else
    apply "Set UFW default deny incoming" ufw default deny incoming
    fail "UFW default incoming was not deny — applied"
  fi

  if ufw status verbose | grep -q "allow (outgoing)"; then
    pass "UFW default allow outgoing"
  else
    apply "Set UFW default allow outgoing" ufw default allow outgoing
    fail "UFW default outgoing not allow — applied"
  fi

  # SSH (rate-limited)
  if ufw status | grep -q "22/tcp.*LIMIT"; then
    pass "UFW SSH rate-limited"
  else
    apply "Rate-limit SSH on UFW" bash -c 'ufw delete allow 22/tcp 2>/dev/null; ufw limit 22/tcp'
    fail "UFW SSH not rate-limited — applied"
  fi

  # Reload
  [[ "$MODE" == "apply" ]] && ufw reload &>/dev/null && fix "UFW reloaded."
}

# ══════════════════════════════════════════════════════════════════════════════
# 5. APPARMOR
# ══════════════════════════════════════════════════════════════════════════════
harden_apparmor() {
  section "5. AppArmor"

  if ! command -v apparmor_status &>/dev/null; then
    apply "Install AppArmor utilities" apt-get install -y -qq apparmor apparmor-utils
  fi

  if apparmor_status 2>/dev/null | grep -q "apparmor module is loaded"; then
    pass "AppArmor module loaded"
  else
    apply "Enable AppArmor" bash -c 'systemctl enable --now apparmor'
    fail "AppArmor not loaded — enabled"
  fi

  # Enforce all existing profiles
  if [[ "$MODE" == "apply" ]]; then
    aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    fix "All existing AppArmor profiles set to enforce."
  fi

  # Install bas-orchestrator profile
  if [[ -f "$APPARMOR_PROFILE_SRC" ]]; then
    if diff -q "${APPARMOR_PROFILE_SRC}" "${APPARMOR_PROFILE_DEST}" &>/dev/null; then
      pass "bas-orchestrator AppArmor profile installed and current"
    else
      apply "Install bas-orchestrator AppArmor profile" bash -c \
        "cp '${APPARMOR_PROFILE_SRC}' '${APPARMOR_PROFILE_DEST}' && \
         apparmor_parser -r '${APPARMOR_PROFILE_DEST}' && \
         aa-enforce '${APPARMOR_PROFILE_DEST}'"
      fail "bas-orchestrator AppArmor profile missing/outdated — installed"
    fi
  else
    info "AppArmor profile source not found at ${APPARMOR_PROFILE_SRC} — skipping."
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 6. AUDITD
# ══════════════════════════════════════════════════════════════════════════════
harden_auditd() {
  section "6. Auditd"

  if ! command -v auditd &>/dev/null; then
    apply "Install auditd + audispd-plugins" \
      apt-get install -y -qq auditd audispd-plugins
  fi

  if systemctl is-active --quiet auditd; then
    pass "auditd is running"
  else
    apply "Enable and start auditd" bash -c 'systemctl enable --now auditd'
    fail "auditd not running — started"
  fi

  if [[ -f "$AUDIT_RULES_SRC" ]]; then
    if diff -q "${AUDIT_RULES_SRC}" "${AUDIT_RULES_DEST}" &>/dev/null; then
      pass "BAS audit rules installed and current"
    else
      apply "Install BAS audit rules" bash -c \
        "cp '${AUDIT_RULES_SRC}' '${AUDIT_RULES_DEST}' && \
         augenrules --load 2>/dev/null || auditctl -R '${AUDIT_RULES_DEST}'"
      fail "BAS audit rules missing/outdated — installed"
    fi
  else
    info "Audit rules source not found at ${AUDIT_RULES_SRC} — skipping."
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 7. SERVICES
# ══════════════════════════════════════════════════════════════════════════════
harden_services() {
  section "7. Services (disable unused)"

  local DISABLE_SERVICES=(
    avahi-daemon    # mDNS/zeroconf — not needed
    cups            # printing — not needed
    isc-dhcp-server # DHCP server — not needed
    bind9           # DNS server — not needed
    vsftpd          # FTP — not needed
    apache2         # web server — BAS uses its own
    nginx           # web server — BAS uses its own
    rpcbind         # NFS/RPC — not needed
    nfs-server      # NFS — not needed
    nis             # NIS — not needed
    rsync           # rsync daemon — not needed
    snmpd           # SNMP — not needed
    telnet          # insecure — not needed
  )

  for svc in "${DISABLE_SERVICES[@]}"; do
    if systemctl is-enabled --quiet "${svc}" 2>/dev/null; then
      apply "Disable service: ${svc}" bash -c \
        "systemctl disable --now '${svc}' 2>/dev/null || true"
      fail "${svc} was enabled — disabled"
    else
      pass "Service ${svc} not enabled"
    fi
  done

  # Ensure required services are running
  for svc in docker ssh; do
    if systemctl is-active --quiet "${svc}" 2>/dev/null; then
      pass "Required service ${svc} is running"
    else
      apply "Enable ${svc}" bash -c "systemctl enable --now '${svc}'"
      fail "Required service ${svc} not running — started"
    fi
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# 8. PAM / PASSWORD POLICY
# ══════════════════════════════════════════════════════════════════════════════
harden_pam() {
  section "8. PAM / Password Policy"

  # Install libpam-pwquality if not present
  if ! dpkg -l libpam-pwquality &>/dev/null; then
    apply "Install libpam-pwquality" apt-get install -y -qq libpam-pwquality
  fi

  # pwquality config
  local PWQUALITY_CONF="/etc/security/pwquality.conf"
  local PWQUALITY_SETTINGS=(
    "minlen = 14"
    "dcredit = -1"
    "ucredit = -1"
    "ocredit = -1"
    "lcredit = -1"
    "maxrepeat = 3"
    "gecoscheck = 1"
    "dictcheck = 1"
  )

  local PW_OK=true
  for setting in "${PWQUALITY_SETTINGS[@]}"; do
    local key="${setting%% *}"
    if grep -q "^${key}" "${PWQUALITY_CONF}" 2>/dev/null; then
      pass "pwquality: ${setting}"
    else
      fail "pwquality: ${key} not configured"
      PW_OK=false
    fi
  done

  if [[ "$MODE" == "apply" ]]; then
    for setting in "${PWQUALITY_SETTINGS[@]}"; do
      local key="${setting%% *}"
      local val="${setting#* = }"
      if grep -q "^${key}" "${PWQUALITY_CONF}" 2>/dev/null; then
        sed -i "s/^${key}.*/${setting}/" "${PWQUALITY_CONF}"
      else
        echo "${setting}" >> "${PWQUALITY_CONF}"
      fi
    done
    fix "pwquality settings applied."
  fi

  # Password aging
  local LOGIN_DEFS="/etc/login.defs"
  declare -A AGING=(
    ["PASS_MAX_DAYS"]="90"
    ["PASS_MIN_DAYS"]="1"
    ["PASS_WARN_AGE"]="14"
  )
  for key in "${!AGING[@]}"; do
    local expected="${AGING[$key]}"
    local current
    current=$(grep -E "^${key}" "${LOGIN_DEFS}" | awk '{print $2}' || echo "MISSING")
    if [[ "$current" == "$expected" ]]; then
      pass "${key} = ${current}"
    else
      apply "Set ${key}=${expected}" \
        sed -i "s/^${key}.*/${key}\t${expected}/" "${LOGIN_DEFS}"
      fail "${key} = ${current} (expected ${expected}) — applied"
    fi
  done

  # Account lockout (faillock — Ubuntu 24.04 uses pam_faillock)
  local FAILLOCK_CONF="/etc/security/faillock.conf"
  if [[ -f "$FAILLOCK_CONF" ]]; then
    if grep -q "^deny = " "${FAILLOCK_CONF}"; then
      pass "faillock deny configured"
    else
      apply "Configure faillock" bash -c \
        'grep -q "^deny" /etc/security/faillock.conf || echo "deny = 5" >> /etc/security/faillock.conf
         grep -q "^unlock_time" /etc/security/faillock.conf || echo "unlock_time = 900" >> /etc/security/faillock.conf'
      fail "faillock not configured — applied (deny=5, unlock=900s)"
    fi
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 9. FILE PERMISSIONS
# ══════════════════════════════════════════════════════════════════════════════
harden_permissions() {
  section "9. File Permissions"

  declare -A FILE_PERMS=(
    ["/etc/passwd"]="644"
    ["/etc/passwd-"]="600"
    ["/etc/shadow"]="640"
    ["/etc/shadow-"]="600"
    ["/etc/group"]="644"
    ["/etc/group-"]="600"
    ["/etc/gshadow"]="640"
    ["/etc/gshadow-"]="600"
    ["/etc/ssh/sshd_config"]="600"
    ["/boot/grub/grub.cfg"]="400"
  )

  for f in "${!FILE_PERMS[@]}"; do
    [[ -f "$f" ]] || continue
    local expected="${FILE_PERMS[$f]}"
    local current
    current=$(stat -c '%a' "$f")
    if [[ "$current" == "$expected" ]]; then
      pass "chmod ${expected} ${f}"
    else
      apply "chmod ${expected} ${f}" chmod "${expected}" "${f}"
      fail "${f} perms = ${current} (expected ${expected}) — applied"
    fi
  done

  # BAS config file permissions
  if [[ -f /opt/bas-platform/.env ]]; then
    local perms
    perms=$(stat -c '%a' /opt/bas-platform/.env)
    if [[ "$perms" == "640" ]]; then
      pass "/opt/bas-platform/.env is 640"
    else
      apply "Secure .env permissions" chmod 640 /opt/bas-platform/.env
      fail "/opt/bas-platform/.env perms = ${perms} (expected 640) — applied"
    fi
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# 10. MISCELLANEOUS CIS CONTROLS
# ══════════════════════════════════════════════════════════════════════════════
harden_misc() {
  section "10. Miscellaneous"

  # GRUB password (warning only — not enforced as it disrupts VM recovery)
  if grep -q "^GRUB_PASSWORD\|set superusers\|password_pbkdf2" /etc/grub.d/* 2>/dev/null; then
    pass "GRUB password configured"
  else
    info "WARN: GRUB bootloader not password-protected (CIS 1.4.1). For appliance: acceptable — set if physical access is a concern."
  fi

  # Core dumps disabled
  if grep -q "^\* hard core 0" /etc/security/limits.conf 2>/dev/null; then
    pass "Core dumps disabled"
  else
    apply "Disable core dumps" bash -c \
      'echo "* hard core 0" >> /etc/security/limits.conf
       echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-bas-hardening.conf 2>/dev/null || true'
    fail "Core dumps not disabled — applied"
  fi

  # Ensure /etc/cron.* files are not world-readable
  for crondir in /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$crondir" ]] || continue
    local perms
    perms=$(stat -c '%a' "$crondir")
    if [[ "$perms" =~ ^[0-7]00$ || "$perms" == "700" || "$perms" == "600" ]]; then
      pass "${crondir} permissions OK (${perms})"
    else
      apply "Restrict ${crondir}" chmod og-rwx "${crondir}"
      fail "${crondir} perms = ${perms} — restricted"
    fi
  done

  # Remove legacy/insecure packages
  local REMOVE_PACKAGES=(telnet nis yp-tools rsh-client rsh-redone-client)
  for pkg in "${REMOVE_PACKAGES[@]}"; do
    if dpkg -l "${pkg}" &>/dev/null; then
      apply "Remove insecure package: ${pkg}" apt-get purge -y -qq "${pkg}"
      fail "${pkg} is installed — removed"
    else
      pass "${pkg} not installed"
    fi
  done

  # Ensure automatic security updates are configured
  if systemctl is-active --quiet unattended-upgrades 2>/dev/null; then
    pass "Unattended security upgrades active"
  else
    apply "Enable unattended security upgrades" bash -c \
      'apt-get install -y -qq unattended-upgrades && \
       dpkg-reconfigure -plow unattended-upgrades 2>/dev/null || true'
    fail "Unattended upgrades not active — enabled"
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
main() {
  echo ""
  echo "  BAS Platform — CIS Level 2 Hardening"
  echo "  Mode: ${MODE}  |  Section: ${SECTION}"
  echo "  Log:  ${LOG_FILE}"
  echo ""

  run_section filesystem
  run_section ssh
  run_section sysctl
  run_section ufw
  run_section apparmor
  run_section auditd
  run_section services
  run_section pam
  run_section permissions
  run_section misc

  echo ""
  if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}  All checks passed.${NC}"
  else
    echo -e "${YELLOW}  ${FAIL_COUNT} item(s) were not compliant.${NC}"
    if [[ "$MODE" == "check" ]]; then
      echo "  Run with --apply to remediate: sudo bash harden.sh --apply"
    else
      echo "  Changes applied. Review ${LOG_FILE} for details."
    fi
  fi
  echo ""
}

main "$@"
