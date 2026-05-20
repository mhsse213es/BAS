#!/usr/bin/env bash
# Packer provisioner — Step 3: Sysprep
# Removes build-time artifacts so every cloned VM gets unique identity.
# Must be the LAST provisioner — SSH will not work after this.
set -euo pipefail

echo "[sysprep] Starting..."

# ── Remove build-time sudoers entry ───────────────────────────────────────────
rm -f /etc/sudoers.d/bas-packer
echo "[sysprep] Removed build-time sudoers."

# ── Lock the bas user password (firstboot wizard will set a real one) ─────────
passwd -l bas
# Force password change on first interactive login (belt-and-suspenders)
chage -d 0 bas 2>/dev/null || true
echo "[sysprep] bas account password locked."

# ── Remove SSH host keys (regenerated on first boot) ──────────────────────────
rm -f /etc/ssh/ssh_host_*
# Re-generate on boot via systemd
systemctl enable ssh-keygen 2>/dev/null || true
# For Ubuntu, the ssh service itself regenerates keys if missing
echo "[sysprep] SSH host keys removed."

# ── Clear machine-id (causes systemd-machine-id-setup to regenerate on boot) ──
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
ln -sf /etc/machine-id /var/lib/dbus/machine-id
echo "[sysprep] machine-id cleared."

# ── Remove cloud-init instance data (so cloud-init can re-run on clone) ───────
rm -rf /var/lib/cloud/instances /var/lib/cloud/instance
# Preserve cloud-init itself (customers may use it for VM customization)
echo "[sysprep] cloud-init instance cache cleared."

# ── Remove bash history ────────────────────────────────────────────────────────
unset HISTFILE
rm -f /root/.bash_history /home/bas/.bash_history
history -c 2>/dev/null || true
echo "[sysprep] Shell history cleared."

# ── Truncate system logs ───────────────────────────────────────────────────────
journalctl --rotate --vacuum-time=1s 2>/dev/null || true
find /var/log -type f \( -name "*.log" -o -name "*.gz" -o -name "*.old" -o -name "*.1" \) -delete 2>/dev/null || true
find /var/log -type f | while read -r f; do truncate -s 0 "$f" 2>/dev/null || true; done
echo "[sysprep] Logs cleared."

# ── Clean apt caches ───────────────────────────────────────────────────────────
apt-get clean -qq
rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
echo "[sysprep] APT cache cleaned."

# ── Remove packer temporary keys/files ────────────────────────────────────────
rm -f /home/bas/.ssh/authorized_keys 2>/dev/null || true
# Keep /home/bas/.ssh dir with correct perms for customer to inject their key
mkdir -p /home/bas/.ssh
chmod 0700 /home/bas/.ssh
chown bas:bas /home/bas/.ssh

echo "[sysprep] Complete. VM is ready for distribution."

# Zero free space for better compression of the QCOW2 image
echo "[sysprep] Zeroing free space (improves compression)..."
dd if=/dev/zero of=/ZERO bs=1M 2>/dev/null || true
rm -f /ZERO
sync
echo "[sysprep] Done."
