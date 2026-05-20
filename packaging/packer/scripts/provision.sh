#!/usr/bin/env bash
# Packer provisioner — Step 1: Install Docker CE and system dependencies
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[provision] Updating package index..."
apt-get update -qq

echo "[provision] Installing base packages..."
apt-get install -y -qq \
  ca-certificates curl wget gnupg \
  whiptail openssl jq net-tools \
  lsb-release software-properties-common \
  systemd-resolved \
  apparmor apparmor-utils

# ── Docker CE (official repository) ───────────────────────────────────────────
echo "[provision] Adding Docker apt repository..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list

apt-get update -qq

echo "[provision] Installing Docker CE..."
apt-get install -y -qq \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

# ── Docker post-install ────────────────────────────────────────────────────────
systemctl enable docker
systemctl start docker

# Add bas user to docker group so setup.sh can run docker compose without sudo
usermod -aG docker bas

echo "[provision] Docker $(docker --version) installed."
echo "[provision] Docker Compose $(docker compose version --short) installed."
