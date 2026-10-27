#!/usr/bin/env bash
# Offline Docker prerequisites, shared by install.sh and setup.sh (sourced, never executed).
# Needs the caller to define SCRIPT_DIR (bundle root) and err(). Installs static Docker + Compose from
# tools/docker/ in the release bundle: no network, no package manager, any systemd Linux.
# Offline Docker prerequisites shipped in the bundle at tools/docker/ (static Docker + Compose).
# Same values as packaging/docker-static.pin; compose/tests/offline_prereqs_test.sh fails if they differ.
readonly DOCKER_STATIC_VERSION="29.9.2"
readonly COMPOSE_STATIC_VERSION="v5.6.1"
readonly DOCKER_SHA256_X86_64="9ac225999fd5e863f7694c728ef23d480616b1e5639328fa309befd4243d69eb"
readonly DOCKER_SHA256_AARCH64="873b3e0207857c3b2f28392fb922f3ea6efe37620c16d4d4aaf2fef409c90b73"
readonly COMPOSE_SHA256_X86_64="47737f4236e6d3ccea7291995203f8f018058783b4c3a9469119811a0b5db8c0"
readonly COMPOSE_SHA256_AARCH64="42cfa75f51ad0ccf290bad37899e0038a8c10a0069e85233ecc1d53e3ff1347d"

# ── Docker from the release bundle (no network, any systemd Linux) ─────────
# The bundle ships static Docker + Compose under tools/docker/. Every file is
# checked against the SHA-256 pinned above before it is unpacked or installed.
_docker_static_arch() {
  case "$(uname -m)" in
    x86_64)        echo x86_64 ;;
    aarch64|arm64) echo aarch64 ;;
    *) return 1 ;;
  esac
}

_docker_static_file() {  # <docker|compose> -> path of the bundled file for this CPU
  local arch; arch=$(_docker_static_arch) || return 1
  case "$1" in
    docker)  echo "${SCRIPT_DIR}/tools/docker/docker-${DOCKER_STATIC_VERSION}-${arch}.tgz" ;;
    compose) echo "${SCRIPT_DIR}/tools/docker/docker-compose-linux-${arch}" ;;
  esac
}

_docker_static_sha() {   # <docker|compose> -> pinned SHA-256 for this CPU
  local arch; arch=$(_docker_static_arch) || return 1
  case "$1:$arch" in
    docker:x86_64)   echo "$DOCKER_SHA256_X86_64" ;;
    docker:aarch64)  echo "$DOCKER_SHA256_AARCH64" ;;
    compose:x86_64)  echo "$COMPOSE_SHA256_X86_64" ;;
    compose:aarch64) echo "$COMPOSE_SHA256_AARCH64" ;;
  esac
}

_bundled_has() {         # <docker|compose> -> 0 when the bundle carries it for this CPU
  local f; f=$(_docker_static_file "$1") || return 1
  [[ -f "$f" ]]
}

_verify_bundled() {      # <docker|compose> -> prints the verified path, or errors
  local f sha
  f=$(_docker_static_file "$1") || { err "No bundled Docker for this architecture ($(uname -m))."; return 1; }
  sha=$(_docker_static_sha "$1")
  [[ -f "$f" ]] || { err "Bundled $1 not found at ${f}. The release bundle is incomplete."; return 1; }
  if ! echo "${sha}  ${f}" | sha256sum -c --status -; then
    err "Bundled $(basename "$f") does not match the SHA-256 pinned in this installer -- refusing to install it."; return 1
  fi
  echo "$f"
}

_install_bundled_compose() {
  local f; f=$(_verify_bundled compose) || exit 1
  install -d -m 0755 /usr/local/lib/docker/cli-plugins
  install -m 0755 "$f" /usr/local/lib/docker/cli-plugins/docker-compose
}

_install_bundled_docker() {
  command -v systemctl &>/dev/null || { err "systemd is required to run the bundled Docker as a service. Install Docker manually and re-run."; exit 1; }
  local f tmp b
  f=$(_verify_bundled docker) || exit 1
  tmp=$(mktemp -d)
  tar -xzf "$f" -C "$tmp" || { rm -rf "$tmp"; err "Could not unpack $(basename "$f")."; exit 1; }
  for b in docker dockerd containerd containerd-shim-runc-v2 ctr runc docker-proxy docker-init; do
    [[ -f "${tmp}/docker/${b}" ]] || { rm -rf "$tmp"; err "Bundled Docker archive is missing ${b}."; exit 1; }
    install -m 0755 "${tmp}/docker/${b}" "/usr/local/bin/${b}"
  done
  rm -rf "$tmp"
  getent group docker >/dev/null || groupadd --system docker
  cat > /etc/systemd/system/containerd.service <<'UNIT'
[Unit]
Description=containerd container runtime
After=network.target local-fs.target

[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/local/bin/containerd
Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5
LimitNPROC=infinity
LimitCORE=infinity
OOMScoreAdjust=-999

[Install]
WantedBy=multi-user.target
UNIT
  cat > /etc/systemd/system/docker.socket <<'UNIT'
[Unit]
Description=Docker Socket for the API

[Socket]
ListenStream=/run/docker.sock
SocketMode=0660
SocketUser=root
SocketGroup=docker

[Install]
WantedBy=sockets.target
UNIT
  cat > /etc/systemd/system/docker.service <<'UNIT'
[Unit]
Description=Docker Application Container Engine
After=network-online.target docker.socket containerd.service
Wants=network-online.target
Requires=docker.socket containerd.service

[Service]
Type=notify
ExecStart=/usr/local/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
ExecReload=/bin/kill -s HUP $MAINPID
TimeoutStartSec=0
RestartSec=2
Restart=always
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
KillMode=process
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now containerd.service docker.socket docker.service
  local i
  for i in $(seq 1 30); do docker info &>/dev/null && return 0; sleep 1; done
  err "The bundled Docker was installed but its daemon did not start. See: journalctl -u docker"; exit 1
}

