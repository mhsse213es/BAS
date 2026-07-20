# install.sh Docker/Compose Auto-Install — Design

## Context

`packaging/compose/setup.conf.template` documents `install.sh` — not `setup.sh` — as the command operators actually run for real client installs (`sudo bash install.sh --check --config setup.conf`, `sudo bash install.sh --install --config setup.conf`). `install.sh` is the strict, config-driven "BFSI-Grade Installer" (`--check`/`--install`/`--upgrade`/`--rollback`/`--status`/`--uninstall`) whose `--check` output is explicitly meant to be "attach[ed] to CAB" (change-approval-board) tickets — it is the production path for on-prem client deployments.

Today, `_check_docker()` and `_check_compose()` (`packaging/compose/install.sh:228-248`) return `FAIL:...not installed (required)` / `FAIL:...plugin not found` when either is missing. In `mode_install()` (`install.sh:414`), `render_checks "${results[@]}" || exit 1` (`install.sh:433`) makes any `FAIL` abort the install immediately — so a fresh host without Docker cannot be installed on at all; the operator must manually install Docker out-of-band first, then re-run.

A parallel, newer script (`setup.sh`, whiptail-wizard-based, with a `--no-wizard --config` mode intended for a not-yet-built Python web wizard) already has working Docker CE auto-install logic for Ubuntu/Debian (`install_docker()`, `setup.sh:284-301`, using Docker's official documented apt method), gated only by an implicit "Press OK to continue" in the interactive wizard flow — not an explicit, dedicated consent prompt, and not present in `install.sh` at all.

This plan ports and hardens that capability into `install.sh`: when Docker and/or Compose are missing, ask the operator for explicit permission to download and install Docker CE from Docker's official repository, then proceed — instead of hard-failing.

## Goal

`sudo bash install.sh --install --config setup.conf` on a host without Docker no longer hard-fails. It reports Docker/Compose as installable (not fatal), asks for explicit yes/no confirmation before touching the system, and on "yes" installs Docker CE from Docker's official upstream repository (apt for Ubuntu, dnf for Rocky/RHEL/CentOS — the same OS families `install.sh` already supports per `_check_os`), then continues the install. `--check` (the CAB report mode) remains a pure read-only report and never installs anything. `--yes`/`-y` (already used to skip the rollback/uninstall confirmations) doubles as the non-interactive consent switch for unattended, CAB-scheduled runs.

## Architecture

### 1. Detection — `INST` status instead of `FAIL`

`_check_docker()` and `_check_compose()` change their "not installed" case from `FAIL` to a new `INST` status (mirroring the label `setup.sh:211`/`:228` already uses), and set new global flags:

```bash
# ── Argument parsing ── (near existing MODE/CONFIG_FILE/PURGE_IMAGES/YES globals)
NEED_DOCKER=false
NEED_COMPOSE=false
DOCKER_AUTO_INSTALLED=false
```

```bash
_check_docker() {
  if ! command -v docker &>/dev/null; then
    NEED_DOCKER=true
    echo "INST:Docker -not installed (installer can install it with your consent)"
    return
  fi
  if ! docker info &>/dev/null 2>&1; then
    echo "FAIL:Docker -daemon not running (start it before install)"
    return
  fi
  local ver
  ver=$(docker --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
  echo "PASS:Docker -${ver}"
}

_check_compose() {
  if docker compose version &>/dev/null 2>&1; then
    local ver
    ver=$(docker compose version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
    echo "PASS:Docker Compose -${ver}"
  else
    NEED_COMPOSE=true
    echo "INST:Docker Compose -not installed (installer can install it with your consent)"
  fi
}
```

A daemon that's installed but not running is unchanged — still `FAIL`. Auto-starting a stopped daemon is a different, riskier class of change (could be stopped deliberately) and is out of scope; see Non-goals.

`render_checks()` (`install.sh:345-366`) gains an `INST` case, styled after the existing `PASS`/`FAIL`/`WARN`/`INFO` cases, printed but **not** counted toward `fails`:

```bash
    case "$severity" in
      PASS) echo -e "  ${GREEN}[PASS]${NC} $msg" ;;
      FAIL) echo -e "  ${RED}[FAIL]${NC} $msg"; (( fails++ )) ;;
      WARN) echo -e "  ${YELLOW}[WARN]${NC} $msg"; (( warns++ )) ;;
      INST) echo -e "  ${CYAN}[INST]${NC} $msg" ;;
      INFO) echo -e "        $msg" ;;
    esac
```

This changes both `mode_check` and `mode_install`'s prereq reports identically, since both call the same `_check_docker`/`_check_compose`/`render_checks`. `mode_check` never calls `_install_docker` (see Non-goals) — it only reports what *would* happen on `--install`.

### 2. Consent prompt + install step — `mode_install()`

Inserted as a new step 2 right after the existing prereq report (`install.sh:433`, `render_checks "${results[@]}" || exit 1` — still hard-stops on any real `FAIL`, e.g. daemon-not-running, insufficient RAM/disk, missing licence). All later steps renumber from `N/9` to `N/10`:

```bash
  step "2/10  Docker Engine"
  if $NEED_DOCKER || $NEED_COMPOSE; then
    echo ""
    echo "  Docker and/or Docker Compose are not installed on this host."
    echo "  The installer can download and install Docker CE from Docker's official"
    echo "  repository (download.docker.com) and enable it as a system service."
    echo ""
    if ! $YES; then
      read -rp "  Install Docker CE now from the official Docker repository? [yes/N] " confirm
      [[ "$confirm" == "yes" ]] || { err "Docker is required to continue. Install it manually (or re-run with --yes) and re-run --install."; exit 1; }
    fi
    _install_docker
    DOCKER_AUTO_INSTALLED=true
    log "Docker CE installed: $(docker --version)"
  else
    log "Docker already present -skipping"
  fi
```

On a non-interactive run without `--yes` (no TTY), `read -rp` reads EOF immediately, `confirm` stays empty, the `[[ "$confirm" == "yes" ]]` check fails, and the script exits with the same clear "re-run with --yes" message — identical failure mode to today's existing `read -rp "Confirm rollback?"` gate (`install.sh:598-601`), so this introduces no new class of hang.

### 3. `_install_docker()` — new function, OS-aware

Placed near the other `_check_*`/`_install_*`-style helpers. Ubuntu/Debian branch ports `setup.sh:284-301` verbatim (Docker's own documented official method: import `download.docker.com`'s GPG key, add the apt repo pinned via `signed-by`, install `docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin`, enable the service). A new Rocky/RHEL/CentOS branch is added since `install.sh` (unlike `setup.sh`) explicitly supports that OS family per `_check_os` (`install.sh:221-223`), using Docker's equally-official dnf method:

```bash
_install_docker() {
  local os_id
  os_id=$(grep -oP '(?<=^ID=).+' /etc/os-release 2>/dev/null | tr -d '"' || echo "unknown")
  case "$os_id" in
    ubuntu|debian)
      apt-get update -qq
      apt-get install -y -qq ca-certificates curl gnupg lsb-release
      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      chmod a+r /etc/apt/keyrings/docker.gpg
      echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${os_id} $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
      apt-get update -qq
      apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
      ;;
    rocky|rhel|centos)
      dnf install -y -q dnf-plugins-core
      dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
      dnf install -y -q \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin
      ;;
    *)
      err "Automatic Docker install is not supported on this OS (${os_id})."
      info "Install Docker CE manually: https://docs.docker.com/engine/install/"
      exit 1
      ;;
  esac
  systemctl enable --now docker
}
```

Note: the Ubuntu branch parameterizes `os_id` into the repo URL (`linux/${os_id}`) rather than hardcoding `linux/ubuntu` as `setup.sh` does today — this makes the Debian case actually correct (Docker publishes separate `linux/ubuntu` and `linux/debian` repos), a small accuracy fix over the `setup.sh` original that this plan does not need to backport (see Non-goals).

### 4. Audit trail — `_write_install_log()`

One new line, consistent with the existing fields (`install.sh:842-855`):

```bash
    echo "Docker CE : $($DOCKER_AUTO_INSTALLED && echo 'auto-installed by installer' || echo 'pre-existing')"
```

Placed alongside the existing `Admin`/`TLS`/`Port` lines. This gives CAB/audit reviewers a record of whether the installer modified the host's package set beyond the application itself.

### 5. Usage banner / `--yes` documentation

The top-of-file usage comment (`install.sh:4-10`) and the two `Usage:` error strings (`install.sh:84`, `:91`) get `--yes` called out as also covering the Docker-install consent prompt, e.g.:

```
#   sudo bash install.sh --install  --config setup.conf [--yes]  # first-time install
#                                                                  #   --yes also grants
#                                                                  #   consent to auto-install
#                                                                  #   Docker CE if missing
```

## Non-goals

- **`--check` never installs anything.** It reports `INST` status (informational: "would be auto-installed with consent on --install") but never calls `_install_docker`, since its whole purpose is a safe, non-destructive report for change-approval review before a maintenance window.
- **A daemon that's installed but stopped is not auto-started.** Stays a hard `FAIL` ("start it before install") — a stopped Docker daemon may be stopped deliberately (e.g. mid-maintenance on a shared host), so silently starting it is a different and riskier kind of change than installing a missing package, and is not part of this request.
- **`mode_upgrade` is untouched.** An upgrade only runs against an existing installation (`install.sh:524`, hard-fails if `${DATA_DIR}/docker-compose.yml` doesn't exist), which already implies Docker is present.
- **No new CLI flag.** Reuses the existing `--yes`/`-y` flag (already the established "skip interactive confirmation" switch for `--rollback` and `--uninstall`) rather than introducing a Docker-specific one.
- **`setup.sh`'s existing auto-install is not touched by this plan.** Its own hardcoded `linux/ubuntu` repo URL and implicit-consent UX are pre-existing and out of scope here, per the earlier scoping decision to focus on `install.sh` (the actual documented production path). A follow-up could bring `setup.sh` in line with this design later.
- **No GPG key fingerprint pinning beyond what `setup.sh` already does.** The curl-pipe-to-`gpg --dearmor` pattern is Docker's own documented official installation method; this plan doesn't add verification that doesn't already exist elsewhere in this codebase's Docker-install path.

## Testing

`install.sh` has no existing automated test harness (it's a standalone bash script invoked by an operator against a real or CAB-provisioned host, not covered by the Go test suite). Verification is manual/scripted:

1. **Static check:** `bash -n install.sh` (syntax) and `shellcheck install.sh` if available in the environment (the repo already has a `staticcheck.conf` for Go; no existing shellcheck config, so this is best-effort, not a hard gate).
2. **`--check` on a Docker-less host** (fresh Ubuntu 22.04 or Rocky 9 container/VM): confirms `INST` lines appear for Docker/Compose, exit code reflects no fatal `FAIL`, and no package is installed as a side effect.
3. **`--install --config setup.conf` on the same host, interactively, answering "no"** at the consent prompt: confirms it aborts cleanly with the "Install it manually... and re-run" message, without side effects.
4. **`--install --config setup.conf` on the same host, interactively, answering "yes"**: confirms Docker CE installs successfully, the install proceeds through to a running stack, and `install.log` shows `Docker CE : auto-installed by installer`.
5. **`--install --config setup.conf --yes` on a Docker-less host, unattended** (e.g. `< /dev/null` to simulate no TTY): confirms it installs without prompting.
6. **`--install --config setup.conf` on a host that already has Docker + Compose**: confirms the "Docker already present -skipping" path, no network calls, `install.log` shows `Docker CE : pre-existing`.
7. **Unsupported OS** (e.g. a container with an unrecognized `/etc/os-release` `ID`): confirms `_install_docker` exits with the clear manual-install-required error rather than guessing a package manager.
