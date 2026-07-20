# install.sh Docker Auto-Install Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `packaging/compose/install.sh --install` runs on a host without Docker/Compose, it asks the operator for explicit permission to install Docker CE from Docker's official repository instead of hard-failing, while `--check` stays a pure read-only report.

**Architecture:** `_check_docker`/`_check_compose` change their "missing" verdict from fatal `FAIL` to non-fatal `INST` (informational: installable) and set `NEED_DOCKER`/`NEED_COMPOSE` flags. A new OS-aware `_install_docker()` function (apt for Ubuntu/Debian, dnf for Rocky/RHEL/CentOS) is gated behind a new consent step inserted into `mode_install()`, reusing the existing `--yes`/`-y` flag for unattended runs. Along the way, a pre-existing bug in `render_checks()`'s fail/warn counters (found while establishing a test baseline) gets fixed, since it sits in the exact function this plan extends.

**Tech Stack:** Bash (`set -euo pipefail`), Docker CLI, apt/dnf, systemd. No existing automated test harness for this script — verification is live, via throwaway Docker containers standing in for target hosts (the same technique used to find the baseline bug).

## Global Constraints

- Supported OS families (per existing `_check_os`, `install.sh:213-226`): Ubuntu 20.04+, Rocky/RHEL/CentOS 9+. `_install_docker` must handle both; any other OS gets a clear manual-install error, not a guessed package manager.
- No new CLI flag — reuse the existing `--yes`/`-y` flag (`install.sh:69,81`) as the unattended-consent switch.
- `--check` (`mode_check`) must never install anything — it only reports what `--install` would do.
- A Docker daemon that's installed but not running stays a hard `FAIL` — never auto-started.
- `mode_upgrade` is untouched (an upgrade only runs against an existing install, which already implies Docker is present).
- Docker CE is installed via Docker's own officially documented method (`download.docker.com` apt/dnf repos) — same trust model already used by `packaging/compose/setup.sh:284-301`.

---

### Task 1: Fix the `render_checks()` fail/warn counter bug

**Files:**
- Modify: `packaging/compose/install.sh:345-366` (`render_checks`)

**Interfaces:**
- Produces: `render_checks()` — unchanged signature/behavior contract (takes `"${results[@]}"` of `SEVERITY:message` strings, prints them, returns 1 if any `FAIL`), just no longer dies mid-loop.

This is a pre-existing bug, unrelated to the Docker feature, discovered while establishing a test baseline for this plan (see below) — fixed here because it lives in the exact function Task 2 extends, and because it currently makes it impossible to reliably observe more than one `FAIL`/`WARN` in a `--check` report.

- [ ] **Step 1: Reproduce the bug in a throwaway container**

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  ubuntu:22.04 bash -c "cd /install && bash install.sh --check; echo EXITCODE=\$?"
```

Expected (current, buggy behavior): output stops after the very first `[FAIL]` line (currently `Docker -not installed (required)`) — every later check (Compose, RAM, CPU, disk, port, openssl, bundle integrity) and the final "N prerequisite(s) failed" summary never print. `EXITCODE=1`.

Root cause: in bash, `(( fails++ ))` (post-increment) *evaluates to* the value **before** incrementing. The first time `fails` goes from `0`→`1`, the expression's value is `0` (falsy), so `(( fails++ ))` returns a non-zero exit status as a bare statement — and since the whole script runs under `set -euo pipefail`, that non-zero status kills the script immediately. Same bug applies to `(( warns++ ))`.

- [ ] **Step 2: Fix the increments**

In `packaging/compose/install.sh`, inside `render_checks()`:

```bash
      PASS) echo -e "  ${GREEN}[PASS]${NC} $msg" ;;
      FAIL) echo -e "  ${RED}[FAIL]${NC} $msg"; (( fails++ )) ;;
      WARN) echo -e "  ${YELLOW}[WARN]${NC} $msg"; (( warns++ )) ;;
      INFO) echo -e "        $msg" ;;
```

becomes:

```bash
      PASS) echo -e "  ${GREEN}[PASS]${NC} $msg" ;;
      FAIL) echo -e "  ${RED}[FAIL]${NC} $msg"; fails=$((fails + 1)) ;;
      WARN) echo -e "  ${YELLOW}[WARN]${NC} $msg"; warns=$((warns + 1)) ;;
      INFO) echo -e "        $msg" ;;
```

(`fails=$((fails + 1))` is a plain arithmetic assignment — its exit status is always `0`, so it can never trip `errexit`, regardless of the value.)

- [ ] **Step 3: Re-run the same container command and confirm the fix**

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  ubuntu:22.04 bash -c "cd /install && bash install.sh --check; echo EXITCODE=\$?"
```

Expected now: all checks print (`OS`, `Docker`, `Docker Compose`, `RAM`, `CPU`, `Disk`, `Port`, `openssl`, `Bundle integrity`), followed by a line like `N prerequisite(s) failed -resolve before install.`, then `EXITCODE=1`.

- [ ] **Step 4: Syntax check**

```bash
bash -n packaging/compose/install.sh
```

Expected: no output, exit 0.

- [ ] **Step 5: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "fix(installer): render_checks fail/warn counters killed script on first FAIL

Post-increment (( fails++ )) evaluates to the pre-increment value, so
the very first FAIL (0->1) made the bare statement return a falsy exit
status and set -e killed the script mid-report. Found while building a
test baseline for the Docker auto-install feature."
```

---

### Task 2: Detection — `INST` status for missing Docker/Compose

**Files:**
- Modify: `packaging/compose/install.sh:66-69` (global flags)
- Modify: `packaging/compose/install.sh:228-248` (`_check_docker`, `_check_compose`)
- Modify: `packaging/compose/install.sh:345-366` post-Task-1 (`render_checks` — add `INST` case)

**Interfaces:**
- Produces: globals `NEED_DOCKER` (bool string `true`/`false`), `NEED_COMPOSE` (bool string `true`/`false`) — read by Task 4's consent step. `DOCKER_AUTO_INSTALLED` (bool string) declared here, set by Task 4, read by Task 4's audit-log addition.
- Produces: `_check_docker()`/`_check_compose()` now emit `INST:...` (not `FAIL:...`) when the tool is simply missing; still emit `FAIL:...` when Docker is installed but its daemon isn't running (unchanged, intentionally not auto-fixed).

- [ ] **Step 1: Add the new globals**

In `packaging/compose/install.sh`:

```bash
MODE=""
CONFIG_FILE=""
PURGE_IMAGES=false
YES=false
```

becomes:

```bash
MODE=""
CONFIG_FILE=""
PURGE_IMAGES=false
YES=false
NEED_DOCKER=false
NEED_COMPOSE=false
DOCKER_AUTO_INSTALLED=false
```

- [ ] **Step 2: Change `_check_docker`'s missing-binary case to `INST`**

```bash
_check_docker() {
  if ! command -v docker &>/dev/null; then
    echo "FAIL:Docker -not installed (required)"; return
  fi
  if ! docker info &>/dev/null 2>&1; then
    echo "FAIL:Docker -daemon not running (start it before install)"; return
  fi
  local ver
  ver=$(docker --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
  echo "PASS:Docker -${ver}"
}
```

becomes:

```bash
_check_docker() {
  if ! command -v docker &>/dev/null; then
    NEED_DOCKER=true
    echo "INST:Docker -not installed (installer can install it with your consent)"; return
  fi
  if ! docker info &>/dev/null 2>&1; then
    echo "FAIL:Docker -daemon not running (start it before install)"; return
  fi
  local ver
  ver=$(docker --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
  echo "PASS:Docker -${ver}"
}
```

- [ ] **Step 3: Change `_check_compose`'s missing-plugin case to `INST`**

```bash
_check_compose() {
  if docker compose version &>/dev/null 2>&1; then
    local ver
    ver=$(docker compose version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1 || echo "?")
    echo "PASS:Docker Compose -${ver}"
  else
    echo "FAIL:Docker Compose -plugin not found (install docker-compose-plugin)"
  fi
}
```

becomes:

```bash
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

- [ ] **Step 4: Add the `INST` case to `render_checks`**

```bash
      PASS) echo -e "  ${GREEN}[PASS]${NC} $msg" ;;
      FAIL) echo -e "  ${RED}[FAIL]${NC} $msg"; fails=$((fails + 1)) ;;
      WARN) echo -e "  ${YELLOW}[WARN]${NC} $msg"; warns=$((warns + 1)) ;;
      INFO) echo -e "        $msg" ;;
```

becomes:

```bash
      PASS) echo -e "  ${GREEN}[PASS]${NC} $msg" ;;
      FAIL) echo -e "  ${RED}[FAIL]${NC} $msg"; fails=$((fails + 1)) ;;
      WARN) echo -e "  ${YELLOW}[WARN]${NC} $msg"; warns=$((warns + 1)) ;;
      INST) echo -e "  ${CYAN}[INST]${NC} $msg" ;;
      INFO) echo -e "        $msg" ;;
```

`CYAN` is already defined at `install.sh:54` — no new color variable needed. `INST` is intentionally excluded from both the `fails` and `warns` tallies: it's informational, not a problem.

- [ ] **Step 5: Syntax check**

```bash
bash -n packaging/compose/install.sh
```

Expected: no output, exit 0.

- [ ] **Step 6: Live-verify `--check` on a Docker-less host reports `INST`, not `FAIL`, for Docker/Compose**

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  ubuntu:22.04 bash -c "cd /install && bash install.sh --check; echo EXITCODE=\$?"
```

Expected: lines `[INST] Docker -not installed (installer can install it with your consent)` and `[INST] Docker Compose -not installed (installer can install it with your consent)` appear; the final summary counts only the pre-existing, unrelated `openssl` `FAIL` (openssl isn't installed in the base `ubuntu:22.04` image) toward `fails`, e.g. `1 prerequisite(s) failed -resolve before install.`, `EXITCODE=1`. Docker/Compose no longer contribute to that count.

- [ ] **Step 7: Live-verify `--check` on a Rocky Linux host doesn't crash on OS detection**

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  rockylinux:9 bash -c "cd /install && bash install.sh --check; echo EXITCODE=\$?"
```

Expected: `[PASS] OS -Rocky/RHEL 9...` followed by the same `INST` lines for Docker/Compose as the Ubuntu run. Confirms `_check_os`'s Rocky/RHEL branch (`install.sh:221-223`) and the new `INST` handling both work on the dnf-family OS this plan's `_install_docker` (Task 3) will also need to support.

- [ ] **Step 8: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "feat(installer): detect missing Docker/Compose as installable, not fatal

_check_docker/_check_compose now report INST (installable, non-fatal)
instead of FAIL when the tool is simply absent -- a running-but-stopped
daemon still hard-fails, unchanged. Sets NEED_DOCKER/NEED_COMPOSE for
the consent-gated auto-install step landing in a later commit."
```

---

### Task 3: `_install_docker()` — OS-aware Docker CE installer

**Files:**
- Modify: `packaging/compose/install.sh` — new function inserted immediately after `_check_compose()` (ends at line 248 post-Task-2), before `_check_ram()` (line 250)

**Interfaces:**
- Consumes: nothing from earlier tasks (reads `/etc/os-release` directly).
- Produces: `_install_docker()` — no arguments, no return value; installs and enables Docker CE, or calls `err`+`exit 1` on an unsupported OS. Called by Task 4's consent step.

- [ ] **Step 1: Add the function**

Insert immediately after `_check_compose()`'s closing `}` (post-Task-2, still at `install.sh:248`), before `_check_ram()`:

```bash
# ── Docker CE installation ─────────────────────────────────────────────────────
# Installs from Docker's own officially documented apt/dnf repositories.
# Called only after explicit operator consent (see mode_install).
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

- [ ] **Step 2: Syntax check**

```bash
bash -n packaging/compose/install.sh
```

Expected: no output, exit 0.

- [ ] **Step 3: Isolated live test — extract just this function and exercise all three branches**

`_install_docker` can't be exercised cleanly through the full script (argument parsing and the root check run unconditionally at the top of `install.sh`, before any function is reachable in isolation). Extract just the function body into a throwaway harness so each OS branch can be verified directly, without needing a full `setup.conf` or a real systemd host:

```bash
sed -n '/^_install_docker() {/,/^}/p' packaging/compose/install.sh > /tmp/harness.sh
cat /tmp/harness.sh   # sanity check it captured the whole function
```

Expected: the full `_install_docker` function body, starting with `_install_docker() {` and ending with the matching `}`.

Ubuntu branch — real apt-get against the real Docker repo, with a `systemctl` stub (a bare container has no systemd as PID 1, so the final `systemctl enable --now docker` line is stubbed; everything before it — repo setup, GPG import, package install — runs for real):

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  ubuntu:22.04 bash -c '
    apt-get update -qq && apt-get install -y -qq gnupg curl ca-certificates lsb-release >/dev/null
    mkdir -p /usr/local/sbin
    printf "#!/bin/sh\necho \"[stub] systemctl \$*\"\nexit 0\n" > /usr/local/sbin/systemctl
    chmod +x /usr/local/sbin/systemctl
    export PATH="/usr/local/sbin:$PATH"
    source /install/../compose/harness.sh 2>/dev/null || true
    source /tmp/harness.sh 2>/dev/null
    source <(sed -n "/^_install_docker() {/,/^}/p" /install/install.sh)
    _install_docker
    echo "EXIT=$?"
    docker --version
  '
```

Expected: apt output showing Docker's repo being added and `docker-ce`/`docker-ce-cli`/`containerd.io`/`docker-buildx-plugin`/`docker-compose-plugin` installing successfully, a `[stub] systemctl enable --now docker` line, `EXIT=0`, and a real `Docker version 2X.Y.Z, build ...` line at the end (proving the package genuinely installed, not just that the script didn't crash).

Rocky branch:

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  rockylinux:9 bash -c '
    mkdir -p /usr/local/sbin
    printf "#!/bin/sh\necho \"[stub] systemctl \$*\"\nexit 0\n" > /usr/local/sbin/systemctl
    chmod +x /usr/local/sbin/systemctl
    export PATH="/usr/local/sbin:$PATH"
    source <(sed -n "/^_install_docker() {/,/^}/p" /install/install.sh)
    _install_docker
    echo "EXIT=$?"
    docker --version
  '
```

Expected: same shape — dnf adds Docker's repo and installs the same package set, `[stub] systemctl enable --now docker`, `EXIT=0`, real `docker --version` output.

Unsupported-OS branch (alpine — not ubuntu/debian/rocky/rhel/centos):

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  alpine bash -c '
    apk add --no-cache bash >/dev/null
    err() { echo "[FAIL] $*" >&2; }
    info() { echo "      $*"; }
    source <(sed -n "/^_install_docker() {/,/^}/p" /install/install.sh)
    _install_docker
    echo "EXIT=$?"
  ' 2>&1
```

Expected: `[FAIL] Automatic Docker install is not supported on this OS (alpine).`, `      Install Docker CE manually: https://docs.docker.com/engine/install/`, and the container exits before printing `EXIT=$?` (the function's own `exit 1` terminates the shell — this is correct: it proves the unsupported-OS path refuses to guess a package manager rather than silently doing nothing).

- [ ] **Step 4: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "feat(installer): add _install_docker() -- OS-aware Docker CE install

apt path for Ubuntu/Debian, dnf path for Rocky/RHEL/CentOS, both using
Docker's own officially documented repositories. Unsupported OS gets a
clear manual-install error rather than a guessed package manager. Not
yet wired into any mode -- that lands in the next commit."
```

---

### Task 4: Consent prompt, `mode_install` wiring, audit log, usage docs

**Files:**
- Modify: `packaging/compose/install.sh:414-513` post-Task-3 (`mode_install` — new step, renumbered steps)
- Modify: `packaging/compose/install.sh:842-855` post-Task-3 (`_write_install_log`)
- Modify: `packaging/compose/install.sh:1-10` (top-of-file usage comment)
- Modify: `packaging/compose/install.sh:83-92` (`Usage:` error strings)

**Interfaces:**
- Consumes: `NEED_DOCKER`/`NEED_COMPOSE` (Task 2), `_install_docker()` (Task 3), `DOCKER_AUTO_INSTALLED` (declared Task 2, set here), existing `$YES` flag (pre-existing).

- [ ] **Step 1: Insert the consent-gated Docker step into `mode_install`, renumber the rest**

```bash
  step "1/9  Prerequisite checks"
```

becomes:

```bash
  step "1/10  Prerequisite checks"
```

Immediately after the existing prereq block (`render_checks "${results[@]}" || exit 1`) and before `step "2/9  Creating data directories"`:

```bash
  render_checks "${results[@]}" || exit 1

  step "2/9  Creating data directories"
```

becomes:

```bash
  render_checks "${results[@]}" || exit 1

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

  step "3/10  Creating data directories"
```

Then renumber every remaining step label in `mode_install`:

```bash
  step "3/9  Loading Docker images (air-gap safe -no pull)"
```
→
```bash
  step "4/10  Loading Docker images (air-gap safe -no pull)"
```

```bash
  step "4/9  Staging bundle files"
```
→
```bash
  step "5/10  Staging bundle files"
```

```bash
  step "5/9  Writing .env (root-readable only)"
```
→
```bash
  step "6/10  Writing .env (root-readable only)"
```

```bash
  step "6/9  Installing docker-compose.yml"
```
→
```bash
  step "7/10  Installing docker-compose.yml"
```

```bash
  step "7/9  Installing systemd service (auto-start on boot)"
```
→
```bash
  step "8/10  Installing systemd service (auto-start on boot)"
```

```bash
  step "8/9  Starting stack"
```
→
```bash
  step "9/10  Starting stack"
```

```bash
  step "9/9  Creating admin user"
```
→
```bash
  step "10/10  Creating admin user"
```

- [ ] **Step 2: Record the Docker install decision in the audit log**

```bash
_write_install_log() {
  local log_file="$1"
  {
    echo "Audspect BAS -Install Log"
    echo "Timestamp : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Version   : ${BAS_VERSION}"
    echo "Host      : $(hostname -f 2>/dev/null || hostname)"
    echo "Data dir  : ${DATA_DIR}"
    echo "Port      : ${BAS_PORT}"
    echo "TLS       : ${BAS_TLS}"
    echo "Admin     : ${ADMIN_EMAIL}"
  } >> "$log_file"
  chmod 640 "$log_file"
}
```

becomes:

```bash
_write_install_log() {
  local log_file="$1"
  local docker_note="pre-existing"
  $DOCKER_AUTO_INSTALLED && docker_note="auto-installed by installer"
  {
    echo "Audspect BAS -Install Log"
    echo "Timestamp : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "Version   : ${BAS_VERSION}"
    echo "Host      : $(hostname -f 2>/dev/null || hostname)"
    echo "Data dir  : ${DATA_DIR}"
    echo "Port      : ${BAS_PORT}"
    echo "TLS       : ${BAS_TLS}"
    echo "Admin     : ${ADMIN_EMAIL}"
    echo "Docker CE : ${docker_note}"
  } >> "$log_file"
  chmod 640 "$log_file"
}
```

- [ ] **Step 3: Document `--yes` covering Docker consent in the usage banner**

```bash
#!/usr/bin/env bash
# Audspect BAS Platform -BFSI-Grade Installer
#
# Usage:
#   sudo bash install.sh --check                          # prereq report (attach to CAB)
#   sudo bash install.sh --install  --config setup.conf  # first-time install
#   sudo bash install.sh --upgrade  --config setup.conf  # in-place upgrade
#   sudo bash install.sh --rollback                      # restore previous version
#   sudo bash install.sh --status                        # current state
#   sudo bash install.sh --uninstall [--purge-images] [--yes]
#
# All secrets not supplied in setup.conf are auto-generated and written to
# ${DATA_DIR}/.env which is readable only by root. setup.conf is the
# change-management artefact approved before the maintenance window.
#
# Supported OS: Ubuntu 20.04/22.04/24.04, Rocky Linux / RHEL 9
set -euo pipefail
```

becomes:

```bash
#!/usr/bin/env bash
# Audspect BAS Platform -BFSI-Grade Installer
#
# Usage:
#   sudo bash install.sh --check                          # prereq report (attach to CAB)
#   sudo bash install.sh --install  --config setup.conf [--yes]  # first-time install
#   sudo bash install.sh --upgrade  --config setup.conf  # in-place upgrade
#   sudo bash install.sh --rollback                      # restore previous version
#   sudo bash install.sh --status                        # current state
#   sudo bash install.sh --uninstall [--purge-images] [--yes]
#
# If Docker/Docker Compose are missing, --install asks for explicit
# confirmation before installing Docker CE from Docker's official
# repository. --yes also grants that consent, for unattended runs.
#
# All secrets not supplied in setup.conf are auto-generated and written to
# ${DATA_DIR}/.env which is readable only by root. setup.conf is the
# change-management artefact approved before the maintenance window.
#
# Supported OS: Ubuntu 20.04/22.04/24.04, Rocky Linux / RHEL 9
set -euo pipefail
```

- [ ] **Step 4: Syntax check**

```bash
bash -n packaging/compose/install.sh
```

Expected: no output, exit 0.

- [ ] **Step 5: Live-verify the "no" path aborts cleanly with zero side effects**

```bash
cat > /tmp/test-setup.conf <<'EOF'
DATA_DIR=/opt/audspect-test
BAS_PORT=9443
BAS_TLS=false
DB_PASSWORD=testpass123
ADMIN_EMAIL=admin@test.local
ADMIN_PASSWORD=TestPass123!
LIC_PATH=
EOF
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  -v "C:\Users\ADMINI~1\AppData\Local\Temp\test-setup.conf:/tmp/test-setup.conf:ro" \
  ubuntu:22.04 bash -c "apt-get update -qq && apt-get install -y -qq openssl iproute2 >/dev/null; cd /install && echo no | bash install.sh --install --config /tmp/test-setup.conf; echo EXITCODE=\$?"
```

(Adjust the second `-v` source path to wherever `/tmp/test-setup.conf` actually lands on the Windows host — Git Bash's `/tmp` maps under the user's local temp directory.)

Expected: prereqs pass through to the new `2/10  Docker Engine` step, the prompt `Install Docker CE now from the official Docker repository? [yes/N]` appears, `no` (from the piped `echo no`) doesn't match `"yes"`, and the script exits with `[FAIL] Docker is required to continue. Install it manually (or re-run with --yes) and re-run --install.` and `EXITCODE=1` — **before** `3/10 Creating data directories` ever runs (no `/opt/audspect-test` side effects).

- [ ] **Step 6: Live-verify the `--yes` path reaches and completes the Docker install step**

```bash
MSYS_NO_PATHCONV=1 docker run --rm --tmpfs /run --tmpfs /run/lock \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  -v "C:\Users\ADMINI~1\AppData\Local\Temp\test-setup.conf:/tmp/test-setup.conf:ro" \
  ubuntu:22.04 bash -c "
    apt-get update -qq && apt-get install -y -qq openssl iproute2 >/dev/null
    mkdir -p /usr/local/sbin
    printf '#!/bin/sh\necho \"[stub] systemctl \$*\"\nexit 0\n' > /usr/local/sbin/systemctl
    chmod +x /usr/local/sbin/systemctl
    export PATH=/usr/local/sbin:\$PATH
    cd /install && timeout 90 bash install.sh --install --config /tmp/test-setup.conf --yes
    echo EXITCODE=\$?
  "
```

Expected: no prompt (unattended), prereqs pass, `2/10  Docker Engine` step runs `_install_docker` for real (apt output installing `docker-ce` etc.), then `Docker CE installed: Docker version ...` log line, then the run proceeds into `3/10  Creating data directories` and beyond using the **pre-existing** (unmodified by this plan) rest of `mode_install`. The `timeout 90` bound is intentional — later steps (starting the actual compose stack) need a real Docker daemon and systemd, which a bare container can't provide; this test only needs to prove the new step (`2/10`) itself completes correctly, not that the entire pre-existing installer finishes end-to-end in a container. It's fine if the run is still mid-way through a later, pre-existing step when the timeout hits.

- [ ] **Step 7: Live-verify the skip path when Docker is already present**

```bash
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose:/install:ro" \
  -v "C:\Users\ADMINI~1\AppData\Local\Temp\test-setup.conf:/tmp/test-setup.conf:ro" \
  ubuntu:22.04 bash -c "
    apt-get update -qq && apt-get install -y -qq openssl iproute2 >/dev/null
    mkdir -p /usr/local/sbin
    cat > /usr/local/sbin/docker <<'STUB'
#!/bin/sh
case \"\$1 \$2\" in
  '--version') echo 'Docker version 27.0.0, build stub';;
  'info') exit 0;;
  'compose version') echo 'Docker Compose version v2.29.0';;
  *) exit 0;;
esac
STUB
    chmod +x /usr/local/sbin/docker
    export PATH=/usr/local/sbin:\$PATH
    cd /install && timeout 30 bash install.sh --install --config /tmp/test-setup.conf --yes
    echo EXITCODE=\$?
  "
```

Expected: `1/10  Prerequisite checks` shows `[PASS] Docker -27.0.0` and `[PASS] Docker Compose -2.29.0`, `2/10  Docker Engine` prints `Docker already present -skipping` (no apt-get invocation, no consent prompt), confirming `NEED_DOCKER`/`NEED_COMPOSE` correctly stayed `false`.

- [ ] **Step 8: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "feat(installer): wire Docker consent prompt into mode_install

New step 2/10 asks for explicit permission before installing Docker CE
when missing, reusing --yes for unattended CAB-scheduled runs. Records
the decision in install.log for audit review. mode_check is untouched
-- it only reports INST status, never installs."
```

---

### Task 5: Staging-host verification runbook

**Files:**
- Create: `docs/superpowers/plans/2026-07-20-docker-auto-install-staging-checklist.md`

The container-based tests in Tasks 2-4 can't prove the parts that need a real init system (`systemctl enable --now docker` genuinely starting the daemon, then the full `docker compose up` stack actually becoming healthy) — a bare `docker run` container has no PID-1 systemd. That requires a real VM or a CAB-provisioned staging host. This task hands off exactly what to run there.

- [ ] **Step 1: Write the runbook**

```markdown
# Docker Auto-Install — Staging Host Verification

Run on a real VM or CAB-provisioned staging host (not a container) with a
genuine systemd PID 1, for both supported OS families, before this ships to
a production client install.

## Prerequisites
- A fresh Ubuntu 22.04 VM with no Docker installed.
- A fresh Rocky Linux 9 VM with no Docker installed.
- `packaging/compose/install.sh`, `docker-compose.yml`, and a valid
  `setup.conf` (real `LIC_PATH`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, etc. --
  see `setup.conf.template`) staged on each host.

## Ubuntu 22.04
1. `sudo bash install.sh --check --config setup.conf` -- confirm `[INST]`
   lines for Docker/Compose, no `[FAIL]` for either, full report prints
   through to the final summary line (validates the Task 1 bugfix on a
   real host).
2. `sudo bash install.sh --install --config setup.conf`, answer `no` at
   the Docker prompt -- confirm clean abort, `docker` still not installed,
   `/opt/audspect` (or configured `DATA_DIR`) not created.
3. `sudo bash install.sh --install --config setup.conf`, answer `yes` --
   confirm: Docker CE installs, `systemctl status docker` shows
   `active (running)`, the install proceeds through all 10 steps, the
   dashboard becomes reachable at the configured port, and
   `${DATA_DIR}/install.log` contains `Docker CE : auto-installed by
   installer`.
4. `sudo bash install.sh --uninstall --yes` to reset the host, confirm
   Docker itself is left installed (only the BAS stack is removed --
   uninstall was never in scope for touching Docker).
5. Re-run `sudo bash install.sh --install --config setup.conf --yes`
   fully unattended -- confirm no prompt appears and it completes the
   same as step 3.

## Rocky Linux 9
Repeat steps 1-3 and 5 above. Confirm the dnf-based `_install_docker`
branch installs cleanly and `systemctl status docker` is `active
(running)`.

## Already-has-Docker host
On a host that already has Docker + Compose installed (either from a
prior run above, or pre-existing), run
`sudo bash install.sh --check --config setup.conf` and confirm both
report `[PASS]`, then `--install` and confirm step `2/10` logs
`Docker already present -skipping` with no network calls and
`install.log` shows `Docker CE : pre-existing`.

## Sign-off
Record pass/fail for each scenario above, plus OS + Docker + Compose
versions observed, before this is approved for a production client
deployment.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/2026-07-20-docker-auto-install-staging-checklist.md
git commit -m "docs(installer): staging-host verification runbook for Docker auto-install

Covers the systemd-dependent scenarios (real daemon start, full stack
health) that a bare container can't prove -- hands off to a real VM
or CAB-provisioned staging host before production rollout."
```

- [ ] **Step 3: Push everything**

```bash
git push
```
