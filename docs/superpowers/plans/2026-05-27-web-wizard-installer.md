# Web Wizard Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace broken whiptail password prompts with a browser-based setup wizard and config-file pre-seed path, both fully air-gapped.

**Architecture:** `setup.sh` detects `setup.conf` presence and routes to either direct install (config mode) or a Python3 stdlib HTTP server on :9001 (wizard mode). The wizard browser form POSTs config, triggers `bash setup.sh --config ... --no-wizard` as a subprocess, and streams its stdout back via SSE.

**Tech Stack:** Bash, Python3 stdlib only (http.server, subprocess, threading, json, socket, socketserver), vanilla HTML/CSS/JS inline (no CDN).

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `packaging/compose/setup.conf` | Create | Blank config template shipped in ZIP |
| `packaging/compose/setup.sh` | Rewrite | All installer logic with wizard/config/no-wizard modes |
| `packaging/windows-build.ps1` | Modify | Copy setup.conf into delivery dir |

---

### Task 1: Create setup.conf template and update windows-build.ps1

**Files:**
- Create: `packaging/compose/setup.conf`
- Modify: `packaging/windows-build.ps1` (after the uninstall.sh copy block)

- [ ] **Step 1: Create setup.conf**

Create `packaging/compose/setup.conf` with this exact content:

```bash
# BAS Platform Setup Configuration
# Fill all values then run: sudo bash setup.sh --offline
# Leave blank to launch the browser-based setup wizard automatically.

INSTALL_DIR=/opt/bas-platform
DASHBOARD_PORT=9000
LIC_PATH=
DB_PASSWORD=
ADMIN_PASSWORD=
```

- [ ] **Step 2: Add copy line in windows-build.ps1**

In `packaging/windows-build.ps1`, find the block that copies installer files and add `setup.conf` after the uninstall.sh copy:

```powershell
if (Test-Path "$ComposeDir\uninstall.sh") {
    Copy-Item "$ComposeDir\uninstall.sh" "$OutDir\uninstall.sh"
}
Copy-Item "$ComposeDir\setup.conf" "$OutDir\setup.conf"
```

- [ ] **Step 3: Commit**

```bash
git add packaging/compose/setup.conf packaging/windows-build.ps1
git commit -m "feat: add setup.conf template and include in delivery zip"
git push
```

---

### Task 2: Rewrite setup.sh — skeleton, globals, and load_config()

**Files:**
- Modify: `packaging/compose/setup.sh`

This task replaces the top section (constants through `_wt`) with new globals and adds `load_config()`. Keep everything from `require_root()` downward untouched for now.

- [ ] **Step 1: Add new globals after the existing constants block**

Find the block:
```bash
# Set by --offline flag; skips docker pull (images already loaded)
OFFLINE=false

# Set during prereq checks — installer auto-installs these if missing
NEED_DOCKER=false
NEED_COMPOSE=false
```

Replace with:
```bash
# Set by --offline flag; skips docker pull (images already loaded)
OFFLINE=false

# Set during prereq checks — installer auto-installs these if missing
NEED_DOCKER=false
NEED_COMPOSE=false

# Set by --config <file> flag; skips wizard, reads values from file
CONFIG_FILE=""

# Set internally when Python wizard spawns setup.sh as subprocess
# Disables all whiptail; outputs plain log lines to stdout
NO_WIZARD=false
```

- [ ] **Step 2: Add load_config() function**

Add this function after the `err()` log helper and before `require_root()`:

```bash
# ── Config file loader ────────────────────────────────────────────────────────
# Reads key=value pairs from setup.conf without sourcing (no code exec).
# Sets: INSTALL_DIR, DASHBOARD_PORT, DB_PASSWORD, ADMIN_PASSWORD, LIC_PATH
# Generates: JWT_SECRET, AGENT_SECRET, CALDERA_API_KEY, CALDERA_API_KEY_BLUE
load_config() {
  local cfg="$1"
  [[ -f "$cfg" ]] || { err "Config file not found: $cfg"; exit 1; }

  local key val
  while IFS='=' read -r key val; do
    # skip comments and blank lines
    [[ "$key" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${key// }" ]] && continue
    key="${key// /}"                        # strip spaces from key
    val="${val#"${val%%[![:space:]]*}"}"    # ltrim
    val="${val%"${val##*[![:space:]]}"}"    # rtrim
    val="${val#\'}" ; val="${val%\'}"       # strip surrounding single quotes
    val="${val#\"}" ; val="${val%\"}"       # strip surrounding double quotes
    case "$key" in
      INSTALL_DIR)    INSTALL_DIR="$val"    ;;
      DASHBOARD_PORT) DASHBOARD_PORT="$val" ;;
      DB_PASSWORD)    DB_PASSWORD="$val"    ;;
      ADMIN_PASSWORD) ADMIN_PASSWORD="$val" ;;
      LIC_PATH)       LIC_PATH="$val"       ;;
    esac
  done < "$cfg"

  # Defaults
  [[ -z "${INSTALL_DIR:-}"    ]] && INSTALL_DIR="$DEFAULT_INSTALL_DIR"
  [[ -z "${DASHBOARD_PORT:-}" ]] && DASHBOARD_PORT="$DEFAULT_PORT"

  # Required field validation
  local missing=false
  [[ -z "${LIC_PATH:-}"       ]] && { err "setup.conf: LIC_PATH is required.";       missing=true; }
  [[ -z "${DB_PASSWORD:-}"    ]] && { err "setup.conf: DB_PASSWORD is required.";    missing=true; }
  [[ -z "${ADMIN_PASSWORD:-}" ]] && { err "setup.conf: ADMIN_PASSWORD is required."; missing=true; }
  $missing && exit 1

  # Password length validation
  [[ ${#DB_PASSWORD}    -lt 8  ]] && { err "DB_PASSWORD must be at least 8 characters.";    exit 1; }
  [[ ${#ADMIN_PASSWORD} -lt 10 ]] && { err "ADMIN_PASSWORD must be at least 10 characters."; exit 1; }

  # Generate runtime secrets
  JWT_SECRET=$(openssl rand -hex 32)
  AGENT_SECRET=$(openssl rand -hex 24)
  CALDERA_API_KEY=$(openssl rand -hex 20)
  CALDERA_API_KEY_BLUE=$(openssl rand -hex 20)

  log "Config loaded: install=${INSTALL_DIR} port=${DASHBOARD_PORT}"
}
```

- [ ] **Step 3: Commit**

```bash
git add packaging/compose/setup.sh
git commit -m "feat: add CONFIG_FILE/NO_WIZARD globals and load_config() to setup.sh"
git push
```

---

### Task 3: Add _step() helper and refactor do_install()

**Files:**
- Modify: `packaging/compose/setup.sh`

- [ ] **Step 1: Add _step() helper before do_install()**

Add immediately before the `do_install()` function:

```bash
# Progress step helper — outputs whiptail gauge format OR plain log line
# Usage: _step PCT "Human-readable message"
_step() {
  local pct="$1" msg="$2"
  if $NO_WIZARD; then
    log "$msg"
  else
    echo "$pct"
    echo "# $msg"
  fi
}
```

- [ ] **Step 2: Replace do_install() with dual-mode version**

Replace the entire existing `do_install()` function with:

```bash
do_install() {
  if $NO_WIZARD; then
    _do_install_steps
  else
    local progress_log
    progress_log=$(mktemp)
    (
      _do_install_steps 2>>"$progress_log"
    ) | whiptail --title "$TITLE — Installing" \
                 --gauge "Installing BAS Platform, please wait..." 10 70 0
    rm -f "$progress_log"
  fi
}

_do_install_steps() {
  # Step 1 — Install Docker if missing
  _step 5 "Installing Docker CE (may take 1-2 minutes)..."
  if $NEED_DOCKER; then
    install_docker || { err "Docker install failed."; exit 1; }
  fi

  # Step 2 — Create directory structure
  _step 15 "Creating install directory..."
  mkdir -p "${INSTALL_DIR}/scenarios" "${INSTALL_DIR}/wwwroot" "${INSTALL_DIR}/data"

  # Step 3 — Copy license file
  _step 20 "Installing license..."
  cp "${LIC_PATH}" "${INSTALL_DIR}/bas.lic"
  chmod 640 "${INSTALL_DIR}/bas.lic"
  chown root:root "${INSTALL_DIR}/bas.lic"

  # Step 4 — Copy application files
  _step 25 "Copying application files..."
  if [[ -d "${SCRIPT_DIR}/scenarios" ]]; then
    cp -r "${SCRIPT_DIR}/scenarios/." "${INSTALL_DIR}/scenarios/"
  fi
  if [[ -d "${SCRIPT_DIR}/wwwroot" ]]; then
    cp -r "${SCRIPT_DIR}/wwwroot/." "${INSTALL_DIR}/wwwroot/"
  fi

  # Step 5 — Copy compose files
  _step 30 "Copying configuration templates..."
  cp "${SCRIPT_DIR}/docker-compose.yml"      "${INSTALL_DIR}/"
  cp "${SCRIPT_DIR}/docker-compose.prod.yml" "${INSTALL_DIR}/"

  # Step 6 — Write .env
  _step 38 "Writing .env configuration..."
  cat > "${INSTALL_DIR}/.env" <<EOF
# BAS Platform — generated by setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
BAS_VERSION=${BAS_VERSION}
REGISTRY=
POSTGRES_DB=bas_platform
POSTGRES_USER=bas_user
POSTGRES_PASSWORD=${DB_PASSWORD}
JWT_SECRET=${JWT_SECRET}
AGENT_SECRET=${AGENT_SECRET}
DASHBOARD_PORT=${DASHBOARD_PORT}
BAS_LICENSE_PATH=/etc/bas/bas.lic
CALDERA_API_KEY=${CALDERA_API_KEY}
CALDERA_API_KEY_BLUE=${CALDERA_API_KEY_BLUE}
EOF
  chmod 640 "${INSTALL_DIR}/.env"
  chown root:root "${INSTALL_DIR}/.env"

  # Step 7 — Write admin seed
  _step 45 "Writing admin seed..."
  cat > "${INSTALL_DIR}/.env.admin-seed" <<EOF
# One-time admin seed — deleted after first successful boot
BAS_ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF
  chmod 600 "${INSTALL_DIR}/.env.admin-seed"

  # Step 8 — Load or pull Docker images
  _step 50 "Loading Docker images..."
  if [[ "$OFFLINE" == "true" ]]; then
    for img in "${SCRIPT_DIR}"/images/*.tar.gz "${SCRIPT_DIR}"/images/*.tar; do
      [[ -f "$img" ]] || continue
      _step 55 "Loading $(basename "$img")..."
      docker load < "$img" || true
    done
  else
    cd "${INSTALL_DIR}"
    docker compose -f docker-compose.yml pull --quiet || true
  fi

  # Step 9 — Install systemd service
  _step 80 "Installing systemd service..."
  sed "s|/opt/bas-platform|${INSTALL_DIR}|g" \
    "${SCRIPT_DIR}/systemd/bas-compose.service" \
    > /etc/systemd/system/bas-compose.service
  systemctl daemon-reload
  systemctl enable bas-compose.service

  # Step 10 — Start services
  _step 87 "Starting BAS Platform..."
  cd "${INSTALL_DIR}"
  systemctl start bas-compose.service
  sleep 3

  # Step 11 — Health check
  _step 93 "Waiting for orchestrator to become healthy..."
  local retries=0
  until curl -sf "http://localhost:${DASHBOARD_PORT}/health" &>/dev/null || [[ $retries -ge 24 ]]; do
    sleep 5
    ((retries++))
  done

  # Step 12 — Clean up admin seed
  _step 98 "Finalising..."
  rm -f "${INSTALL_DIR}/.env.admin-seed"

  _step 100 "Installation complete."
}
```

- [ ] **Step 3: Commit**

```bash
git add packaging/compose/setup.sh
git commit -m "feat: add _step() helper and refactor do_install() for dual-mode output"
git push
```

---

### Task 4: Add show_credentials() function

**Files:**
- Modify: `packaging/compose/setup.sh`

- [ ] **Step 1: Add show_credentials() before page_finish()**

```bash
# Plain-text credentials summary — used after no-wizard installs
show_credentials() {
  local detected_ip
  detected_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")
  echo ""
  echo "============================================================"
  echo "  BAS Platform v${BAS_VERSION} installed successfully!"
  echo "============================================================"
  echo ""
  echo "  Dashboard URL : http://${detected_ip}:${DASHBOARD_PORT}"
  echo "  Caldera UI    : http://${detected_ip}:8888"
  echo "  Login         : admin / (password you set)"
  echo "  Install path  : ${INSTALL_DIR}"
  echo ""
  echo "  Agent downloads:"
  echo "    Linux amd64 : http://${detected_ip}:${DASHBOARD_PORT}/api/agent/download/linux-amd64"
  echo "    Linux arm64 : http://${detected_ip}:${DASHBOARD_PORT}/api/agent/download/linux-arm64"
  echo "    Windows     : http://${detected_ip}:${DASHBOARD_PORT}/api/agent/download/windows-amd64"
  echo ""
  echo "  Useful commands:"
  echo "    Logs   : docker compose -C ${INSTALL_DIR} logs -f"
  echo "    Status : systemctl status bas-compose"
  echo "    Stop   : systemctl stop bas-compose"
  echo "============================================================"
}
```

- [ ] **Step 2: Commit**

```bash
git add packaging/compose/setup.sh
git commit -m "feat: add show_credentials() plain-text summary for no-wizard mode"
git push
```

---

### Task 5: Add start_web_wizard() with embedded Python server

**Files:**
- Modify: `packaging/compose/setup.sh`

This is the largest task. The Python server is written as a single-quoted heredoc inside `start_web_wizard()` so bash does not expand any variables.

- [ ] **Step 1: Add start_web_wizard() function**

Add the complete function after `show_credentials()` and before `page_finish()`:

```bash
# ── Web-based setup wizard ────────────────────────────────────────────────────
# Writes a Python3 stdlib HTTP server to /tmp, starts it on :9001.
# The browser form POSTs config values; the server writes setup.conf and
# spawns this same setup.sh with --config + --no-wizard.
# All output from the install subprocess is streamed back to the browser via SSE.
# Python exits automatically ~3 s after the subprocess completes.
start_web_wizard() {
  command -v python3 &>/dev/null || { err "python3 is required for the setup wizard."; exit 1; }

  local server_ip
  server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "localhost")

  local pyfile
  pyfile=$(mktemp /tmp/bas-wizard-XXXXXX.py)
  chmod 600 "$pyfile"

  # Write the Python server — single-quoted heredoc prevents bash expansion
  cat > "$pyfile" << 'PYEOF'
#!/usr/bin/env python3
"""BAS Platform setup wizard — Python3 stdlib only, fully offline."""
import http.server, socketserver, subprocess, threading, json, os, sys, time, socket

SCRIPT_DIR = sys.argv[1]
SETUP_SH   = sys.argv[2]
PORT       = 9001

_log     = []      # captured lines from install subprocess
_done    = False   # True once subprocess exits
_rc      = 0       # subprocess return code
_lock    = threading.Lock()
_started = False   # guard against double-submit

def _local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip

PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BAS Platform Setup</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b1420;color:#c9d1d9;font-family:ui-monospace,SFMono-Regular,"SF Mono",Consolas,"Liberation Mono",Menlo,monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:2rem 1rem}
.card{background:#152338;border:1px solid #22324a;border-radius:8px;width:100%;max-width:580px;padding:2rem}
.header{margin-bottom:1.5rem}
.header h1{color:#e6edf3;font-size:1.1rem;font-weight:600;margin-bottom:.3rem}
.header p{color:#9aa9bc;font-size:.78rem}
.section-title{color:#9aa9bc;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;margin:1.25rem 0 .5rem}
.row{display:grid;grid-template-columns:1fr 1fr;gap:.75rem}
label{display:block;color:#9aa9bc;font-size:.75rem;margin-bottom:.3rem}
input{width:100%;background:#0d1b2e;border:1px solid #22324a;border-radius:4px;color:#e6edf3;padding:.45rem .65rem;font-size:.82rem;font-family:inherit;outline:none;transition:border-color .15s}
input:focus{border-color:#2f81f7;background:#0f1f35}
input::placeholder{color:#3d4f63}
input:disabled{opacity:.5}
.field{margin-bottom:.75rem}
.btn{display:block;width:100%;margin-top:1.5rem;padding:.65rem;background:#2f81f7;border:none;border-radius:6px;color:#fff;font-family:inherit;font-size:.85rem;font-weight:600;cursor:pointer;transition:background .15s}
.btn:hover:not(:disabled){background:#388bfd}
.btn:disabled{background:#1b2a41;color:#4d5f72;cursor:not-allowed}
.log-wrap{display:none;margin-top:1.25rem;border:1px solid #22324a;border-radius:4px;overflow:hidden}
.log-wrap.show{display:block}
.log-head{background:#0d1b2e;padding:.4rem .7rem;font-size:.7rem;color:#9aa9bc;border-bottom:1px solid #22324a}
.log-body{background:#080f1a;padding:.6rem .7rem;height:240px;overflow-y:auto;font-size:.72rem;line-height:1.6}
.ll{white-space:pre-wrap;word-break:break-all}
.ll.ok{color:#3fb950}.ll.warn{color:#d29922}.ll.bad{color:#f85149}
.banner{display:none;margin-top:1rem;border-radius:6px;padding:.9rem 1rem;font-size:.8rem}
.banner.show{display:block}
.banner.success{background:#0f2718;border:1px solid #238636;color:#3fb950}
.banner.success h2{font-size:.9rem;margin-bottom:.4rem}
.banner.success a{color:#2f81f7;text-decoration:none}
.banner.success p{color:#9aa9bc;margin-top:.3rem;font-size:.75rem}
.banner.fail{background:#200e0e;border:1px solid #da3633;color:#f85149}
.sep{border:none;border-top:1px solid #1b2a41;margin:1.25rem 0}
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <h1>BAS Platform &mdash; Setup Wizard</h1>
    <p>All configuration stays on this server. No internet required.</p>
  </div>
  <form id="frm">
    <p class="section-title">License</p>
    <div class="field">
      <label>License file path</label>
      <input name="LIC_PATH" placeholder="/root/hdfc-prod-001.lic" required>
    </div>
    <hr class="sep">
    <p class="section-title">Installation</p>
    <div class="row">
      <div class="field">
        <label>Install directory</label>
        <input name="INSTALL_DIR" value="/opt/bas-platform" required>
      </div>
      <div class="field">
        <label>Dashboard port</label>
        <input name="DASHBOARD_PORT" value="9000" required>
      </div>
    </div>
    <hr class="sep">
    <p class="section-title">Database</p>
    <div class="row">
      <div class="field">
        <label>Password <span style="color:#4d5f72">(min 8)</span></label>
        <input type="password" id="dbp" name="DB_PASSWORD" required>
      </div>
      <div class="field">
        <label>Confirm password</label>
        <input type="password" id="dbp2" required>
      </div>
    </div>
    <hr class="sep">
    <p class="section-title">Admin Account</p>
    <div class="row">
      <div class="field">
        <label>Password <span style="color:#4d5f72">(min 10)</span></label>
        <input type="password" id="adp" name="ADMIN_PASSWORD" required>
      </div>
      <div class="field">
        <label>Confirm password</label>
        <input type="password" id="adp2" required>
      </div>
    </div>
    <button type="submit" class="btn" id="btn">Install BAS Platform</button>
  </form>
  <div class="log-wrap" id="logwrap">
    <div class="log-head">Installation log</div>
    <div class="log-body" id="log"></div>
  </div>
  <div class="banner" id="ok"></div>
  <div class="banner fail" id="fail"></div>
</div>
<script>
const frm=document.getElementById("frm"),btn=document.getElementById("btn"),
      logEl=document.getElementById("log"),logWrap=document.getElementById("logwrap"),
      okBanner=document.getElementById("ok"),failBanner=document.getElementById("fail");

function addLine(txt){
  const d=document.createElement("div");
  const cls=txt.startsWith("[+]")?"ok":txt.startsWith("[!")?"warn":
            (txt.includes("[x]")||txt.toLowerCase().includes("error"))?"bad":"";
  d.className="ll"+(cls?" "+cls:"");
  d.textContent=txt;
  logEl.appendChild(d);
  logEl.scrollTop=logEl.scrollHeight;
}

frm.addEventListener("submit",async function(e){
  e.preventDefault();
  const dbp=document.getElementById("dbp").value;
  const dbp2=document.getElementById("dbp2").value;
  const adp=document.getElementById("adp").value;
  const adp2=document.getElementById("adp2").value;
  if(dbp!==dbp2){alert("Database passwords do not match.");return;}
  if(adp!==adp2){alert("Admin passwords do not match.");return;}
  if(dbp.length<8){alert("Database password must be at least 8 characters.");return;}
  if(adp.length<10){alert("Admin password must be at least 10 characters.");return;}

  const data={};
  new FormData(frm).forEach(function(v,k){data[k]=v;});

  btn.disabled=true;
  btn.textContent="Installing...";
  frm.querySelectorAll("input").forEach(function(i){i.disabled=true;});
  logWrap.classList.add("show");

  try{
    const res=await fetch("/install",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify(data)
    });
    if(!res.ok){throw new Error("HTTP "+res.status);}
  }catch(err){
    failBanner.textContent="Failed to start installation: "+err.message;
    failBanner.classList.add("show");
    btn.disabled=false;
    btn.textContent="Retry";
    return;
  }

  const src=new EventSource("/events");
  src.onmessage=function(ev){
    const d=ev.data;
    if(d.startsWith("__DONE__")){
      src.close();
      const rc=parseInt(d.slice(8),10);
      btn.textContent="Done";
      if(rc===0){
        const ip=location.hostname;
        const port=data.DASHBOARD_PORT||"9000";
        okBanner.className="banner success show";
        okBanner.innerHTML="<h2>Installation complete!</h2>"+
          "<p>Dashboard: <a href=\"http://"+ip+":"+port+"\" target=\"_blank\">"+
          "http://"+ip+":"+port+"</a></p>"+
          "<p>Caldera: http://"+ip+":8888</p>"+
          "<p>Login: admin / (password you set)</p>";
      }else{
        failBanner.textContent="Installation failed (exit code "+rc+"). Check the log above.";
        failBanner.classList.add("show");
      }
    }else{
      try{addLine(JSON.parse(d));}catch(_){addLine(d);}
    }
  };
  src.onerror=function(){src.close();};
});
</script>
</body>
</html>'''

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # silence access log

    def do_GET(self):
        if self.path == "/":
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            idx = 0
            try:
                while True:
                    with _lock:
                        chunk = _log[idx:]
                        done  = _done
                        rc    = _rc
                    for line in chunk:
                        msg = json.dumps(line)
                        self.wfile.write(("data:" + msg + "\n\n").encode("utf-8"))
                        idx += 1
                    if chunk:
                        self.wfile.flush()
                    if done and idx >= len(_log):
                        self.wfile.write(("data:__DONE__" + str(rc) + "\n\n").encode("utf-8"))
                        self.wfile.flush()
                        break
                    time.sleep(0.1)
            except Exception:
                pass
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        global _started
        if self.path == "/install" and not _started:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length))
            cfg = os.path.join(SCRIPT_DIR, "setup.conf")
            with open(cfg, "w") as fh:
                for k, v in data.items():
                    fh.write(k + "=" + v + "\n")
            os.chmod(cfg, 0o600)
            _started = True
            threading.Thread(target=_run_install, args=(cfg,), daemon=True).start()
            resp = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(400)
            self.end_headers()

def _run_install(cfg):
    global _done, _rc
    proc = subprocess.Popen(
        ["bash", SETUP_SH, "--config", cfg, "--offline", "--no-wizard"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    for line in proc.stdout:
        with _lock:
            _log.append(line.rstrip())
    proc.wait()
    with _lock:
        _rc   = proc.returncode
        _done = True
    # Auto-shutdown after browser receives __DONE__ event
    threading.Timer(3, srv.shutdown).start()

ip  = _local_ip()
srv = ThreadedHTTPServer(("", PORT), Handler)
print("[+] BAS Setup Wizard: http://" + ip + ":" + str(PORT), flush=True)
print("[+] Open this URL in a browser on any machine on this network.", flush=True)
srv.serve_forever()
PYEOF

  log "Starting setup wizard on port 9001..."
  log ""
  log "  Open this URL in your browser:"
  log "  http://${server_ip}:9001"
  log ""
  log "  Fill in the form and click 'Install BAS Platform'."
  log "  This terminal will exit when installation is complete."
  log "  (Ctrl+C to cancel)"
  log ""

  python3 "$pyfile" "$SCRIPT_DIR" "${BASH_SOURCE[0]}"
  local wiz_rc=$?
  rm -f "$pyfile"
  [[ $wiz_rc -ne 0 ]] && { err "Setup wizard exited unexpectedly."; exit 1; }
}
```

- [ ] **Step 2: Commit**

```bash
git add packaging/compose/setup.sh
git commit -m "feat: add start_web_wizard() with embedded Python3 stdlib SSE server"
git push
```

---

### Task 6: Rewrite main() with routing logic

**Files:**
- Modify: `packaging/compose/setup.sh`

- [ ] **Step 1: Replace the entire main() function**

Find and replace the entire `main()` function (from `main() {` to the closing `}`) with:

```bash
main() {
  # ── Parse flags ──────────────────────────────────────────────────────────────
  local _args=("$@")
  local i=0
  while [[ $i -lt ${#_args[@]} ]]; do
    case "${_args[$i]}" in
      --offline)   OFFLINE=true ;;
      --no-wizard) NO_WIZARD=true ;;
      --config)
        i=$(( i + 1 ))
        CONFIG_FILE="${_args[$i]:-}"
        ;;
    esac
    i=$(( i + 1 ))
  done

  # ── No-wizard mode: called internally by Python wizard subprocess ─────────────
  # Pure stdout, no whiptail, all output captured by Python SSE streamer.
  if $NO_WIZARD; then
    [[ -z "$CONFIG_FILE" ]] && { err "--config <file> is required with --no-wizard"; exit 1; }
    require_root
    verify_bundle_signatures
    load_config "$CONFIG_FILE"

    # License validation
    log "Validating license..."
    local lic_result
    lic_result=$(_check_license "$LIC_PATH")
    if [[ "$lic_result" == OK:* ]]; then
      local lic_info="${lic_result#OK:}"
      log "License OK — ${lic_info%%|*} (expires ${lic_info##*|})"
    else
      err "License invalid: ${lic_result#FAIL:}"
      exit 1
    fi

    # Prerequisite checks (text mode — abort on FAIL)
    log "Checking prerequisites..."
    while IFS= read -r result; do
      local status="${result%%:*}" message="${result#*:}"
      case "$status" in
        PASS) log "  OK  ${message}" ;;
        WARN) warn "  WN  ${message}" ;;
        INST) log "  >>  ${message} (will install)" ;;
        FAIL) err "  !! ${message}"; exit 1 ;;
      esac
    done < <(
      check_os
      check_ram
      check_disk "$INSTALL_DIR"
      check_docker
      check_compose
      check_port "$DASHBOARD_PORT"
      check_port "5432"
    )

    # Auto-install Docker if needed
    if $NEED_DOCKER; then
      log "Installing Docker CE..."
      install_docker || { err "Docker CE installation failed."; exit 1; }
    fi

    do_install
    show_credentials
    return 0
  fi

  # ── Normal interactive modes ──────────────────────────────────────────────────
  require_root
  ensure_whiptail
  verify_bundle_signatures

  # Config file mode: setup.conf was pre-seeded or --config passed
  if [[ -n "$CONFIG_FILE" ]] || [[ -f "${SCRIPT_DIR}/setup.conf" ]]; then
    [[ -z "$CONFIG_FILE" ]] && CONFIG_FILE="${SCRIPT_DIR}/setup.conf"
    load_config "$CONFIG_FILE"

    # Validate license with whiptail (or plain if whiptail fails)
    log "Validating license..."
    local lic_result lic_info
    lic_result=$(_check_license "$LIC_PATH")
    if [[ "$lic_result" != OK:* ]]; then
      { whiptail --title "$TITLE — License Error" --msgbox \
"License check FAILED:

  ${lic_result#FAIL:}

Edit setup.conf, update LIC_PATH, and re-run." 14 64; } 2>/dev/null || \
        err "License invalid: ${lic_result#FAIL:}"
      exit 1
    fi
    lic_info="${lic_result#OK:}"
    log "License OK — ${lic_info%%|*} (expires ${lic_info##*|})"

    page_welcome
    page_prereqs
    do_install
    page_finish
    log "Setup complete. Dashboard: http://$(hostname -I | awk '{print $1}'):${DASHBOARD_PORT}"
    return 0
  fi

  # Web wizard mode: no setup.conf found
  start_web_wizard
}
```

- [ ] **Step 2: Remove the old `main "$@"` call at the bottom and replace with:**

```bash
main "$@"
```

(It should already be there — just verify it's still present after editing.)

- [ ] **Step 3: Commit**

```bash
git add packaging/compose/setup.sh
git commit -m "feat: rewrite main() with no-wizard/config-file/web-wizard routing"
git push
```

---

### Task 7: Remove obsolete whiptail password pages

**Files:**
- Modify: `packaging/compose/setup.sh`

These functions are no longer called from `main()` and can be removed to keep the file clean.

- [ ] **Step 1: Remove page_database(), page_network(), page_install_dir(), page_security(), page_confirm()**

Delete these five functions entirely from `setup.sh`. They are replaced by the web form + `load_config()`.

Keep: `page_welcome()`, `page_prereqs()`, `page_finish()`, `page_license()` (page_license is no longer called from main but keep it in case it's referenced elsewhere — actually check: if it's not referenced anywhere after the rewrite, remove it too).

After the rewrite, `page_license` is no longer called from `main()` (license validation is done inline in both paths). Remove it.

The functions to DELETE are:
- `page_license()`
- `page_install_dir()`
- `page_database()`
- `page_network()`
- `page_security()`
- `page_confirm()`

Also remove `_read_secret()` (added in a previous fix attempt, no longer needed).

Keep:
- `page_welcome()`
- `page_prereqs()`
- `page_finish()`

- [ ] **Step 2: Verify setup.sh has no dangling references**

Run:
```bash
grep -n "page_license\|page_database\|page_network\|page_security\|page_confirm\|page_install_dir\|_read_secret" packaging/compose/setup.sh
```

Expected output: no matches (or only the function definitions you just deleted — which should also be gone).

- [ ] **Step 3: Commit**

```bash
git add packaging/compose/setup.sh
git commit -m "refactor: remove obsolete whiptail password pages replaced by web wizard"
git push
```

---

### Task 8: End-to-end verification

- [ ] **Step 1: Syntax-check setup.sh on Windows**

```powershell
bash -n packaging/compose/setup.sh
```

Expected: no output (no syntax errors). If bash is not in PATH on Windows, skip — will be verified on Ubuntu.

- [ ] **Step 2: Rebuild delivery package on Windows**

```powershell
.\packaging\windows-build.ps1 -Version "1.6.0" -Customer "HDFC Bank" -CustomerID "hdfc-prod-001" -Days 31
```

Verify `dist\bas-install-1.6.0\setup.conf` exists in the output dir.

- [ ] **Step 3: Test config-file path on Ubuntu VM**

On `ubuntuu@ubuntuu-VMware-Virtual-Platform`:

```bash
unzip bas-install-1.6.0.zip
# Pre-fill config
nano bas-install-1.6.0/setup.conf
# Set:
#   LIC_PATH=/root/hdfc-prod-001.lic (or wherever .lic landed)
#   DB_PASSWORD=TestPass123
#   ADMIN_PASSWORD=AdminPass1234
sudo bash bas-install-1.6.0/setup.sh --offline
```

Expected: wizard pages skip, installs in text mode, prints credentials at end.

- [ ] **Step 4: Test web wizard path on Ubuntu VM**

```bash
# Rename setup.conf so wizard triggers
mv bas-install-1.6.0/setup.conf bas-install-1.6.0/setup.conf.bak
sudo bash bas-install-1.6.0/setup.sh --offline
```

Expected output on terminal:
```
[+] Starting setup wizard on port 9001...
[+] Open this URL in your browser:
[+]   http://10.x.x.x:9001
```

Open `http://<vm-ip>:9001` in a browser on any machine on the same network. Fill in the form, click Install. Watch the live log stream. Verify success banner appears with dashboard URL.

- [ ] **Step 5: Verify dashboard is accessible**

Open `http://<vm-ip>:9000` — confirm BAS login page loads.

- [ ] **Step 6: Final commit if any adjustments were made during testing**

```bash
git add packaging/compose/setup.sh
git commit -m "fix: <describe any adjustments from testing>"
git push
```
