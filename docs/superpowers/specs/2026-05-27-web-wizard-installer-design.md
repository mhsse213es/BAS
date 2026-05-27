# BAS Platform — Web Wizard Installer Design

**Date:** 2026-05-27  
**Status:** Approved  
**Scope:** `packaging/compose/setup.sh`, new `packaging/compose/setup.conf`

---

## Problem

`whiptail --passwordbox` silently fails in VMware terminal environments, meaning the DB password and admin password pages are never collected. Multiple fallback attempts (TERM export, `read -s`) have not resolved it reliably across all target environments.

## Solution

Replace all interactive password input with two non-terminal paths:

1. **Web wizard** — Python3 stdlib HTTP server on `:9001`. Operator opens browser, fills a form, clicks Install. Live log streamed via SSE. Zero external resources (air-gapped safe).
2. **Config file** — `setup.conf` key=value file pre-seeded before running `setup.sh`. Wizard skipped entirely. Works for scripted/automated deploys and SSH-only access.

Whiptail is retained only for informational pages (welcome, prereqs) where it already works.

---

## Architecture

### Install modes

```
sudo bash setup.sh --offline
       │
       ├─ setup.conf present?
       │   YES ──► load_config() → validate license → page_prereqs → do_install → show_credentials
       │
       └─ NO  ──► start_web_wizard()
                   └─ python3 /tmp/bas-wizard-XXXX.py $SCRIPT_DIR $SETUP_SH
                       serves http://0.0.0.0:9001
                       browser submits form
                       → writes setup.conf
                       → spawns: bash setup.sh --config setup.conf --offline --no-wizard
                       → streams subprocess stdout/stderr via SSE
                       → sends __DONE__<rc> event
                       → auto-shuts-down after 3 s delay
```

### Internal `--no-wizard` flag

Used exclusively by the Python subprocess call. When set:
- No whiptail at all — pure stdout log output (Python captures it)
- Skips `ensure_whiptail`, `page_welcome`, `page_prereqs` UI
- Runs prereq checks in text mode, aborts on FAIL
- Runs `do_install` in text mode (no gauge pipe)
- Prints credential summary to stdout on success

### `do_install` dual-mode output

A `_step PCT "message"` helper selects output format:
- Normal mode: `echo $PCT; echo "# $message"` → piped into whiptail gauge
- No-wizard mode: `log "$message"` → plain stdout captured by Python

---

## Components

### 1. `setup.conf` (new file, ships in ZIP)

```bash
# BAS Platform Setup Configuration
# Fill all values and run: sudo bash setup.sh --offline
# Or leave blank — the browser wizard will appear automatically.

INSTALL_DIR=/opt/bas-platform
DASHBOARD_PORT=9000
LIC_PATH=
DB_PASSWORD=
ADMIN_PASSWORD=
```

Shipped blank. Operator either pre-fills it or leaves it blank (triggers wizard).

### 2. `load_config(file)` function

- Reads `setup.conf` with `while IFS='=' read -r key val` (no `source` — no arbitrary code exec)
- Strips whitespace and quotes from values
- Applies defaults for `INSTALL_DIR` and `DASHBOARD_PORT`
- Validates: `DB_PASSWORD` ≥ 8 chars, `ADMIN_PASSWORD` ≥ 10 chars, `LIC_PATH` non-empty
- Generates `JWT_SECRET`, `AGENT_SECRET`, `CALDERA_API_KEY`, `CALDERA_API_KEY_BLUE` via openssl

### 3. `start_web_wizard()` function

- Writes Python server to `mktemp /tmp/bas-wizard-XXXX.py`
- Detects server IP via UDP socket trick (no external call)
- Prints `http://<ip>:9001` to terminal
- Executes `python3 $pyfile $SCRIPT_DIR $SETUP_SH`
- Removes temp file on exit

### 4. Embedded Python server (heredoc in `setup.sh`)

**Python stdlib only:** `http.server`, `subprocess`, `threading`, `json`, `os`, `sys`, `time`, `socket`

Routes:
| Method | Path | Action |
|--------|------|--------|
| GET | `/` | Serve inline HTML page |
| GET | `/events` | SSE stream of install log lines |
| POST | `/install` | Write `setup.conf`, start install subprocess |

Thread model:
- Main thread: `HTTPServer.serve_forever()`
- Install thread: `subprocess.Popen` reading stdout line-by-line into `_log[]`
- Shutdown timer: `threading.Timer(3, srv.shutdown)` fires after `_done = True`

SSE protocol:
- Each log line: `data:<json-encoded-string>\n\n`
- Completion: `data:__DONE__<returncode>\n\n`

### 5. HTML page (inline in Python string)

**Air-gapped constraints:**
- No external URLs anywhere (no CDN, no Google Fonts, no external JS)
- System monospace font stack
- All CSS inline in `<style>` block
- All JS inline in `<script>` block, vanilla only

**Form fields:**
- License file path (text, required)
- Install directory (text, default `/opt/bas-platform`)
- Dashboard port (number, default `9000`)
- DB password + confirm (password inputs, min 8)
- Admin password + confirm (password inputs, min 10)
- Install button

**Client-side validation** (before POST):
- Password match check
- Min length check
- All fields non-empty

**Post-submit UI:**
- Form fields disabled, button shows "Installing…"
- Log panel appears, auto-scrolls
- On `__DONE__0`: success banner with dashboard URL
- On `__DONE__<non-zero>`: error banner with exit code

**Visual style:** Navy palette matching BAS dashboard (`#0b1420` bg, `#152338` card, `#2f81f7` accent).

---

## Changes to `setup.sh`

### New globals
```bash
NO_WIZARD=false
CONFIG_FILE=""
```

### New functions
- `load_config(file)`
- `start_web_wizard()`
- `_step(pct, msg)` — replaces raw `echo N; echo "# msg"` in do_install
- `show_credentials()` — plain-text finish for no-wizard mode

### Modified functions
- `main()` — routing logic (config file / web wizard / no-wizard subprocess)
- `do_install()` — wraps `_do_install_steps` in gauge or plain mode
- `_do_install_steps()` — extracted from `do_install`, uses `_step` throughout

### Removed dependency
- `page_database()`, `page_security()` password collection via whiptail — eliminated
- `page_install_dir()`, `page_network()` — replaced by config/form

### Kept unchanged
- `check_os/ram/disk/docker/compose/port`
- `verify_bundle_signatures`
- `_check_license`
- `install_docker`
- `page_welcome`, `page_prereqs` (whiptail msgbox — works fine)
- `page_finish` (whiptail msgbox — used in normal config-file mode)

---

## `windows-build.ps1` change

Add one line to copy `setup.conf` template into the output dir:
```powershell
Copy-Item "$ComposeDir\setup.conf" "$OutDir\setup.conf"
```

---

## Error handling

| Failure | Behaviour |
|---------|-----------|
| `setup.conf` missing required field | `err` + `exit 1` before install starts |
| License invalid in config mode | Error message + `exit 1` |
| Prereq FAIL in no-wizard mode | `err` line + `exit 1` (visible in browser log) |
| Install subprocess exits non-zero | Browser shows error banner with exit code |
| Python3 not available | `err "python3 required"` + `exit 1` before wizard starts |
| Port 9001 already in use | Python bind fails, error printed to terminal |

---

## Delivery flow (updated)

```
[Windows] windows-build.ps1
    → dist/bas-install-1.6.0.zip contains:
        setup.conf          ← blank template
        setup.sh
        images/*.tar
        ...

[Client Ubuntu]
  Option A (wizard):
    unzip bas-install-1.6.0.zip
    sudo bash bas-install-1.6.0/setup.sh --offline
    → open http://<server-ip>:9001 in browser
    → fill form, click Install
    → watch live log
    → done

  Option B (pre-seeded):
    unzip bas-install-1.6.0.zip
    nano bas-install-1.6.0/setup.conf   # fill in values
    sudo bash bas-install-1.6.0/setup.sh --offline
    → installs silently
    → prints credentials on terminal
```

---

## Out of scope

- Multi-node / cluster install
- HTTPS for the wizard port (LAN-only, one-time use)
- Wizard authentication (one-time use, firewall-protected)
- Windows client install (agent-only, separate tooling)
