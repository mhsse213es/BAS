# Audspect BAS — Installation Guide

**Platform Version:** v1.7.5

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Pre-Installation Checklist](#2-pre-installation-checklist)
3. [Installation](#3-installation)
4. [TLS / HTTPS Configuration](#4-tls--https-configuration)
5. [Systemd Service](#5-systemd-service)
6. [Offline / Air-Gapped Deployment](#6-offline--air-gapped-deployment)
7. [Proxy Environments](#7-proxy-environments)
8. [Database Schema](#8-database-schema)
9. [Certificate Replacement](#9-certificate-replacement)
10. [High-Availability Setup](#10-high-availability-setup)
11. [Sizing and Performance](#11-sizing-and-performance)
12. [Firewall and Port Reference](#12-firewall-and-port-reference)
13. [Post-Installation Verification](#13-post-installation-verification)
14. [Rollback](#14-rollback)

---

## 1. Requirements

### Server

| Component | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20.04/22.04/24.04 LTS or Rocky Linux / RHEL 9 | Ubuntu 22.04/24.04 LTS |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disk | 40 GB | 100 GB SSD |
| Docker Engine | 24.0+ | 25.0+ |
| Docker Compose | v2.20+ | v2.24+ |

If Docker isn't already installed, the installer can install Docker CE from its official repository itself — it asks for explicit confirmation first (or accepts `--yes` for unattended runs).

### Endpoints (agent targets)

| OS | Supported Versions |
|---|---|
| Windows | Windows 10/11, Server 2016/2019/2022 |
| Linux | Ubuntu 18.04+, RHEL 7+, Debian 10+ |
| macOS | Agent source exists for macOS, but it is not currently cross-compiled or shipped in the delivery bundle — not available as a deliverable today |

### Network

- Agents must reach the server on the configured port (default **9443**, TCP outbound from each endpoint)
- Browser must reach the same port
- That port must not be blocked by endpoint firewalls for agent connectivity

---

## 2. Pre-Installation Checklist

- [ ] Ubuntu or Rocky/RHEL server provisioned and SSH accessible
- [ ] Delivery ZIP (`bas-install-<version>.zip`) transferred to the server
- [ ] Static IP or DNS name assigned to the server
- [ ] Firewall allows the chosen port (default 9443) from the agent subnet and analyst workstations
- [ ] At least 40 GB free disk space confirmed
- [ ] Customer license file on hand (`.lic`)
- [ ] TLS certificate and key on hand, if enabling `BAS_TLS`
- [ ] `setup.conf` prepared (see below) — this is the change-management artefact for the install

---

## 3. Installation

### 3.1 Extract the delivery package

```bash
cd /opt
sudo unzip bas-install-<version>.zip
cd bas-install-<version>
```

The package includes:
- `install.sh` — the installer (also handles upgrade, rollback, status, uninstall)
- `images/` — Docker image tarballs (all offline)
- `scenarios/` — signed scenario YAML files
- `setup.conf.template` — copy to `setup.conf` and fill in
- `docker-compose.yml` — production compose file
- `VERIFY.md` — GPG bundle-signature verification instructions (read this before unzipping, if the ZIP was signed)

### 3.2 Prepare `setup.conf`

```bash
cp setup.conf.template setup.conf
nano setup.conf
```

| Key | Required | Default | Notes |
|---|---|---|---|
| `DATA_DIR` | | `/opt/audspect` | Installation directory |
| `BAS_PORT` | | `9443` | Dashboard/API listening port |
| `BAS_TLS` | | `false` | Enable built-in TLS termination |
| `TLS_CERT` / `TLS_KEY` | if `BAS_TLS=true` | | Certificate/key paths |
| `DB_PASSWORD` | **yes** | | Postgres password |
| `ADMIN_EMAIL` | **yes** | | Initial admin account email |
| `ADMIN_PASSWORD` | **yes** | | Initial admin account password (forced change on first login) |
| `LOG_RETENTION_DAYS` | | `90` | Log retention window |
| `JWT_SECRET` | | auto-generated | JWT signing key |
| `AGENT_SECRET` | | auto-generated | Agent MAC secret |
| `LIC_PATH` | **yes** | | Path to the customer license file |

### 3.3 Run the installer

```bash
sudo bash install.sh --check                              # optional: prereq report
sudo bash install.sh --install --config setup.conf --yes
```

This single command loads the Docker images, writes `${DATA_DIR}/.env` (secrets not supplied in `setup.conf` are auto-generated), stages `docker-compose.yml` and the license, creates and enables a systemd unit, starts the stack, waits for the health check, and creates the initial admin user — a full 10-step process with no separate "web wizard" step.

When it completes, the dashboard is available at `http://<server-ip>:9443` (or `https://` if `BAS_TLS=true`).

**There is no interactive web-based setup wizard in the current release.** An older `setup.sh` (`--web`, port 9001) exists in the repository history but is not included in the current delivery bundle — `install.sh` is the sole supported installer.

---

## 4. TLS / HTTPS Configuration

Two supported approaches — pick one, don't combine them:

### 4.1 Built-in (`BAS_TLS`)

Set `BAS_TLS=true`, `TLS_CERT=/path/to/cert.pem`, `TLS_KEY=/path/to/key.pem` in `setup.conf` before running `--install` (or before an `--upgrade`, to add TLS to an existing install). The orchestrator terminates TLS itself — no reverse proxy needed.

### 4.2 Reverse Proxy (nginx)

Leave `BAS_TLS=false` and terminate TLS in front of the orchestrator instead:

```bash
sudo apt install nginx
```

Create `/etc/nginx/sites-available/audspect`:
```nginx
server {
    listen 443 ssl;
    server_name bas.company.com;

    ssl_certificate     /etc/ssl/certs/bas.crt;
    ssl_certificate_key /etc/ssl/private/bas.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers on;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;

    location / {
        proxy_pass         http://127.0.0.1:9443;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_read_timeout 86400s;   # Keep WebSocket connections alive
    }
}

server {
    listen 80;
    server_name bas.company.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo ln -s /etc/nginx/sites-available/audspect /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Agents must be re-enrolled with the HTTPS URL if they were previously enrolled with HTTP.

### 4.3 Caddy (alternative reverse proxy)

```
bas.company.com {
    reverse_proxy localhost:9443
}
```

Caddy handles TLS automatically with Let's Encrypt. For an internal/air-gapped CA, see [Certificate Replacement](#9-certificate-replacement).

---

## 5. Systemd Service

`install.sh --install` creates and enables `/etc/systemd/system/audspect.service` automatically — there is nothing to hand-write. It runs `docker compose -p audspect up -d --remove-orphans` on start (and `down` on stop), with `Restart=on-failure`.

```bash
sudo systemctl status audspect
sudo systemctl restart audspect
```

If you ever need to inspect or regenerate it, `install.sh --upgrade` refreshes the unit's `WorkingDirectory` automatically in case `DATA_DIR` changed — no manual edit needed there either.

---

## 6. Offline / Air-Gapped Deployment

The delivery ZIP is self-contained. No internet access is required at any point after receiving the ZIP.

### 6.1 Image loading

`install.sh --install`/`--upgrade` loads images from `images/*.tar` automatically. If loading manually:

```bash
cd /opt/bas-install-<version>/images
for f in *.tar; do sudo docker load < "$f"; echo "Loaded $f"; done
```

### 6.2 Content bundle

The orchestrator image includes at build time:
- ART atomics YAML library
- CISA KEV catalog (`cisa-kev.json`)
- ATT&CK STIX data bundle
- Built-in scenario YAML files with RSA-4096 signatures (native Go crypto — not GPG; see [Signing Infrastructure](../internal/signing-infrastructure.md))

No outbound connections are made by the orchestrator at runtime for content updates.

### 6.3 Updates in air-gapped environments

Receive a new delivery ZIP from Audspect. Follow the [Upgrade Guide](upgrade-guide.md) — `install.sh --upgrade`.

---

## 7. Proxy Environments

If the server itself is behind an HTTP proxy (relevant only if you need `docker pull` for something beyond the bundled images — the bundle itself never requires internet access):

```bash
sudo mkdir -p /etc/systemd/system/docker.service.d
sudo tee /etc/systemd/system/docker.service.d/proxy.conf <<EOF
[Service]
Environment="HTTP_PROXY=http://proxy.company.com:3128"
Environment="HTTPS_PROXY=http://proxy.company.com:3128"
Environment="NO_PROXY=localhost,127.0.0.1,192.168.0.0/16"
EOF
sudo systemctl daemon-reload && sudo systemctl restart docker
```

---

## 8. Database Schema

There's no numbered-migration-file system to "run" — the orchestrator applies its full, idempotent schema (`CREATE TABLE IF NOT EXISTS` / `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`) on every startup, automatically, both on first install and on every upgrade. There's no manual migration step and no separate migration-status table to check.

To confirm the schema applied cleanly, check the orchestrator's startup logs:
```bash
docker logs audspect-orchestrator --tail=100 | grep -i "schema\|migrat"
```

---

## 9. Certificate Replacement

### 9.1 TLS certificate renewal

**Reverse-proxy TLS (nginx):**
```bash
sudo cp new.crt /etc/ssl/certs/bas.crt
sudo cp new.key /etc/ssl/private/bas.key
sudo nginx -t && sudo systemctl reload nginx
```
No orchestrator restart needed — nginx handles termination.

**Built-in TLS (`BAS_TLS=true`):** update `TLS_CERT`/`TLS_KEY` in `setup.conf` and re-run `install.sh --upgrade --config setup.conf` to pick up the new files.

### 9.2 Internal CA certificates

If agents need to trust an internal CA (for HTTPS connections to the orchestrator):

**Windows:** Install the CA cert in the Windows Certificate Store (Trusted Root Certification Authorities).

**Linux:**
```bash
sudo cp company-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

---

## 10. High-Availability Setup

HA requires two orchestrator nodes behind a load balancer, sharing one PostgreSQL instance. This is not something `install.sh` sets up for you — it's a manually-assembled configuration on top of the standard single-node install.

**Requirements:**
- Layer 7 load balancer with sticky sessions (session affinity by cookie or source IP)
- Shared PostgreSQL: the same connection details on both nodes
- Same `JWT_SECRET` and `AGENT_SECRET` on both nodes
- Load balancer must forward `Upgrade` and `Connection` headers for WebSocket

**Limitations:**
- WebSocket events (live run output, AP job updates) are delivered only to the browser session connected to the node processing the event. Without sticky sessions, users may miss live updates.
- Recommend sticky sessions based on the `bas_token` cookie.

Contact Audspect support for a reviewed HA configuration.

---

## 11. Sizing and Performance

| Workload | vCPU | RAM | Disk |
|---|---|---|---|
| Up to 10 agents, daily runs | 2 | 4 GB | 40 GB |
| 10–50 agents, daily runs | 4 | 8 GB | 100 GB |
| 50–200 agents, continuous | 8 | 16 GB | 250 GB |
| 200+ agents | Contact Audspect | | |

**Disk planning:**
- Each completed run's step-level results are stored as a JSONB payload on the run row (`scenario_runs.results`) — larger scans produce larger payloads
- Reports (HTML/PDF) render on-demand at request time — there's no growing report-blob store to plan disk around
- Audit packs (ZIP): 500 KB–5 MB each
- Attack path collections: 1–20 MB each (depends on fleet size)

**PostgreSQL tuning for large deployments** — see [Performance Tuning Guide](../internal/performance-tuning.md) (internal) for the full connection-pool and `postgres` command-line tuning reference.

---

## 12. Firewall and Port Reference

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 9443 (default, configurable via `BAS_PORT`) | TCP | Inbound to server | Dashboard, API, agent connections |
| 5432 | TCP | Internal only | PostgreSQL (never expose externally) |
| 8888 | TCP | Internal only | Caldera API (optional, never expose externally) |
| 443 | TCP | Inbound to server | HTTPS (if using a reverse proxy) |
| 80 | TCP | Inbound to server | HTTP → HTTPS redirect (if using a reverse proxy) |

There is no separate temporary setup-wizard port — installation runs entirely from the CLI (`install.sh`), nothing to expose or close afterward.

**Agent subnet rules:**
- Agents must be allowed to make outbound TCP connections to the server on the configured port (9443 by default, or 443 if fronted by a TLS reverse proxy)
- No inbound ports are required on agent endpoints

---

## 13. Post-Installation Verification

```bash
sudo bash install.sh --status
```

Or manually:
```bash
# Server health
curl -s http://<server-ip>:9443/health | python3 -m json.tool

# PostgreSQL connectivity
docker exec audspect-postgres psql -U bas_user -d bas_platform -c "SELECT count(*) FROM users;"

# Dashboard reachable
curl -sI http://<server-ip>:9443 | head -5

# Scenario integrity
docker logs audspect-orchestrator | grep -i "scenario\|sign\|load"
```

Expected `/health` response shape:
```json
{"status": "ok", "db": "ok", "version": "<current version>"}
```

---

## 14. Rollback

```bash
sudo bash install.sh --rollback
```

Restores the most recent timestamped backup (`docker-compose.yml`, `.env`, version marker) that `--upgrade` took automatically, and restarts the stack. See the [Upgrade Guide](upgrade-guide.md) → Rollback Procedure for the full flow, including what to do if the previous version's Docker images have already been pruned.

**Database note:** Rollback of config/images is only safe on its own if the schema changes since the previous version are backward-compatible with the previous binary (nearly always true — schema changes are additive `IF NOT EXISTS` statements, never destructive). If a destructive schema change did ship (rare; announced in release notes), restore from a pre-upgrade database backup instead — see [Backup and Restore Guide](backup-restore.md).

---

*© Audspect — Confidential — Customer Distribution*
