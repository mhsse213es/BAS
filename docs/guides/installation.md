# Audspect BAS — Installation Guide

**Platform Version:** v1.7.3

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Pre-Installation Checklist](#2-pre-installation-checklist)
3. [Standard Installation (Web Wizard)](#3-standard-installation-web-wizard)
4. [CLI Installation](#4-cli-installation)
5. [TLS / HTTPS Configuration](#5-tls--https-configuration)
6. [Running as a systemd Service](#6-running-as-a-systemd-service)
7. [Offline / Air-Gapped Deployment](#7-offline--air-gapped-deployment)
8. [Proxy Environments](#8-proxy-environments)
9. [Database Migration](#9-database-migration)
10. [Certificate Replacement](#10-certificate-replacement)
11. [High-Availability Setup](#11-high-availability-setup)
12. [Sizing and Performance](#12-sizing-and-performance)
13. [Firewall and Port Reference](#13-firewall-and-port-reference)
14. [Post-Installation Verification](#14-post-installation-verification)
15. [Rollback](#15-rollback)

---

## 1. Requirements

### Server

| Component | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20.04 LTS | Ubuntu 22.04/24.04 LTS |
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disk | 40 GB | 100 GB SSD |
| Docker Engine | 24.0 | 25.0 |
| Docker Compose | v2.20 | v2.24 |

### Endpoints (agent targets)

| OS | Supported Versions |
|---|---|
| Windows | Windows 10/11, Server 2016/2019/2022 |
| Linux | Ubuntu 18.04+, RHEL 7+, Debian 10+ |
| macOS | 12 (Monterey)+ |

### Network

- Agents must reach the server on port 9000 (TCP outbound from each endpoint)
- Browser must reach port 9000
- Port 9000 must not be blocked by endpoint firewalls for agent connectivity

---

## 2. Pre-Installation Checklist

- [ ] Ubuntu server provisioned and SSH accessible
- [ ] Docker and Docker Compose installed
- [ ] Delivery ZIP transferred to the server
- [ ] Static IP or DNS name assigned to the server
- [ ] Firewall allows port 9000 from agent subnet and analyst workstations
- [ ] At least 40 GB free disk space confirmed
- [ ] Customer license file on hand (`.lic`)
- [ ] TLS certificate and key on hand (if deploying with HTTPS)

---

## 3. Standard Installation (Web Wizard)

### 3.1 Extract the delivery package

```bash
cd /opt
sudo unzip audspect-bas-v1.7.3.zip
cd audspect-bas-v1.7.3
```

The package includes:
- `setup.sh` — orchestrates the installation
- `images/` — Docker image tarballs (all offline)
- `scenarios/` — signed scenario YAML files
- `config.template.env` — sample environment configuration
- `docker-compose.yml` — production compose file

### 3.2 Start the web wizard

```bash
sudo ./setup.sh --web
```

The wizard starts a temporary HTTP server on port 9001. Open `http://<server-ip>:9001/setup` in a browser.

### 3.3 Fill in the setup form

| Field | Notes |
|---|---|
| **Server URL** | Must be reachable from agent endpoints. Use IP if no DNS. E.g., `http://192.168.10.50:9000` |
| **Admin email** | This becomes the admin username. Use a valid email format. |
| **Admin password** | Minimum 12 characters. You will be forced to change it on first login. |
| **Agent secret** | A random passphrase. Agents use this for authentication. Store it securely. |
| **JWT secret** | Leave blank to auto-generate. If supplying: minimum 32 characters. |
| **License path** | Absolute path to the `.lic` file on the server. E.g., `/opt/audspect.lic` |

Click **Deploy**. The wizard:
1. Loads all Docker images from `images/`
2. Writes `/opt/audspect-bas-v1.7.3/.env` with the filled values
3. Runs `docker compose up -d`
4. Polls `/health` until the orchestrator reports healthy

When the wizard shows **Deployment successful**, the dashboard is available at `http://<server-ip>:9000`.

---

## 4. CLI Installation

If you prefer non-interactive installation or are running headless:

```bash
sudo ./setup.sh \
  --url http://192.168.10.50:9000 \
  --admin-email admin@company.com \
  --admin-password "YourP@ssw0rd!" \
  --agent-secret "your-agent-secret-phrase" \
  --jwt-secret "your-jwt-secret-minimum-32-chars" \
  --license /opt/audspect.lic
```

All options can also be set by pre-populating the `.env` file manually and running `docker compose up -d`.

---

## 5. TLS / HTTPS Configuration

TLS is implemented via a reverse proxy in front of the orchestrator. The orchestrator itself speaks plain HTTP on port 9000.

### 5.1 nginx (recommended)

Install nginx:
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
        proxy_pass         http://127.0.0.1:9000;
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

Enable and reload:
```bash
sudo ln -s /etc/nginx/sites-available/audspect /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

**Important:** After adding TLS, update `PUBLIC_BASE_URL` in `.env` to `https://bas.company.com` and restart:
```bash
docker compose restart orchestrator
```

Agents must also be re-enrolled with the HTTPS URL if they were previously enrolled with HTTP.

### 5.2 Caddy (alternative)

```
bas.company.com {
    reverse_proxy localhost:9000
}
```

Caddy handles TLS automatically with Let's Encrypt. For internal/air-gapped CA, see the [Certificate Replacement](#10-certificate-replacement) section.

---

## 6. Running as a systemd Service

To ensure Docker Compose starts on server reboot:

```bash
sudo systemctl enable docker
```

Create `/etc/systemd/system/audspect.service`:
```ini
[Unit]
Description=Audspect BAS Platform
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/audspect-bas-v1.7.3
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable audspect
sudo systemctl start audspect
```

---

## 7. Offline / Air-Gapped Deployment

The delivery ZIP is self-contained. No internet access is required at any point after receiving the ZIP.

### 7.1 Image loading

The setup script loads images automatically. If loading manually:

```bash
cd /opt/audspect-bas-v1.7.3/images
for f in *.tar; do sudo docker load < "$f"; echo "Loaded $f"; done
```

### 7.2 Content bundle

The orchestrator image includes at build time:
- ART atomics YAML library
- CISA KEV catalog (`cisa-kev.json`)
- ATT&CK STIX data bundle
- Built-in scenario YAML files with RSA-4096 signatures

No outbound connections are made by the orchestrator at runtime for content updates.

### 7.3 Updates in air-gapped environments

Receive a new delivery ZIP from Audspect. Follow the [Upgrade Guide](upgrade-guide.md).

---

## 8. Proxy Environments

If the server is behind an HTTP proxy (for Docker pulls during development, etc.), configure Docker's proxy:

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

**Note:** For air-gapped deployments the proxy is not needed — all images load from local tarballs.

---

## 9. Database Migration

Database schema migrations run automatically on orchestrator startup. On upgrade, the new orchestrator image applies any pending migrations before serving traffic.

To run migrations manually (not normally required):
```bash
docker compose run --rm orchestrator migrate
```

To verify migration status:
```bash
docker compose exec postgres psql -U bas -d bas -c "SELECT version FROM schema_migrations ORDER BY applied_at DESC LIMIT 5;"
```

---

## 10. Certificate Replacement

### 10.1 TLS certificate renewal (nginx)

```bash
sudo cp new.crt /etc/ssl/certs/bas.crt
sudo cp new.key /etc/ssl/private/bas.key
sudo nginx -t && sudo systemctl reload nginx
```

No restart of the orchestrator is needed for TLS renewal — nginx handles the termination.

### 10.2 Internal CA certificates

If agents need to trust an internal CA (for HTTPS connections to the orchestrator):

**Windows:** Install the CA cert in the Windows Certificate Store (Trusted Root Certification Authorities).

**Linux:**
```bash
sudo cp company-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

---

## 11. High-Availability Setup

HA requires two orchestrator nodes behind a load balancer, sharing one PostgreSQL instance.

**Requirements:**
- Layer 7 load balancer with sticky sessions (session affinity by cookie or source IP)
- Shared PostgreSQL: the same `DATABASE_URL` on both nodes
- Same `JWT_SECRET` and `AGENT_SECRET` on both nodes
- Load balancer must forward `Upgrade` and `Connection` headers for WebSocket

**Limitations:**
- WebSocket events (live run output, AP job updates) are delivered only to the browser session connected to the node processing the event. Without sticky sessions, users may miss live updates.
- Recommend sticky sessions based on `bas_token` cookie.

Contact Audspect support for a reviewed HA configuration.

---

## 12. Sizing and Performance

| Workload | vCPU | RAM | Disk |
|---|---|---|---|
| Up to 10 agents, daily runs | 2 | 4 GB | 40 GB |
| 10–50 agents, daily runs | 4 | 8 GB | 100 GB |
| 50–200 agents, continuous | 8 | 16 GB | 250 GB |
| 200+ agents | Contact Audspect | | |

**Disk planning:**
- Each completed run produces approximately 50–500 KB of result JSON depending on scenario complexity
- PDF reports: 200 KB–2 MB each
- Audit packs (ZIP): 500 KB–5 MB each
- Attack path collections: 1–20 MB each (depends on fleet size)
- Allocate at least 1 GB per 1,000 completed runs

**PostgreSQL tuning for large deployments:**

Add to `docker-compose.yml` postgres service `command:`:
```yaml
command:
  - postgres
  - -c
  - shared_buffers=512MB
  - -c
  - work_mem=16MB
  - -c
  - maintenance_work_mem=128MB
  - -c
  - max_connections=100
```

---

## 13. Firewall and Port Reference

| Port | Protocol | Direction | Purpose |
|---|---|---|---|
| 9000 | TCP | Inbound to server | Dashboard, API, agent connections |
| 9001 | TCP | Inbound to server | Setup wizard (temporary, close after setup) |
| 5432 | TCP | Internal only | PostgreSQL (never expose externally) |
| 8888 | TCP | Internal only | Caldera API (optional, never expose externally) |
| 443 | TCP | Inbound to server | HTTPS (if using reverse proxy) |
| 80 | TCP | Inbound to server | HTTP → HTTPS redirect (if using reverse proxy) |

**Agent subnet rules:**
- Agents must be allowed to make outbound TCP connections to the server on port 9000 (or 443 if using TLS)
- No inbound ports are required on agent endpoints

---

## 14. Post-Installation Verification

Run these checks after deployment:

```bash
# Server health
curl -s http://<server-ip>:9000/health | python3 -m json.tool

# PostgreSQL connectivity
docker compose exec postgres psql -U bas -d bas -c "SELECT count(*) FROM users;"

# Dashboard reachable
curl -sI http://<server-ip>:9000 | head -5

# Scenario integrity (orchestrator log)
docker compose logs orchestrator | grep -i "scenario\|sign\|load"
```

Expected `/health` response:
```json
{"status": "ok", "db": "ok", "version": "1.7.3"}
```

---

## 15. Rollback

If an upgrade fails and you need to roll back:

```bash
cd /opt/audspect-bas-v1.7.3          # Previous version directory
docker compose up -d
```

**Database note:** Rollback is only safe if the new version's migrations are backward-compatible with the previous binary. If destructive migrations ran (rare; announced in release notes), restore from a pre-upgrade backup.

→ See [Backup and Restore Guide](backup-restore.md) for database backup procedures.

---

*© Audspect — Confidential — Customer Distribution*
