# Audspect BAS — Configuration Guide

**Platform Version:** v1.7.3

---

## Configuration Precedence

Configuration is loaded in this order, with later sources overriding earlier ones:

```
Built-in defaults  →  config.json (working directory, or the path passed as the first argument)  →  Environment variables
```

Environment variables always win. In Docker Compose deployments, all configuration is done via environment variables in the `.env` file — the JSON config file is optional.

---

## Required Variables

These must be set before the orchestrator will start:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string for the runtime role. Format: `postgres://user:password@host:5432/dbname?sslmode=disable` |
| `DATABASE_ADMIN_URL` | PostgreSQL connection string for the admin role, used only at startup for schema bootstrap and runtime-role provisioning. |
| `BAS_APP_DB_PASSWORD` | Password of the runtime database role (`bas_app`). Read from the environment only; it is not a JSON config key. |
| `JWT_SECRET` | JWT signing key. Minimum 32 bytes; known placeholder values are rejected at startup. Treat as a credential — rotate on schedule. |

---

## Core Variables

| Variable | Default | Description |
|---|---|---|
| `HTTP_PORT` | `9443` | Port of the agent mTLS listener (the installer maps this to `BAS_PORT`). The dashboard listener is `HTTP_PORT_DASHBOARD` (default `9543`). |
| `AGENT_SECRET` | (none) | Shared secret used for HMAC-SHA256 verification of agent-submitted results (`X-Result-MAC`). When unset, result MAC verification is disabled. |
| `BAS_LICENSE_PATH` | `/etc/bas/bas.lic` | Path to the customer license file (`.lic`). If the path is empty, the orchestrator reads `/etc/bas/bas.lic`. Startup fails if the file is missing or its signature does not verify. |
| `PUBLIC_BASE_URL` | (none) | Public URL of the platform. Used for phishing tracker and DLP sink URLs, and as the allowed WebSocket origin. Example: `https://bas.company.com` |

---

## Admin Bootstrap Variables

Applied only at first run: the orchestrator creates an admin account from these values only when no admin account exists. An existing admin is never overwritten at startup, so a password changed in the dashboard persists across restarts.

| Variable | Default | Description |
|---|---|---|
| `BAS_ADMIN_EMAIL` | `admin` | Admin account username. Use a valid email format. |
| `BAS_ADMIN_PASSWORD` | (none) | Password for the first admin account, used only when no admin exists. If unset and no admin exists, no account is created and the first admin is created through the setup endpoint (`install.sh` does this). Minimum 10 characters. There is no built-in default password. |

---

## Password and Security

| Variable | Default | Description |
|---|---|---|
| `BAS_PBKDF2_ITERATIONS` | `310000` | PBKDF2-HMAC-SHA256 iteration count. Minimum enforced: 310,000 (NIST SP 800-132). Increase for higher-security deployments with available CPU budget (e.g., 600000). |

---

## Scenario and Content Directories

| Variable | Default | Description |
|---|---|---|
| `SCENARIOS_DIR` | `scenarios` | Path to directory containing scenario YAML files and `.sig` signature files |
| `ART_DIR` | `/art-atomics` | Path to the Atomic Red Team atomics library (bundled in image) |
| `ART_PAYLOAD_DIR` | `/art-payloads` | Path to operator-supplied ART external payload binaries |
| `ART_CONTENT_VERSION` | (none) | Content pack version tag. Reseed is skipped on startup when this matches the previously seeded version. |
| `KEV_FILE` | `/content/cisa-kev.json` | CISA Known Exploited Vulnerabilities catalog JSON. Bundled in image at `/content/cisa-kev.json`. |
| `EPSS_FILE` | (none) | FIRST EPSS CSV/CSV.GZ file for exploit prediction scores. Optional. |

---

## Caldera Integration

| Variable | Default | Description |
|---|---|---|
| `CALDERA_URL` | (none) | Caldera REST API base URL. Example: `http://caldera:8888`. If not set, Caldera-backed scenarios are unavailable. |
| `CALDERA_API_KEY` | (none) | Caldera REST API key |

---

## Attack Path

| Variable | Default | Description |
|---|---|---|
| `BAS_SHARPHOUND_PATH` | (none) | Absolute path to `SharpHound.exe` on the server. Required to enable SharpHound collection in AP jobs. The binary is pushed to agents as part of the job payload. |

---

## SMTP (Exercise Engine / Phishing Simulation)

All SMTP variables are optional. Required only if the Purple Team Exercise Engine's phishing injection feature is used.

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | (none) | SMTP server hostname |
| `SMTP_PORT` | `25` | SMTP port |
| `SMTP_USER` | (none) | SMTP authentication username |
| `SMTP_PASS` | (none) | SMTP authentication password |
| `SMTP_FROM` | (none) | From address for exercise emails |
| `SMTP_FROM_NAME` | `Audspect BAS` | Display name for exercise emails |

---

## Threat Intelligence Connectors

| Variable | Default | Description |
|---|---|---|
| `MISP_URL` | (none) | MISP instance base URL. Example: `https://misp.company.com` |
| `MISP_API_KEY` | (none) | MISP API key (read-only key is sufficient) |
| `OPENCTI_URL` | (none) | OpenCTI instance base URL |
| `OPENCTI_API_KEY` | (none) | OpenCTI API key |
| `THREAT_INTEL_POLL_HOURS` | `24` | How frequently to poll configured connectors for new intelligence (in hours) |
| `THREAT_INTEL_SECTORS` | (none) | Comma-separated sector filter for intelligence. Example: `financial-services,banking` |
| `THREAT_INTEL_REGIONS` | (none) | Comma-separated region filter. Example: `Asia,India` |

Sector and region filters apply as OR conditions — intelligence matching any listed sector or region is included.

### TLS certificate verification

Outbound connectors verify the TLS certificate of the system they connect to. This is deliberate: every one of these connections carries an API key or password, and accepting any certificate would expose that credential to anyone able to intercept the connection.

Appliances that present a self-signed certificate — common for air-gapped MISP and on-prem TAXII/QRadar/Splunk deployments — need verification turned off explicitly, per connector:

| Connector | Where to set it |
|---|---|
| MISP | **Settings → Threat Intelligence → MISP → Skip TLS verify** |
| TAXII | **Settings → TAXII Connectors → (edit) → Skip TLS certificate verification** |
| Splunk / QRadar / Trellix / Elastic | `"insecureTls": true` on `POST`/`PUT /api/detectverify/configs` |

**Elastic Security detection connector:** requires Elastic Stack 8.x (alerts-as-data, `.alerts-security.alerts-<space>` indices). Set `baseUrl` to the Elasticsearch URL and configure exactly one auth mode: an API key in `apiToken`, or a username in `clientId` and password in `clientSecret`. The credentials need read privilege on `.alerts-security.alerts-*`.

Prefer installing the appliance's CA certificate on the orchestrator host over disabling verification.

---

## Docker Compose `.env` File Example

```dotenv
# Required
DATABASE_URL=postgres://bas_app:<BAS_APP_DB_PASSWORD>@postgres:5432/bas_platform?sslmode=prefer
DATABASE_ADMIN_URL=postgres://bas:securepassword@postgres:5432/bas?sslmode=disable
BAS_APP_DB_PASSWORD=change-this-runtime-db-password
JWT_SECRET=change-this-to-a-random-64-character-string-before-production

# Core
HTTP_PORT=9443
AGENT_SECRET=change-this-to-a-random-agent-secret
BAS_LICENSE_PATH=/etc/bas/audspect.lic
PUBLIC_BASE_URL=https://192.168.1.50:9543

# Admin bootstrap (first run only)
BAS_ADMIN_EMAIL=admin@company.com
BAS_ADMIN_PASSWORD=ChangeOnFirstLogin!99

# Security
BAS_PBKDF2_ITERATIONS=310000

# Optional: Caldera
# CALDERA_URL=http://caldera:8888
# CALDERA_API_KEY=your-caldera-key

# Optional: Threat Intel
# MISP_URL=https://misp.company.com
# MISP_API_KEY=your-misp-key
# OPENCTI_URL=https://opencti.company.com
# OPENCTI_API_KEY=your-opencti-key
# THREAT_INTEL_POLL_HOURS=24
# THREAT_INTEL_SECTORS=financial-services,banking
# THREAT_INTEL_REGIONS=Asia,India

# Optional: SMTP (Purple Team exercises)
# SMTP_HOST=smtp.company.com
# SMTP_PORT=587
# SMTP_USER=bas-mailer@company.com
# SMTP_PASS=your-smtp-password
# SMTP_FROM=bas-mailer@company.com
# SMTP_FROM_NAME=Audspect BAS
```

---

## Config File Format (JSON)

If using a JSON config file alongside environment variables (e.g., for local development), place it as `config.json` in the orchestrator's working directory, or pass its path as the first argument to the orchestrator binary. The file cannot supply `BAS_APP_DB_PASSWORD`, which is read from the environment only:

```json
{
  "database_url": "postgres://bas:password@localhost:5432/bas?sslmode=disable",
  "jwt_secret": "your-jwt-secret",
  "http_port": 9443,
  "agent_secret": "your-agent-secret",
  "scenarios_dir": "/opt/bas/scenarios",
  "caldera_url": "http://localhost:8888",
  "caldera_api_key": "your-caldera-key",
  "pbkdf2_iterations": 310000
}
```

**Security warning:** Storing `jwt_secret` or `agent_secret` in the JSON file means they are readable by anyone with filesystem access. The orchestrator logs a warning at startup when secrets are found in the config file. Prefer environment variables for all secret values.

---

## Applying Configuration Changes

Most configuration changes require restarting the orchestrator:

```bash
# Edit .env (default install directory; DATA_DIR in setup.conf)
nano /opt/audspect/.env

# Restart orchestrator (not full stack)
cd /opt/audspect
docker compose restart orchestrator
```

**Changes that take effect without restart:**
- None. All config is loaded at startup.

**Changes that require full stack restart (not just orchestrator):**
- `DATABASE_URL` (if pointing to a different database host)

---

## Verifying Configuration

To confirm the active password-hashing settings and crypto profile:

```
GET /api/crypto/info
Authorization: Bearer <jwt>
```

Response includes `password_algorithm`, `pbkdf2_iterations`, `jwt`, `scenario_signing` and `fips_ready`. License details are available at `GET /api/license` (Settings → License).

The JWT secret and passwords are never returned by any API endpoint. The agent bootstrap secret is returned only by `GET /api/config/connection`, to users with the `config:view-connection` permission, so the Deploy Agent page can build an install package.

---

*© Audspect — Confidential — Customer Distribution*
