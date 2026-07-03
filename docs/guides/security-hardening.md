# Audspect BAS — Security Hardening Guide

**Platform Version:** v1.7.3

---

## Overview

Audspect BAS is designed for on-premises deployment in regulated environments. This guide documents the platform's built-in security controls and the additional hardening steps recommended for production deployments, particularly in BFSI environments.

---

## TLS Configuration

### Recommended: nginx TLS termination

The orchestrator speaks plain HTTP on port 9000. Terminate TLS at an nginx reverse proxy:

```nginx
server {
    listen 443 ssl;
    server_name bas.company.com;

    # Certificate
    ssl_certificate     /etc/ssl/certs/bas.crt;
    ssl_certificate_key /etc/ssl/private/bas.key;

    # Protocol and ciphers (TLS 1.2+ only; forward secrecy required)
    ssl_protocols             TLSv1.2 TLSv1.3;
    ssl_ciphers               ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    ssl_session_cache         shared:SSL:10m;
    ssl_session_timeout       1d;

    # HSTS (enable after confirming TLS works)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    # Additional security headers
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;

    location / {
        proxy_pass         http://127.0.0.1:9000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400s;
    }
}
```

**Critical:** After TLS is enabled, update `PUBLIC_BASE_URL=https://bas.company.com` in `.env` and restart the orchestrator. Re-enroll all agents with the HTTPS URL.

### Certificate Requirements

| Requirement | Specification |
|---|---|
| Key algorithm | RSA-2048 minimum; RSA-4096 or ECDSA P-256 recommended |
| Hash algorithm | SHA-256 minimum |
| Validity period | Maximum 2 years (1 year recommended) |
| SAN | Must include the server's FQDN |

---

## Password Security

| Control | Implementation |
|---|---|
| Algorithm | PBKDF2-HMAC-SHA256 |
| Iterations | 310,000 (NIST SP 800-132 minimum; configurable higher) |
| Key length | 256-bit (32 bytes) derived key |
| Salt | 256-bit (32 bytes) cryptographically random per hash |
| Format | `$pbkdf2-sha256$<iter>$<b64salt>$<b64dk>` |
| Self-test | Runs at startup via `RunCryptoSelfTests()`; startup aborts on failure |
| Legacy migration | bcrypt hashes from prior versions verified read-only; re-hashed on next login |

**Recommendation:** Increase `BAS_PBKDF2_ITERATIONS` to 600,000 on deployments where login latency of ~200ms is acceptable. Higher iterations provide better brute-force resistance.

---

## Session Security

| Control | Value |
|---|---|
| Token type | JWT HS256 |
| Token TTL | 24 hours |
| Storage | HttpOnly cookie |
| Cookie flags | `SameSite=Strict; HttpOnly; Secure` (Secure flag only when TLS is active) |
| CSRF protection | SameSite=Strict prevents cross-origin form submission |
| Revocation | Rotate `JWT_SECRET` to invalidate all active sessions |

---

## Agent Trust and Result Integrity

### Agent Binary Trust

On every heartbeat, the agent submits the SHA-256 hash of its own binary. The orchestrator verifies this against `BINARIES.sha256`. Mismatches flag the agent in the dashboard and audit log.

To update the trust manifest after releasing a new agent binary:
- Re-run `windows-build.ps1` — it re-generates and re-signs `BINARIES.sha256` automatically

### Result Integrity (HMAC-SHA256)

Every result POST from an agent includes a MAC header:
```
X-BAS-MAC: sha256=<hmac-sha256-hex>
```

The MAC is computed over the full request body using `AGENT_SECRET` as the key. The orchestrator rejects any result where the MAC does not match. This prevents replay attacks and result injection.

**Requirements:**
- `AGENT_SECRET` must be set and match between server and agent
- The secret should be at least 32 characters of cryptographic randomness
- Rotate `AGENT_SECRET` by updating `.env`, restarting the orchestrator, and redeploying agents with the new secret

---

## Scenario Integrity (RSA-4096 Signing)

Every scenario YAML ships with a detached RSA-4096 signature (`.yaml.sig`). The orchestrator verifies each signature on load and rejects unsigned or tampered scenarios.

**Verification:**
- On startup: all scenarios in `SCENARIOS_DIR` are verified
- On filesystem change: the 15-second watcher detects in-place tampering
- On scenario run dispatch: signature is re-verified before dispatch

A scenario that fails signature verification cannot be run — it appears in the dashboard with a red "Signature Invalid" badge.

**For custom scenarios:** Custom scenarios authored in the dashboard are automatically signed by the orchestrator using the platform's signing key.

**For externally authored YAML:** Must be signed using the platform signing tool before placement in `SCENARIOS_DIR`. Contact Audspect for the signing tool and key material.

---

## Docker Hardening

The orchestrator container uses the following hardening defaults:

| Control | Value |
|---|---|
| Base image | `gcr.io/distroless/static` (distroless) |
| Run user | `nonroot` (UID 65532) |
| Shell | None (distroless has no shell) |
| Package manager | None |
| Writeable filesystem | No (read-only root, explicit volume mounts only) |
| Network mode | Bridge (not host) |
| Privileged | No |
| Capabilities | None added |
| Port exposure | `9000` only |

### docker-compose.yml hardening additions

```yaml
services:
  orchestrator:
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

  postgres:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - FOWNER
      - SETUID
      - SETGID
```

---

## Network Segmentation

**Recommended network architecture:**

```
[Analyst Workstations]  →  port 443 → [nginx reverse proxy]  →  port 9000 → [Orchestrator]
[Target Endpoints]      →  port 443 → [nginx reverse proxy]  →  port 9000 → [Orchestrator]
[Orchestrator]          →  port 5432 → [PostgreSQL] (internal only)
[Orchestrator]          →  port 8888 → [Caldera] (internal only, optional)
```

**Rules:**
- PostgreSQL port 5432 must NOT be accessible from outside the Docker network
- Caldera port 8888 must NOT be accessible from outside the Docker network
- The setup wizard port (9001) must be closed after initial setup
- AGENT_SECRET and JWT_SECRET must never traverse unencrypted network links

---

## Secrets Rotation Schedule

| Secret | Recommended Rotation | Notes |
|---|---|---|
| `JWT_SECRET` | Every 90 days | Rotation invalidates all active browser sessions |
| `AGENT_SECRET` | Every 180 days | Requires agent redeployment with new secret |
| TLS certificate | Before expiry; yearly minimum | nginx `ssl_certificate` and `ssl_certificate_key` |
| Admin password | After any suspected compromise | Via dashboard or API |
| GPG signing key | Every 3 years | See [Signing Infrastructure](../internal/signing-infrastructure.md) |

Rotation of `JWT_SECRET` or `AGENT_SECRET` requires:
1. Update `.env`
2. `docker compose restart orchestrator`
3. For `AGENT_SECRET`: redeploy all agents with the new secret

---

## Audit Logging

All security-relevant events are written to the `events` table and exposed via the Audit Log UI:

| Event Category | Events Logged |
|---|---|
| Authentication | Login success/failure, password change, password reset, logout |
| User management | Create, edit, delete user; role change |
| Agent management | State change (quarantine, retire, restrict) |
| Scenario execution | Run started, cancelled, completed |
| Integrity | Signature verification failure, binary trust mismatch, tamper detection |
| Admin actions | Config reads, license queries |

Audit log entries include: event type, timestamp, actor (user email or agent ID), affected resource ID, source IP.

**Log access:**
```
GET /api/events?category=auth&from=2026-07-01&limit=100
```

**Log export:**
```
GET /api/events/export?format=csv&from=2026-07-01&to=2026-07-31
```

---

## Least Privilege

| Component | User Account |
|---|---|
| Orchestrator container | `nonroot` (UID 65532) — cannot write to root filesystem |
| PostgreSQL container | `postgres` user — owns only the `bas` database |
| Agent (Windows service) | `LOCAL SERVICE` or a dedicated service account with minimum OS permissions |
| Agent (Linux service) | Dedicated `bas-agent` user with no sudo |

**Agent Windows privilege note:** Agent execution of ART atomics may require elevated privileges for techniques that test privilege escalation paths. In this case, run the agent as a standard user and allow it to attempt (and fail) privileged operations — this tests whether EDR controls block the escalation.

---

## FIPS Considerations

The orchestrator uses standard Go `crypto/sha256` and `golang.org/x/crypto/pbkdf2` — both compatible with FIPS 140-2 approved algorithms. Go itself is not a FIPS-validated cryptographic module.

For deployments with formal FIPS 140-2 requirements:
- The orchestrator algorithms (PBKDF2-HMAC-SHA256, HMAC-SHA256, RSA-4096) are FIPS-approved algorithm families
- FIPS validation requires an approved cryptographic module boundary — consult your security officer and contact Audspect for validated deployment guidance

---

## Code Obfuscation

The orchestrator binary is compiled with **Garble** (`-literals -tiny`), which:
- Obfuscates identifier names, package names, and string literals
- Makes reverse engineering of the binary significantly harder
- Does not affect runtime behavior
- Is applied automatically during the release build (`windows-build.ps1`)

---

*© Audspect — Confidential — Customer Distribution*
