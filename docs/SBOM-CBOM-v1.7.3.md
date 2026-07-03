# Software Bill of Materials & Cryptographic Bill of Materials

**Product:** Audspect BAS (Breach & Attack Simulation Platform)

**Version:** 1.7.3

**Document Date:** 3 July 2026

**Document Revision:** 1.0 — Initial Release

**Prepared By:** Audspect 

**Classification:** CONFIDENTIAL — Restricted Distribution — Authorised Recipients Only

**Standard Referenced:** NTIA Minimum Elements for SBOM · Structured to align with the CycloneDX v1.4 data model


> **Source of Truth:** All entries in this document are derived from direct inspection of the repository at tag v1.7.3 — specifically go.mod, go.sum, requirements.txt, Dockerfile, and docker-compose.yml. Nothing has been inferred or guessed.

---

## Table of Contents

1. [Document Information](#1-document-information)
2. [Software Bill of Materials (SBOM)](#2-software-bill-of-materials-sbom)
   - 2.1 [First-Party Components](#21-first-party-components)
   - 2.2 [Orchestrator — Go Libraries (Direct)](#22-orchestrator--go-libraries-direct)
   - 2.3 [Orchestrator — Go Libraries (Indirect)](#23-orchestrator--go-libraries-indirect)
   - 2.4 [Agent — Go Libraries](#24-agent--go-libraries)
   - 2.5 [Installer — Go Libraries](#25-installer--go-libraries)
   - 2.6 [API Service — Python Libraries](#26-api-service--python-libraries)
   - 2.7 [Container Base Images](#27-container-base-images)
   - 2.8 [Bundled Third-Party Data](#28-bundled-third-party-data)
   - 2.9 [Build-Time Tools (Not Shipped)](#29-build-time-tools-not-shipped)
3. [Cryptographic Bill of Materials (CBOM)](#3-cryptographic-bill-of-materials-cbom)
   - 3.1 [Algorithm Inventory Summary](#31-algorithm-inventory-summary)
   - 3.2 [Password Hashing — PBKDF2-HMAC-SHA256](#32-password-hashing--pbkdf2-hmac-sha256)
   - 3.3 [Session Tokens — JWT HS256](#33-session-tokens--jwt-hs256)
   - 3.4 [Agent Authentication — HMAC-SHA256](#34-agent-authentication--hmac-sha256)
   - 3.5 [Scenario & Manifest Signing — RSA-4096](#35-scenario--manifest-signing--rsa-4096)
   - 3.6 [Binary Integrity — SHA-256 Manifest](#36-binary-integrity--sha-256-manifest)
   - 3.7 [UI Asset Integrity — SHA-256](#37-ui-asset-integrity--sha-256)
   - 3.8 [Cryptographic Randomness](#38-cryptographic-randomness)
   - 3.9 [Database Transport](#39-database-transport)
   - 3.10 [Orchestrator API Transport](#310-orchestrator-api-transport)
   - 3.11 [API Service Cryptography (Python)](#311-api-service-cryptography-python)
4. [Compliance Alignment](#4-compliance-alignment)

---

## 1. Document Information

### Purpose

This document provides a complete inventory of all software components (SBOM) and cryptographic algorithms and primitives (CBOM) used in Audspect BAS v1.7.3. It is intended for use by procurement personnel, security review teams, and regulatory audit bodies.

### Scope

- Orchestrator service (Go 1.26, Linux amd64, garble-obfuscated)
- Endpoint agent binaries (Go 1.26, five platform targets)
- Windows GUI installer (Go 1.26)
- API service (Python 3.12, FastAPI — separate deployment)
- MITRE Caldera simulation engine (custom Docker image)
- All container images declared in `docker-compose.yml`
- All third-party data bundled at build time

### Classification & Handling

This document is **CONFIDENTIAL**. It must not be shared with parties outside the authorised customer organisation without prior written consent from Audspect.

| Field | Value |
|---|---|
| Product | Audspect BAS Platform |
| Version | `1.7.3` |
| Document Revision | 1.0 — Initial Release |
| Document Date | 3 July 2026 |
| Prepared By | Audspect |
| SBOM Format Alignment | NTIA Minimum Elements; CycloneDX v1.4 (aligned, not machine-generated) |

---

## 2. Software Bill of Materials (SBOM)

### 2.1 First-Party Components

| Component | Language / Runtime | Target Platform | Build Method | Deployment Runtime | Notes |
|---|---|---|---|---|---|
| bas-orchestrator | Go 1.26 | Linux amd64 | `garble -literals build -trimpath -s -w` | `gcr.io/distroless/static-debian12` | Own application modules are obfuscated during the production build; third-party dependencies remain unobfuscated to preserve runtime compatibility and reflection.|
| `bas-agent-linux-amd64` | Go 1.26 | Linux amd64 | `go build -trimpath -s -w` | Bare metal / VM / Docker | CGO_ENABLED=0; fully static |
| `bas-agent-linux-arm64` | Go 1.26 | Linux arm64 | `go build -trimpath -s -w` | Bare metal / VM | CGO_ENABLED=0; fully static |
| `bas-agent-windows-amd64.exe` | Go 1.26 | Windows amd64 | `go build -trimpath -s -w` | Windows 10+ | CGO_ENABLED=0; includes tray and status-window UI |
| `bas-agent-darwin-amd64` | Go 1.26 | macOS amd64 (Intel) | `go build -trimpath -s -w` | macOS 12+ | CGO_ENABLED=0; fully static |
| `bas-agent-darwin-arm64` | Go 1.26 | macOS arm64 (Apple Silicon) | `go build -trimpath -s -w` | macOS 12+ | CGO_ENABLED=0; fully static |
| `bas-agent-windows-amd64-setup.exe` | Go 1.26 | Windows amd64 | `go build -H windowsgui -trimpath -s -w` | Windows 10+ | GUI installer; embeds agent binary; optionally bundles WebView2 Evergreen runtime |
| API Service | Python 3.12 | Linux (Docker) | `pip install -r requirements.txt` | `python:3.12-slim` | FastAPI + Uvicorn; separate deployment — not in standard install bundle |
| `bas-caldera` | Python (MITRE Caldera) | Linux (Docker) | Custom Dockerfile from `ghcr.io/mitre/caldera:latest` | Docker container | CTID adversary-emulation-library baked in; atomic plugin disabled; version not pinned — see **GAP-01** |

---

### 2.2 Orchestrator — Go Libraries (Direct)

**Source:** `orchestrator/go.mod` · Module: Audspect BAS Orchestrator · Go version: `1.26`

| Package | Version | Role | License |
|---|---|---|---|
| `github.com/chromedp/cdproto` | `20260321001828-e3e3800016bc` | Chrome DevTools Protocol types & client | MIT |
| `github.com/chromedp/chromedp` | `v0.15.1` | Headless Chrome automation for HTML→PDF rendering | MIT |
| `github.com/go-chi/chi/v5` | `v5.0.12` | HTTP router for all API and UI endpoints | MIT |
| `github.com/go-pdf/fpdf` | `v0.9.0` | Fallback PDF renderer (used when Chromium sidecar is unavailable) | MIT |
| `github.com/golang-jwt/jwt/v5` | `v5.2.1` | JWT creation and validation (HS256) | MIT |
| `github.com/gorilla/websocket` | `v1.5.3` | WebSocket server for agent C2 channel | BSD-2-Clause |
| `github.com/jackc/pgx/v5` | `v5.6.0` | PostgreSQL driver (connection pool, queries, migrations) | MIT |
| `golang.org/x/crypto` | `v0.24.0` | PBKDF2-HMAC-SHA256 password hashing | BSD-3-Clause |
| `gopkg.in/yaml.v3` | `v3.0.1` | Scenario YAML parsing | MIT |

---

### 2.3 Orchestrator — Go Libraries (Indirect)

Transitive dependencies. Hashes for all are recorded in `orchestrator/go.sum`. Licenses should be independently verified against each package's own `LICENSE` file for formal legal review.

| Package | Version | Pulled In By | License |
|---|---|---|---|
| `github.com/chromedp/sysutil` | `v1.1.0` | chromedp | MIT |
| `github.com/go-json-experiment/json` | `20260214004413-d219187c3433` | chromedp | BSD-3-Clause |
| `github.com/gobwas/httphead` | `v0.1.0` | gobwas/ws | MIT |
| `github.com/gobwas/pool` | `v0.2.1` | gobwas/ws | MIT |
| `github.com/gobwas/ws` | `v1.4.0` | gorilla/websocket (via chromedp) | MIT |
| `github.com/jackc/pgpassfile` | `v1.0.0` | jackc/pgx | MIT |
| `github.com/jackc/pgservicefile` | `20221227161230-091c0ba34f0a` | jackc/pgx | MIT |
| `github.com/jackc/puddle/v2` | `v2.2.1` | jackc/pgx | MIT |
| `github.com/kr/text` | `v0.2.0` | testing deps | MIT |
| `github.com/rogpeppe/go-internal` | `v1.14.1` | testing deps | BSD-3-Clause |
| `golang.org/x/sync` | `v0.7.0` | pgx / chromedp | BSD-3-Clause |
| `golang.org/x/sys` | `v0.42.0` | chromedp/sysutil | BSD-3-Clause |
| `golang.org/x/text` | `v0.16.0` | pgx / text encoding | BSD-3-Clause |

---

### 2.4 Agent — Go Libraries

**Source:** `agent/go.mod` · Module: `audspect/agent` · Go version: `1.26`

| Package | Version | Role | License | Type |
|---|---|---|---|---|
| `github.com/gorilla/websocket` | `v1.5.3` | Agent-to-orchestrator C2 WebSocket channel | BSD-2-Clause | Direct |
| `github.com/jchv/go-webview2` | `20260205173254-56598839c808` | WebView2 bindings — status console window on Windows | MIT | Direct |
| `golang.org/x/sys` | `v0.45.0` | OS syscall interface (Windows API, Linux signals) | BSD-3-Clause | Direct |
| `github.com/jchv/go-winloader` | `20250406163304-c1995be93bd1` | Windows DLL loader (required by go-webview2) | MIT | Indirect |

---

### 2.5 Installer — Go Libraries

**Source:** `installer/go.mod` · Module: `audspect/installer` · Go version: `1.25`

| Package | Version | Role | License | Type |
|---|---|---|---|---|
| `golang.org/x/sys` | `v0.45.0` | Windows API calls for installer file operations and registry access | BSD-3-Clause | Direct |

---

### 2.6 API Service — Python Libraries

**Source:** `api/requirements.txt` · Runtime: Python 3.12 (`python:3.12-slim`)

| Package | Version | Role | License |
|---|---|---|---|
| `fastapi` | `0.115.0` | ASGI web framework — REST API routes | MIT |
| `uvicorn[standard]` | `0.30.6` | ASGI server | BSD-3-Clause |
| `sqlalchemy[asyncio]` | `2.0.35` | ORM / async database abstraction | MIT |
| `asyncpg` | `0.29.0` | Async PostgreSQL driver | Apache 2.0 |
| `pydantic` | `2.9.2` | Data validation and schema serialisation | MIT |
| `pydantic-settings` | `2.5.2` | Settings management from environment variables | MIT |
| `python-jose[cryptography]` | `3.3.0` | JWT implementation (HS256 / RS256) | MIT |
| `passlib[bcrypt]` | `1.7.4` | Password hashing — bcrypt | BSD-2-Clause |
| `httpx` | `0.27.2` | Async HTTP client | BSD-3-Clause |
| `python-multipart` | `0.0.12` | Multipart form data parsing | Apache 2.0 |
| `weasyprint` | `62.3` | HTML→PDF renderer (Python-side fallback) | BSD-3-Clause |
| `jinja2` | `3.1.4` | HTML templating | BSD-3-Clause |

---

### 2.7 Container Base Images

> ⚠️ **Supply-Chain Risk:** Three images are pinned by floating tag, not by digest. A rebuild may silently pull a different image. See **GAP-01** and **GAP-02**.

| Image | Tag | Role | Shipped in Runtime? | Pin Status |
|---|---|---|---|---|
| `postgres` | `16-alpine` | PostgreSQL 16.x — primary data store | Yes | Tag only — not pinned to digest |
| `chromedp/headless-shell` | `latest` | Headless Chromium — HTML→PDF sidecar | Yes | ⚠️ Floating `:latest` |
| `ghcr.io/mitre/caldera` | `latest` | MITRE Caldera ATT&CK simulation engine (base for custom image) | Yes | ⚠️ Floating `:latest` |
| `gcr.io/distroless/static-debian12` | (default) | Orchestrator production runtime — no shell, no package manager | Yes | Tag only — not pinned to digest |
| `golang` | `1.26-alpine` | Build stage for orchestrator and agent binaries | No (build only) | Tag only |
| `debian` | `bookworm-slim` | Build stage for .deb / .rpm agent packages | No (build only) | Tag only |
| `alpine` | `latest` | ART sparse-clone and CISA KEV fetch stage | No (build only) | ⚠️ Floating `:latest` (build only) |

---

### 2.8 Bundled Third-Party Data

All datasets below are fetched at Docker build time and baked into the orchestrator image. They are not pulled at runtime — the product ships fully air-gappable.

| Dataset | Version / Snapshot | Source | Fetch Method | License |
|---|---|---|---|---|
| MITRE ATT&CK Enterprise STIX | **v16.1 (Oct 2024) — pinned** | `mitre-attack/attack-stix-data` (GitHub) | Build-time `curl`; distilled to compact JSON embedded in binary. Pinned to v16.1 — v17 removed inline data fields this tool reads. | CC BY 4.0 |
| CISA Known Exploited Vulnerabilities (KEV) | Snapshot at build time — not pinned | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Build-time `curl`; baked into image as `/content/cisa-kev.json`. Build fails loudly if file is absent or empty. | Public Domain (US Federal Government) |
| Atomic Red Team (ART) YAMLs | `master` HEAD at build — not pinned | `redcanaryco/atomic-red-team` (GitHub) | Sparse clone (`--depth 1`) at Docker build — YAML technique files only, no binary payloads | MIT |
| CTID Adversary Emulation Library | Depth-1 HEAD at Caldera image build | `center-for-threat-informed-defense/adversary_emulation_library` (GitHub) | `git clone --depth 1` during `bas-caldera` Docker image build; commit SHA logged to build output | Apache 2.0 |

---

### 2.9 Build-Time Tools (Not Shipped)

These tools run during the build process on the internet-connected Windows build host or inside Docker build stages. None are included in the shipped product or runtime containers.

| Tool | Version | Purpose |
|---|---|---|
| `mvdan.cc/garble` | `latest` at build time | Orchestrator binary obfuscation — renames identifiers and encrypts string literals for proprietary application code only. Third-party libraries are excluded. |
| Git | Host version | ART YAML sparse-clone and CTID adversary-emulation-library clone inside Docker build stages |
| Docker / Docker Compose | Host version | Multi-stage image builds and compose-based deployment |
| `sha256sum` (coreutils) | Linux distro version | Generates `BINARIES.sha256` manifest from the five agent binaries compiled in the same build layer |
| OpenSSL | Host version | `JWT_SECRET` and `AGENT_SECRET` random generation during `install.sh` — `openssl rand -base64 48` |
| GPG | Host version | RSA-4096 key pair management; signs scenario YAML files and the `BINARIES.sha256` manifest |
| PowerShell 5.1 | Windows host | `windows-build.ps1` — orchestrates signing, Docker build, and bundle packaging |

---

## 3. Cryptographic Bill of Materials (CBOM)

### 3.1 Algorithm Inventory Summary

| Algorithm | Purpose | Key / Output Size | Standard | Status |
|---|---|---|---|---|
| PBKDF2-HMAC-SHA256 | User password hashing (orchestrator) | 256-bit DK · 256-bit salt · 310,000 iterations | NIST SP 800-132 | ✅ Active — FIPS 140-3 approved |
| HMAC-SHA256 (HS256) | JWT session token signing | Operator key (≥ 256 bit recommended) | RFC 7518 | ✅ Active |
| HMAC-SHA256 | Agent result-submission MAC (`X-Result-MAC`) | Operator-supplied `AGENT_SECRET` | RFC 2104 | ⚠️ Active — optional (unenforced by default) |
| RSA-4096 / PKCS#1 v1.5 + SHA-256 | Scenario YAML & binary manifest signing | 4096-bit RSA key pair | PKCS#1 v1.5 | ⚠️ Active — PSS preferred over v1.5 |
| SHA-256 | Binary integrity manifest (`BINARIES.sha256`) | 256-bit digest per file | NIST FIPS 180-4 | ✅ Active |
| SHA-256 | UI asset integrity (`wwwroot/index.html`) | 256-bit digest | NIST FIPS 180-4 | ✅ Active |
| bcrypt | User password hashing (Python API service) | Variable cost factor | — | ✅ Active (API service only) |
| OS CSPRNG (`crypto/rand`) | Salt generation, random secrets | Arbitrary length | NIST SP 800-90A | ✅ Active |

---

### 3.2 Password Hashing — PBKDF2-HMAC-SHA256

**Applies to:** Orchestrator service only. Python API uses bcrypt (§ 3.11).

| Parameter | Value |
|---|---|
| Algorithm | PBKDF2-HMAC-SHA256 |
| Implementation library | `golang.org/x/crypto/pbkdf2` v0.24.0 |
| Supporting Go stdlib | `crypto/sha256`, `crypto/subtle`, `crypto/rand` |
| Iterations (default) | `310,000` |
| Minimum iterations enforced | `310,000` — NIST SP 800-132 minimum for PBKDF2-HMAC-SHA256 (2023 guidance) |
| Derived key length | 32 bytes (256 bits) |
| Salt length | 32 bytes (256 bits) — generated per-hash from `crypto/rand` |
| Storage format | `$pbkdf2-sha256$<iterations>$<base64-salt>$<base64-dk>` |
| Comparison method | Constant-time — `crypto/subtle.ConstantTimeCompare` |
| Rehash on login | **Yes** — iteration count is embedded in the stored hash; login triggers transparent re-hash when stored count < current default |
| Crypto self-test at startup | SHA-256 KAT · HMAC-SHA256 · RSA-2048 sign/verify · PBKDF2-HMAC-SHA256 · `crypto/rand` entropy · constant-time compare |
| FIPS 140-3 | Approved algorithm family |

---

### 3.3 Session Tokens — JWT HS256

| Parameter | Value |
|---|---|
| Algorithm | HMAC-SHA256 (HS256) |
| Implementation library | `github.com/golang-jwt/jwt/v5` v5.2.1 |
| Key material | `JWT_SECRET` environment variable — generated at install time via `openssl rand -base64 48` (≥ 288 bits entropy) |
| Claims included | `user_id`, `role`, `exp`, `iat`, `sub` |
| Algorithm enforcement | Signing method is type-asserted as `*jwt.SigningMethodHMAC` on validation — non-HMAC tokens are rejected |
| Key rotation | ⚠️ No rotation mechanism — changing `JWT_SECRET` invalidates all active sessions. See **GAP-07**. |

---

### 3.4 Agent Authentication — HMAC-SHA256

| Parameter | Value |
|---|---|
| Algorithm | HMAC-SHA256 |
| Implementation | Go stdlib `crypto/hmac` + `crypto/sha256` |
| Key material | `AGENT_SECRET` environment variable — optional; generated at install or operator-supplied |
| Transport | `X-Result-MAC` HTTP request header on agent result submission; hex-encoded HMAC of the request body |
| Comparison method | `hmac.Equal` — constant-time |
| When `AGENT_SECRET` is unset | ⚠️ **MAC enforcement is DISABLED** — all result submissions are accepted without MAC verification. See **GAP-08**. |

---

### 3.5 Scenario & Manifest Signing — RSA-4096

| Parameter | Value |
|---|---|
| Algorithm | RSA-4096 / PKCS#1 v1.5 + SHA-256 |
| Implementation | Go stdlib `crypto/rsa` (`rsa.VerifyPKCS1v15`) + `crypto/sha256` + `crypto/x509` |
| Signing scheme | PKCS#1 v1.5 — ⚠️ RSA-PSS is preferred over v1.5 for new deployments. See **GAP-04**. |
| Key size | RSA-4096 |
| Private key location | Windows build host GPG keyring |
| Private key protection | ⚠️ **No passphrase set on the GPG key.** See **GAP-05**. |
| Key expiry | `2029-06-04` |
| Public key storage | Embedded as PEM constant `ScenarioPublicKeyPEM` in orchestrator binary (`orchestrator/internal/integrity/signing.go`) |
| Scope | All scenario YAML files and the `BINARIES.sha256` manifest — signed at build time |
| Verification trigger | Scenario load at orchestrator startup; agent binary registration |

---

### 3.6 Binary Integrity — SHA-256 Manifest

| Parameter | Value |
|---|---|
| Algorithm | SHA-256 |
| Tool | `sha256sum` (Linux coreutils, inside Docker `agent-builder` build stage) |
| Manifest file | `BINARIES.sha256` — generated in the same build layer as the agent binaries; signed by the RSA-4096 key (§ 3.5) |
| Coverage | `bas-agent-linux-amd64` · `bas-agent-linux-arm64` · `bas-agent-windows-amd64.exe` · `bas-agent-darwin-amd64` · `bas-agent-darwin-arm64` |
| Verification point | Orchestrator verifies hash at agent registration; mismatch blocks enrollment |

---

### 3.7 UI Asset Integrity — SHA-256

| Parameter | Value |
|---|---|
| Algorithm | SHA-256 |
| Scope | `wwwroot/index.html` — all JavaScript and CSS is inlined, so this file covers the entire UI |
| Injection | Hash computed by `windows-build.ps1` and injected at Docker build time via `-ldflags "-X main.expectedWWWRootHash=<hash>"` |
| Verification trigger | Orchestrator startup — process halts on mismatch |
| Gap | `og/` subdirectory (legacy UI) is not independently hashed |

---

### 3.8 Cryptographic Randomness

| Source | Used By | Platform Mapping | Standard |
|---|---|---|---|
| `crypto/rand` (Go stdlib) | PBKDF2 salt generation (32 bytes per hash); crypto self-tests | `/dev/urandom` on Linux; `CryptGenRandom` on Windows | NIST SP 800-90A compliant OS CSPRNG |
| `openssl rand -base64 48` | `JWT_SECRET` and `AGENT_SECRET` generation during `install.sh` | OpenSSL on host OS | ≥ 288 bits entropy |

---

### 3.9 Database Transport

| Parameter | Value |
|---|---|
| Protocol | PostgreSQL wire protocol over TCP |
| Default TLS mode | `sslmode=prefer` — TLS is used when the server offers it, but plaintext is accepted if TLS is unavailable |
| Enforcement | ⚠️ Not enforced by default — `sslmode=require` or `sslmode=verify-full` with `PGSSLROOTCERT` recommended for production. See **GAP-06**. |
| Server TLS capability | `postgres:16-alpine` supports TLS; requires operator-supplied certificate and key |
| Driver | `github.com/jackc/pgx/v5` v5.6.0 (orchestrator) · `asyncpg` v0.29.0 (Python API) |

---

### 3.10 Orchestrator API Transport

| Parameter | Value |
|---|---|
| Protocol | Plain HTTP — `http.ListenAndServe` on port `9443` |
| TLS | Not provided by orchestrator — TLS termination must be added by the operator via a reverse proxy (nginx, Caddy, HAProxy). See **GAP-09**. |
| Agent C2 channel | WebSocket (`ws://`) over the same HTTP connection — encrypted only when the reverse proxy enforces `wss://` |

---

### 3.11 API Service Cryptography (Python)

| Algorithm / Primitive | Purpose | Library | Notes |
|---|---|---|---|
| bcrypt | User password hashing | `passlib[bcrypt]` v1.7.4 | Cost factor at passlib default; configurable |
| HMAC-SHA256 / RS256 | JWT creation and validation | `python-jose[cryptography]` v3.3.0 | HS256 is the default; RS256 requires operator key configuration |

---

## 4. Compliance Alignment

This mapping is informational. Formal compliance determination requires an authorised audit.

| Framework | Clause / Domain | How This Document Assists |
|---|---|---|
| SEBI CSCRF | Clause 5.3 — Supply Chain Risk Management | SBOM provides the component and third-party dependency inventory required under supply-chain risk controls. CBOM supports algorithm disclosure. |
| RBI Cyber Security Framework | Domain 4 — Data Protection; Annex III | CBOM documents all cryptographic algorithms and key management practices; supports RBI encryption adequacy assessment. |
| CERT-In Directions 2022 | Section 25(xxv) — Software Inventory & Audit Trail | SBOM fulfils the software inventory disclosure requirement. Component versions and build hashes support audit trail reconstruction. |
| IRDAI Cyber Security Guidelines | Guideline 8 — Third-Party Risk | Third-party library and container image inventory (§ 2.2–2.7) provides dependency disclosure required for insurer and regulator review. |
| NIST CSF 2.0 | GV.SC-06 — Supply Chain; ID.AM-02 — Asset Management | SBOM satisfies software component identification and inventory requirements. |
| NIST SP 800-132 | Password-Based Key Derivation | PBKDF2-HMAC-SHA256 at 310,000 iterations meets the 2023 NIST minimum iteration count recommendation. |
| DPDP Act 2023 (India) | Section 8 — Data Fiduciary Obligations | CBOM documents encryption and integrity mechanisms protecting personal data at rest (password hashes) and in transit (TLS posture documented in § 3.9). |

---

> **Disclaimer:** This document reflects the state of the software at version 1.7.3 as of 3 July 2026. Component versions and algorithms may change between releases. Customers should request an updated SBOM & CBOM for each new major or minor release. Licenses are based on well-established knowledge of each package and should be independently verified against each package's own `LICENSE` file in the event of formal legal review.

---

*Audspect BAS v1.7.3 — SBOM & CBOM · Classification: CONFIDENTIAL — Restricted Distribution*
