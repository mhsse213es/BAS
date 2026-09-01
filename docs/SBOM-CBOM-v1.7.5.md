# Software Bill of Materials & Cryptographic Bill of Materials

**Product:** Audspect BAS (Breach & Attack Simulation Platform)

**Version:** 1.7.5

**Document Date:** 14 August 2026

**Document Revision:** 2.0 — Updated for v1.7.5 (supersedes Revision 1.0 / v1.7.3, dated 3 July 2026)

**Prepared By:** Audspect 

**Classification:** CONFIDENTIAL — Restricted Distribution — Authorised Recipients Only

**Standard Referenced:** NTIA Minimum Elements for SBOM · Structured to align with the CycloneDX v1.4 data model · Includes PURL (ECMA-376), CPE 2.3 (NIST NVD), and component hashes


> **Source of Truth:** All entries in this document are derived from direct inspection of the repository at the v1.7.5 build — specifically go.mod, go.sum, requirements.txt, Dockerfile(s), and docker-compose.yml — cross-checked against `go mod graph` for indirect-dependency attribution and against actual non-test source imports to distinguish production-shipped code from test/dev-tool-only tooling. Nothing has been inferred or guessed.

> **What changed since v1.7.3 (3 July 2026):** New Phase 7 SSO/OIDC feature (§2.2, §3.4) adds `coreos/go-oidc/v3`, `golang.org/x/oauth2`, and the transitively-shipped `go-jose/go-jose/v4`; tenant-aware JWT claims (§3.5); several dependency version bumps (§2.2, §2.3); the agent's WebView2 tray dependency was replaced with `rodrigocfd/windigo` (§2.4); `bas-caldera`'s `atomic` plugin is now enabled alongside `emu` (§2.1); and two build-process descriptions inherited from the v1.7.3 document are corrected (§2.8) to match actual current behaviour. A large test-only dependency tree (`testcontainers-go`, for Postgres-backed integration tests) was also added to `go.mod` — it is **not shipped** in any production artifact; see the dedicated callouts in §2.2 and §2.3.

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
   - 2.10 [Package URLs, CPE Identifiers, and Component Hashes](#210-package-urls-cpe-identifiers-and-component-hashes)
   - 2.11 [Dependency Relationships](#211-dependency-relationships)
3. [Cryptographic Bill of Materials (CBOM)](#3-cryptographic-bill-of-materials-cbom)
   - 3.1 [Algorithm Inventory Summary](#31-algorithm-inventory-summary)
   - 3.2 [Password Hashing — PBKDF2-HMAC-SHA256](#32-password-hashing--pbkdf2-hmac-sha256)
   - 3.3 [Session Tokens — JWT HS256](#33-session-tokens--jwt-hs256)
   - 3.4 [SSO Login — OIDC Discovery + OAuth2 Authorization Code + PKCE](#34-sso-login--oidc-discovery--oauth2-authorization-code--pkce)
   - 3.5 [Agent Authentication — HMAC-SHA256](#35-agent-authentication--hmac-sha256)
   - 3.6 [Scenario & Manifest Signing — RSA-4096](#36-scenario--manifest-signing--rsa-4096)
   - 3.7 [Binary Integrity — SHA-256 Manifest](#37-binary-integrity--sha-256-manifest)
   - 3.8 [UI Asset Integrity — SHA-256](#38-ui-asset-integrity--sha-256)
   - 3.9 [Cryptographic Randomness](#39-cryptographic-randomness)
   - 3.10 [Database Transport](#310-database-transport)
   - 3.11 [Orchestrator API Transport](#311-orchestrator-api-transport)
   - 3.12 [API Service Cryptography (Python)](#312-api-service-cryptography-python)
4. [Compliance Alignment](#4-compliance-alignment)

---

## 1. Document Information

### Purpose

This document provides a complete inventory of all software components (SBOM) and cryptographic algorithms and primitives (CBOM) used in Audspect BAS v1.7.5. It is intended for use by procurement personnel, security review teams, and regulatory audit bodies.

### Scope

- Orchestrator service (Go 1.26, Linux amd64, garble-obfuscated) — including the new Phase 7 SSO/OIDC identity-federation slice
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
| Version | `1.7.5` |
| Document Revision | 2.0 — Updated for v1.7.5 |
| Document Date | 14 August 2026 |
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
| `bas-agent-windows-amd64.exe` | Go 1.26 | Windows amd64 | `go build -trimpath -s -w` | Windows 10+ | CGO_ENABLED=0; native Win32 tray UI via `windigo` (§2.4) — the tray executable no longer embeds a WebView2 browser control; the status console opens in the system default browser instead |
| `bas-agent-darwin-amd64` | Go 1.26 | macOS amd64 (Intel) | `go build -trimpath -s -w` | macOS 12+ | CGO_ENABLED=0; fully static |
| `bas-agent-darwin-arm64` | Go 1.26 | macOS arm64 (Apple Silicon) | `go build -trimpath -s -w` | macOS 12+ | CGO_ENABLED=0; fully static |
| `bas-agent-windows-amd64-setup.exe` | Go 1.26 | Windows amd64 | `go build -H windowsgui -trimpath -s -w` | Windows 10+ | GUI installer; embeds agent binary. **Corrected from v1.7.3:** no longer bundles the WebView2 Evergreen runtime — that dependency was removed with the WebView2 tray UI (§2.4). |
| API Service | Python 3.12 | Linux (Docker) | `pip install -r requirements.txt` | `python:3.12-slim` | FastAPI + Uvicorn; separate deployment — not in standard install bundle |
| `bas-caldera` | Python (MITRE Caldera) | Linux (Docker) | Custom Dockerfile from `ghcr.io/mitre/caldera:latest` | Docker container | CTID adversary-emulation-library baked in. **Corrected from v1.7.3:** the `atomic` plugin (Atomic Red Team abilities) is now enabled alongside `emu`, raising the total ability catalog from ~2,200 to ~3,500–5,000+ (overlap with `emu` and the standalone ART library is expected; the dashboard deduplicates at the unique-technique level, not raw ability count). Base image remains `ghcr.io/mitre/caldera:latest` — **not pinned to a digest**, contrary to the v1.7.3 document; it is rebuilt on the internet-connected Windows build host per release. |

---

### 2.2 Orchestrator — Go Libraries (Direct)

**Source:** `orchestrator/go.mod` · Module: Audspect BAS Orchestrator · Go version: `1.26`

| Package | Version | Role | License |
|---|---|---|---|
| `github.com/chromedp/cdproto` | `20260321001828-e3e3800016bc` | Chrome DevTools Protocol types & client | MIT |
| `github.com/chromedp/chromedp` | `v0.15.1` | Headless Chrome automation for HTML→PDF rendering | MIT |
| `github.com/coreos/go-oidc/v3` | `v3.20.0` | **New (v1.7.5, Phase 7 SSO).** OIDC discovery + ID token verification for SSO login | Apache 2.0 |
| `github.com/go-chi/chi/v5` | `v5.0.12` | HTTP router for all API and UI endpoints | MIT |
| `github.com/go-pdf/fpdf` | `v0.9.0` | Fallback PDF renderer (used when Chromium sidecar is unavailable) | MIT |
| `github.com/golang-jwt/jwt/v5` | `v5.2.1` | JWT creation and validation — session tokens (HS256, §3.3) and SSO state tokens (HS256, §3.4) | MIT |
| `github.com/gorilla/websocket` | `v1.5.3` | WebSocket server for agent C2 channel | BSD-2-Clause |
| `github.com/jackc/pgx/v5` | `v5.9.2` | PostgreSQL driver (connection pool, queries, migrations). **Bumped from v5.6.0.** | MIT |
| `golang.org/x/crypto` | `v0.51.0` | PBKDF2-HMAC-SHA256 password hashing. **Bumped from v0.24.0.** | BSD-3-Clause |
| `golang.org/x/oauth2` | `v0.36.0` | **New (v1.7.5, Phase 7 SSO).** OAuth2 Authorization Code + PKCE exchange for SSO login | BSD-3-Clause |
| `gopkg.in/yaml.v3` | `v3.0.1` | Scenario YAML parsing | MIT |

> **Not shown above — test/dev-tool-only direct requires.** `go.mod`'s single `require` block does not distinguish production dependencies from test-only ones; the following appear as **direct** requires but are verified (by grepping actual imports outside `_test.go` files) to be used only by test infrastructure or standalone dev-tool binaries, never by the shipped `cmd/server` production binary:
>
> | Package | Version | Actual Role | Shipped in `bas-orchestrator`? |
> |---|---|---|---|
> | `github.com/testcontainers/testcontainers-go` | `v0.43.0` | Spins up ephemeral Postgres containers for Go integration tests (`internal/testutil/testdb.go`) | **No** |
> | `github.com/testcontainers/testcontainers-go/modules/postgres` | `v0.43.0` | Postgres module for the above | **No** |
> | `golang.org/x/tools` | `v0.48.0` | `cover` package parsing, used only by the standalone `scripts/coveragesummary` dev-tool binary (not built by the production Dockerfile, which builds only `./cmd/server`) | **No** |
>
> These three packages pull in a large transitive tree (Docker/Moby client libraries, OpenTelemetry, `testify`, etc.) — see the "Test-only indirect" callout in §2.3. None of it reaches the `cmd/server` build target.

---

### 2.3 Orchestrator — Go Libraries (Indirect)

Transitive dependencies. Hashes for all are recorded in `orchestrator/go.sum`. Licenses should be independently verified against each package's own `LICENSE` file for formal legal review. Attribution below is verified via `go mod graph` (which parent module(s) pull in each package).

| Package | Version | Pulled In By | License |
|---|---|---|---|
| `github.com/chromedp/sysutil` | `v1.1.0` | chromedp | MIT |
| `github.com/go-json-experiment/json` | `20260214004413-d219187c3433` | chromedp | BSD-3-Clause |
| `github.com/go-jose/go-jose/v4` | `v4.1.4` | `coreos/go-oidc` — performs JWS signature verification on OIDC ID tokens (§3.4). **New (v1.7.5).** | Apache 2.0 |
| `github.com/gobwas/httphead` | `v0.1.0` | gobwas/ws | MIT |
| `github.com/gobwas/pool` | `v0.2.1` | gobwas/ws | MIT |
| `github.com/gobwas/ws` | `v1.4.0` | gorilla/websocket (via chromedp) | MIT |
| `github.com/jackc/pgpassfile` | `v1.0.0` | jackc/pgx | MIT |
| `github.com/jackc/pgservicefile` | `20240606120523-5a60cdf6a761` | jackc/pgx. **Bumped from `20221227161230-091c0ba34f0a`.** | MIT |
| `github.com/jackc/puddle/v2` | `v2.2.2` | jackc/pgx. **Bumped from v2.2.1.** | MIT |
| `golang.org/x/sync` | `v0.22.0` | pgx / chromedp. **Bumped from v0.7.0.** | BSD-3-Clause |
| `golang.org/x/sys` | `v0.47.0` | chromedp / golang.org/x/crypto. **Bumped from v0.42.0.** | BSD-3-Clause |
| `golang.org/x/text` | `v0.37.0` | pgx / golang.org/x/crypto. **Bumped from v0.16.0.** | BSD-3-Clause |
| `golang.org/x/time` | `v0.15.0` | direct import in `internal/api/ratelimit.go` (API rate limiting) — surfaced explicitly in `go.mod`'s indirect block for the first time in this revision | BSD-3-Clause |
| `github.com/kr/text` | `v0.2.0` | testing deps | MIT |
| `github.com/rogpeppe/go-internal` | `v1.14.1` | testing deps | BSD-3-Clause |

> **Test-only indirect (not shipped in binary) — `testcontainers-go` dependency tree.** Verified via `go mod graph`: every package below is reachable **only** from `testcontainers-go` / `testcontainers-go/modules/postgres` (a few also from `golang.org/x/tools`, itself dev-tool-only — see §2.2). None reaches the `cmd/server` production build target.
>
> `dario.cat/mergo` · `github.com/Azure/go-ansiterm` · `github.com/Microsoft/go-winio` · `github.com/cenkalti/backoff/v4` · `github.com/cespare/xxhash/v2` · `github.com/containerd/errdefs` · `github.com/containerd/errdefs/pkg` · `github.com/containerd/log` · `github.com/containerd/platforms` · `github.com/cpuguy83/dockercfg` · `github.com/davecgh/go-spew` · `github.com/distribution/reference` · `github.com/docker/go-connections` · `github.com/docker/go-units` · `github.com/ebitengine/purego` · `github.com/felixge/httpsnoop` · `github.com/go-logr/logr` · `github.com/go-logr/stdr` · `github.com/go-ole/go-ole` · `github.com/google/uuid` · `github.com/klauspost/compress` · `github.com/lufia/plan9stats` · `github.com/magiconair/properties` · `github.com/moby/docker-image-spec` · `github.com/moby/go-archive` · `github.com/moby/moby/api` · `github.com/moby/moby/client` · `github.com/moby/patternmatcher` · `github.com/moby/sys/sequential` · `github.com/moby/sys/user` · `github.com/moby/sys/userns` · `github.com/moby/term` · `github.com/opencontainers/go-digest` · `github.com/opencontainers/image-spec` · `github.com/pmezard/go-difflib` · `github.com/power-devops/perfstat` · `github.com/shirou/gopsutil/v4` · `github.com/sirupsen/logrus` · `github.com/stretchr/testify` · `github.com/tklauser/go-sysconf` · `github.com/tklauser/numcpus` · `github.com/yusufpapurcu/wmi` · `go.opentelemetry.io/auto/sdk` · `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` · `go.opentelemetry.io/otel` · `go.opentelemetry.io/otel/metric` · `go.opentelemetry.io/otel/trace`
>
> Exact pinned versions and `go.sum` hashes for each are available in `orchestrator/go.sum`; they are omitted from the individual PURL/CPE/hash table in §2.10 as out of scope for a production-runtime SBOM, consistent with NTIA guidance that test-only tooling need not be enumerated at the same fidelity as shipped components.

---

### 2.4 Agent — Go Libraries

**Source:** `agent/go.mod` · Module: `audspect/agent` · Go version: `1.26`

| Package | Version | Role | License | Type |
|---|---|---|---|---|
| `github.com/gorilla/websocket` | `v1.5.3` | Agent-to-orchestrator C2 WebSocket channel | BSD-2-Clause | Direct |
| `golang.org/x/sys` | `v0.45.0` | OS syscall interface (Windows API, Linux signals) | BSD-3-Clause | Direct |
| `github.com/rodrigocfd/windigo` | `v0.2.6` | **New (v1.7.5) — replaces `go-webview2`/`go-winloader`, both removed.** Native Win32 API bindings for the tray icon and status window (`browserwindow_windows.go`, `logo_windows.go`, `statuscanvas_windows.go`, `statuswindow_windows.go`, `tray_windows.go`). The status console itself now opens in the system default browser rather than an embedded WebView2 control. **Note:** `agent/go.mod` marks this `// indirect` (stale — `go mod tidy` has not been re-run since the direct import was added); direct source inspection confirms it is imported directly by five agent source files, so it is listed here as Direct. | MIT | Direct *(per source; `go.mod` comment is stale)* |

**Removed since v1.7.3:** `github.com/jchv/go-webview2` and `github.com/jchv/go-winloader` (WebView2 bindings and its Windows DLL loader) are no longer dependencies — confirmed absent from the current `agent/go.mod`.

---

### 2.5 Installer — Go Libraries

**Source:** `installer/go.mod` · Module: `audspect/installer` · Go version: `1.26` (build toolchain: `golang:1.26-alpine`; go.mod minimum compatibility: `1.25`)

| Package | Version | Role | License | Type |
|---|---|---|---|---|
| `golang.org/x/sys` | `v0.45.0` | Windows API calls for installer file operations and registry access | BSD-3-Clause | Direct |

*Unchanged since v1.7.3.*

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

*Unchanged since v1.7.3 — confirmed byte-for-byte identical against `api/requirements.txt`.*

---

### 2.7 Container Base Images

> **Note:** Images listed with a floating tag should be pinned to a digest for production deployments. Pin status is shown in the table below.

| Image | Tag | Role | Shipped in Runtime? | Pin Status |
|---|---|---|---|---|
| `postgres` | `16-alpine` | PostgreSQL 16.x — primary data store | Yes | Tag only — not pinned to digest |
| `chromedp/headless-shell` | `latest` | Headless Chromium — HTML→PDF sidecar | Yes | ⚠️ Floating `:latest` |
| `ghcr.io/mitre/caldera` | `latest` | MITRE Caldera ATT&CK simulation engine (base for custom image) | Yes | ⚠️ Floating `:latest` |
| `gcr.io/distroless/static-debian12` | `latest` | Orchestrator production runtime — no shell, no package manager | Yes | ⚠️ Floating `:latest` |
| `golang` | `1.26-alpine` | Build stage for orchestrator and agent binaries | No (build only) | Tag only |
| `debian` | `bookworm-slim` | Build stage for .deb / .rpm agent packages | No (build only) | Tag only |
| `alpine` | `latest` | ART sparse-clone and CISA KEV fetch stage | No (build only) | ⚠️ Floating `:latest` (build only) |

*Unchanged since v1.7.3 — re-confirmed against `orchestrator/Dockerfile`, `packaging/caldera/Dockerfile`, and `packaging/compose/docker-compose.yml`.*

---

### 2.8 Bundled Third-Party Data

All datasets below are baked into the orchestrator (or `bas-caldera`) image so the product ships fully air-gappable. They are not pulled at runtime.

| Dataset | Version / Snapshot | Source | Fetch Method | License |
|---|---|---|---|---|
| MITRE ATT&CK Enterprise STIX | **v16.1 (Oct 2024) — pinned** | `mitre-attack/attack-stix-data` (GitHub) | **Corrected from v1.7.3.** Not a Docker-build-time `curl` — the raw STIX bundle is fetched once, manually, by a developer (`curl -L -o enterprise-attack-16.1.json ...`) and processed offline by `orchestrator/internal/reporting/attackdata/gen`, an internal dev tool that distills it to compact JSON. The generated JSON files are committed to the repository and embedded into the binary via `go:embed` at build time — no network access is needed during the Docker build itself. Pinned to v16.1: v17 removed the inline data fields this tool reads (enforced by a code comment in `gen/main.go`). | CC BY 4.0 |
| CISA Known Exploited Vulnerabilities (KEV) | Snapshot at build time — not pinned | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Build-time `curl` (Docker `art-fetcher` stage, `orchestrator/Dockerfile`); baked into image as `/content/cisa-kev.json`. Build fails loudly if file is absent or empty. | Public Domain (US Federal Government) |
| Atomic Red Team (ART) YAMLs | `master` HEAD at build — not pinned | `redcanaryco/atomic-red-team` (GitHub) | Sparse, blob-filtered clone at Docker build time (`git sparse-checkout` + `git fetch --depth=1 --filter=blob:none`) — YAML technique files only, no binary payloads | MIT |
| CTID Adversary Emulation Library | Depth-1 HEAD at Caldera image build | `center-for-threat-informed-defense/adversary_emulation_library` (GitHub) | `git clone --depth 1` during `bas-caldera` Docker image build; commit SHA logged to build output; `.git` removed after logging | Apache 2.0 |

---

### 2.9 Build-Time Tools (Not Shipped)

These tools run during the build process on the internet-connected Windows build host or inside Docker build stages. None are included in the shipped product or runtime containers.

| Tool | Version | Purpose |
|---|---|---|
| `mvdan.cc/garble` | `latest` at build time | Orchestrator binary obfuscation — renames identifiers and encrypts string literals for proprietary application code only. Third-party libraries are excluded. |
| `orchestrator/internal/reporting/attackdata/gen` | In-repo Go tool | **Documented for the first time in this revision.** Offline, developer-run — converts a manually-fetched MITRE ATT&CK STIX bundle (§2.8) into committed, `go:embed`-able JSON. Not run automatically at Docker build time. |
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
| HMAC-SHA256 (HS256) | JWT session token signing; SSO state-token signing (§3.4) | Operator key (≥ 256 bit recommended) | RFC 7518 | ✅ Active |
| SHA-256 / S256 PKCE code challenge | SSO login — binds the OAuth2 Authorization Code exchange to the browser that started it | 256-bit digest, base64url-encoded | RFC 7636 | ✅ Active — new in v1.7.5 |
| JWS signature verification (RS256/ES256, per-IdP) | SSO — OIDC ID token verification against the IdP's published JWKS | Per IdP's published key | RFC 7515 / OpenID Connect Core 1.0 | ✅ Active — new in v1.7.5 |
| HMAC-SHA256 | Agent result-submission MAC (`X-Result-MAC`) | Operator-supplied `AGENT_SECRET` | RFC 2104 | ⚠️ Active — optional (unenforced by default) |
| RSA-4096 / PKCS#1 v1.5 + SHA-256 | Scenario YAML & binary manifest signing | 4096-bit RSA key pair | PKCS#1 v1.5 | ⚠️ Active — PSS preferred over v1.5 |
| SHA-256 | Binary integrity manifest (`BINARIES.sha256`) | 256-bit digest per file | NIST FIPS 180-4 | ✅ Active |
| SHA-256 | UI asset integrity (`wwwroot/index.html`) | 256-bit digest | NIST FIPS 180-4 | ✅ Active |
| bcrypt | User password hashing (Python API service) | Variable cost factor | — | ✅ Active (API service only) |
| OS CSPRNG (`crypto/rand`) | Salt generation, random secrets, PKCE verifier generation | Arbitrary length | NIST SP 800-90A | ✅ Active |

---

### 3.2 Password Hashing — PBKDF2-HMAC-SHA256

**Applies to:** Orchestrator service only. Python API uses bcrypt (§3.12).

| Parameter | Value |
|---|---|
| Algorithm | PBKDF2-HMAC-SHA256 |
| Implementation library | `golang.org/x/crypto/pbkdf2` v0.51.0 *(bumped from v0.24.0; PBKDF2 parameters below are unchanged by the version bump)* |
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
| Claims included | `user_id`, `role`, `exp`, `iat`, `sub`, and (**new in v1.7.5**, tenancy) `tenant_id` (nullable — omitted for platform admins) and `is_platform_admin` (bool, orthogonal to `role`: which tenant scope, vs. what permission level within it) |
| Algorithm enforcement | Signing method is type-asserted as `*jwt.SigningMethodHMAC` on validation — non-HMAC tokens are rejected |
| Key rotation | Rotate by updating `JWT_SECRET` in `.env` and restarting the orchestrator; all active sessions are re-issued on next login |
| Related use — SSO state token | The same `golang-jwt/jwt/v5` HS256 mechanism, signed with the same `JWT_SECRET`, is reused for a second purpose in v1.7.5: a short-lived, tamper-evident "state" token (`internal/auth/sso_state.go`) that round-trips through the browser during SSO login, binding one login attempt to one tenant and one PKCE code verifier (§3.4). This is an additional *use* of the existing HS256 JWT primitive, not a new algorithm. |

---

### 3.4 SSO Login — OIDC Discovery + OAuth2 Authorization Code + PKCE

**New in v1.7.5 (Phase 7).** Not present in the v1.7.3 CBOM.

| Parameter | Value |
|---|---|
| Feature | Single Sign-On login via an operator-configured external Identity Provider (IdP) |
| Implementation package | `orchestrator/internal/oidcauth` |
| Libraries | `github.com/coreos/go-oidc/v3` v3.20.0 (OIDC discovery, ID token verification) · `golang.org/x/oauth2` v0.36.0 (OAuth2 Authorization Code exchange) · `github.com/go-jose/go-jose/v4` v4.1.4 (transitive, via go-oidc — performs the actual JWS signature verification on ID tokens) |
| Flow | OAuth2 Authorization Code with PKCE (RFC 7636) |
| PKCE code verifier | 32 random bytes from `crypto/rand`, base64url-encoded (`oidcauth.GeneratePKCE`) |
| PKCE code challenge | SHA-256 of the verifier, base64url-encoded, sent as `code_challenge` with `code_challenge_method=S256` in the initial authorization request |
| CSRF / tamper protection | The OAuth2 `state` parameter is itself a signed JWT (§3.3) carrying `tenant_id` and the raw PKCE code verifier; the state's threat model is tamper-evidence of the browser round-trip, not confidentiality — carrying the raw (not hashed) verifier inside a signed token is safe because the verifier must be presented in cleartext to the IdP at token-exchange time regardless |
| ID token verification | `oidc.Provider.Verifier` (from `coreos/go-oidc`, backed by `go-jose`) validates the ID token's JWS signature against the IdP's published JWKS, and its `aud`/`iss`/`exp` claims, before extracting the `email` claim used to resolve the local user |
| Key material | No static key managed by Audspect for this flow — verification keys are fetched dynamically from the IdP's published JWKS endpoint per OIDC discovery |
| Scope requested | `openid`, `email`, `profile` |

---

### 3.5 Agent Authentication — HMAC-SHA256

| Parameter | Value |
|---|---|
| Algorithm | HMAC-SHA256 |
| Implementation | Go stdlib `crypto/hmac` + `crypto/sha256` |
| Key material | `AGENT_SECRET` environment variable — optional; generated at install or operator-supplied |
| Transport | `X-Result-MAC` HTTP request header on agent result submission; hex-encoded HMAC of the request body |
| Comparison method | `hmac.Equal` — constant-time |
| When `AGENT_SECRET` is unset | MAC enforcement is disabled; set `AGENT_SECRET` in production to enforce result integrity |

---

### 3.6 Scenario & Manifest Signing — RSA-4096

| Parameter | Value |
|---|---|
| Algorithm | RSA-4096 / PKCS#1 v1.5 + SHA-256 |
| Implementation | Go stdlib `crypto/rsa` (`rsa.VerifyPKCS1v15`) + `crypto/sha256` + `crypto/x509` |
| Signing scheme | PKCS#1 v1.5 + SHA-256 (RSA-4096) |
| Key size | RSA-4096 |
| Private key location | Windows build host GPG keyring |
| Private key protection | GPG key protected; stored in secured build environment |
| Key expiry | `2029-06-04` |
| Public key storage | Embedded as PEM constant `ScenarioPublicKeyPEM` in orchestrator binary (`orchestrator/internal/integrity/signing.go`) |
| Scope | All scenario YAML files and the `BINARIES.sha256` manifest — signed at build time |
| Verification trigger | Scenario load at orchestrator startup; agent binary registration |

---

### 3.7 Binary Integrity — SHA-256 Manifest

| Parameter | Value |
|---|---|
| Algorithm | SHA-256 |
| Tool | `sha256sum` (Linux coreutils, inside Docker `agent-builder` build stage) |
| Manifest file | `BINARIES.sha256` — generated in the same build layer as the agent binaries; signed by the RSA-4096 key (§3.6) |
| Coverage | `bas-agent-linux-amd64` · `bas-agent-linux-arm64` · `bas-agent-windows-amd64.exe` · `bas-agent-darwin-amd64` · `bas-agent-darwin-arm64` |
| Verification point | Orchestrator verifies hash at agent registration; mismatch blocks enrollment |

---

### 3.8 UI Asset Integrity — SHA-256

| Parameter | Value |
|---|---|
| Algorithm | SHA-256 |
| Scope | `wwwroot/index.html` — all JavaScript and CSS is inlined, so this file covers the entire UI |
| Injection | Hash computed by `windows-build.ps1` and injected at Docker build time via `-ldflags "-X main.expectedWWWRootHash=<hash>"` |
| Verification trigger | Orchestrator startup — process halts on mismatch |
| Gap | `og/` subdirectory (legacy UI) is not independently hashed |

---

### 3.9 Cryptographic Randomness

| Source | Used By | Platform Mapping | Standard |
|---|---|---|---|
| `crypto/rand` (Go stdlib) | PBKDF2 salt generation (32 bytes per hash); crypto self-tests; PKCE code verifier generation (§3.4) | `/dev/urandom` on Linux; `CryptGenRandom` on Windows | NIST SP 800-90A compliant OS CSPRNG |
| `openssl rand -base64 48` | `JWT_SECRET` and `AGENT_SECRET` generation during `install.sh` | OpenSSL on host OS | ≥ 288 bits entropy |

---

### 3.10 Database Transport

| Parameter | Value |
|---|---|
| Protocol | PostgreSQL wire protocol over TCP |
| Default TLS mode | `sslmode=prefer` — TLS is used when the server offers it, but plaintext is accepted if TLS is unavailable |
| Enforcement | Production deployments should use `sslmode=require` or `sslmode=verify-full` with `PGSSLROOTCERT` |
| Server TLS capability | `postgres:16-alpine` supports TLS; requires operator-supplied certificate and key |
| Driver | `github.com/jackc/pgx/v5` v5.9.2 (orchestrator) · `asyncpg` v0.29.0 (Python API) |

---

### 3.11 Orchestrator API Transport

| Parameter | Value |
|---|---|
| Protocol | Plain HTTP — `http.ListenAndServe` on port `9443` |
| TLS | Not provided by the orchestrator process itself — TLS termination is handled by the operator's reverse proxy (nginx, Caddy, HAProxy) in front of port 9443 |
| Agent C2 channel | WebSocket (`ws://`) over the same HTTP connection — encrypted only when the reverse proxy enforces `wss://` |
| SSO IdP calls | OIDC discovery, JWKS fetch, and Authorization Code exchange (§3.4) are outbound HTTPS calls made by the orchestrator to the operator-configured IdP — TLS here is standard Go `net/http` client TLS to the IdP, independent of the inbound-traffic posture above |

---

### 3.12 API Service Cryptography (Python)

| Algorithm / Primitive | Purpose | Library | Notes |
|---|---|---|---|
| bcrypt | User password hashing | `passlib[bcrypt]` v1.7.4 | Cost factor at passlib default; configurable |
| HMAC-SHA256 / RS256 | JWT creation and validation | `python-jose[cryptography]` v3.3.0 | HS256 is the default; RS256 requires operator key configuration |

*Unchanged since v1.7.3.*

---

### 2.10 Package URLs, CPE Identifiers, and Component Hashes

PURL values follow the [Package URL specification](https://github.com/package-url/purl-spec). CPE 2.3 values follow the [NIST NVD](https://nvd.nist.gov/products/cpe) formatted binding. Hashes are the `h1:` (SHA-256 of the module zip tree) values recorded in `go.sum` / `agent/go.sum` / `installer/go.sum` — the canonical verification source for Go module integrity. Python package hashes are verified by pip during image build using the `--require-hashes` flag with values sourced from PyPI. Test/dev-tool-only packages (§2.2, §2.3) are intentionally omitted here — their hashes are in `orchestrator/go.sum` for anyone who needs them, but they carry no production supply-chain exposure.

#### Orchestrator — Go Libraries (Direct)

| Package | Version | PURL | CPE 2.3 | go.sum h1 Hash |
|---|---|---|---|---|
| `github.com/chromedp/cdproto` | `20260321001828-e3e3800016bc` | `pkg:golang/github.com/chromedp/cdproto@v0.0.0-20260321001828-e3e3800016bc` | `cpe:2.3:a:chromedp:cdproto:0.0.0-20260321001828-e3e3800016bc:*:*:*:*:*:*:*` | `h1:wkN/LMi5vc60pBRWx6qpbk/aEvq3/ZVNpnMvsw8PVVU=` |
| `github.com/chromedp/chromedp` | `v0.15.1` | `pkg:golang/github.com/chromedp/chromedp@v0.15.1` | `cpe:2.3:a:chromedp:chromedp:0.15.1:*:*:*:*:*:*:*` | `h1:EJWiPm7BNqDqjYy6U0lTSL5wNH+iNt9GjC3a4gfjNyQ=` |
| `github.com/coreos/go-oidc/v3` | `v3.20.0` | `pkg:golang/github.com/coreos/go-oidc/v3@v3.20.0` | `cpe:2.3:a:coreos:go-oidc:3.20.0:*:*:*:*:*:*:*` | `h1:EtE0WIBHk03N+DqGkY4+UONzzZHk7amKt6IyNd7OsZE=` |
| `github.com/go-chi/chi/v5` | `v5.0.12` | `pkg:golang/github.com/go-chi/chi@v5.0.12` | `cpe:2.3:a:go-chi:chi:5.0.12:*:*:*:*:*:*:*` | `h1:9euLV5sTrTNTRUU9POmDUvfxyj6LAABLUcEWO+JJb4s=` |
| `github.com/go-pdf/fpdf` | `v0.9.0` | `pkg:golang/github.com/go-pdf/fpdf@v0.9.0` | `cpe:2.3:a:go-pdf:fpdf:0.9.0:*:*:*:*:*:*:*` | `h1:PPvSaUuo1iMi9KkaAn90NuKi+P4gwMedWPHhj8YlJQw=` |
| `github.com/golang-jwt/jwt/v5` | `v5.2.1` | `pkg:golang/github.com/golang-jwt/jwt@v5.2.1` | `cpe:2.3:a:golang-jwt:jwt:5.2.1:*:*:*:*:*:*:*` | `h1:OuVbFODueb089Lh128TAcimifWaLhJwVflnrgM17wHk=` |
| `github.com/gorilla/websocket` | `v1.5.3` | `pkg:golang/github.com/gorilla/websocket@v1.5.3` | `cpe:2.3:a:gorilla:websocket:1.5.3:*:*:*:*:*:*:*` | `h1:saDtZ6Pbx/0u+bgYQ3q96pZgCzfhKXGPqt7kZ72aNNg=` |
| `github.com/jackc/pgx/v5` | `v5.9.2` | `pkg:golang/github.com/jackc/pgx@v5.9.2` | `cpe:2.3:a:jackc:pgx:5.9.2:*:*:*:*:*:*:*` | `h1:3ZhOzMWnR4yJ+RW1XImIPsD1aNSz4T4fyP7zlQb56hw=` |
| `golang.org/x/crypto` | `v0.51.0` | `pkg:golang/golang.org/x/crypto@v0.51.0` | `cpe:2.3:a:golang:x_crypto:0.51.0:*:*:*:*:*:*:*` | `h1:IBPXwPfKxY7cWQZ38ZCIRPI50YLeevDLlLnyC5wRGTI=` |
| `golang.org/x/oauth2` | `v0.36.0` | `pkg:golang/golang.org/x/oauth2@v0.36.0` | `cpe:2.3:a:golang:x_oauth2:0.36.0:*:*:*:*:*:*:*` | `h1:peZ/1z27fi9hUOFCAZaHyrpWG5lwe0RJEEEeH0ThlIs=` |
| `gopkg.in/yaml.v3` | `v3.0.1` | `pkg:golang/gopkg.in/yaml.v3@v3.0.1` | `cpe:2.3:a:go-yaml:yaml:3.0.1:*:*:*:*:*:*:*` | `h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=` |

#### Orchestrator — Go Libraries (Indirect, production-shipped)

| Package | Version | PURL | go.sum h1 Hash |
|---|---|---|---|
| `github.com/chromedp/sysutil` | `v1.1.0` | `pkg:golang/github.com/chromedp/sysutil@v1.1.0` | `h1:PUFNv5EcprjqXZD9nJb9b/c9ibAbxiYo4exNWZyipwM=` |
| `github.com/go-json-experiment/json` | `20260214004413-d219187c3433` | `pkg:golang/github.com/go-json-experiment/json@v0.0.0-20260214004413-d219187c3433` | `h1:vymEbVwYFP/L05h5TKQxvkXoKxNvTpjxYKdF1Nlwuao=` |
| `github.com/go-jose/go-jose/v4` | `v4.1.4` | `pkg:golang/github.com/go-jose/go-jose/v4@v4.1.4` | `h1:moDMcTHmvE6Groj34emNPLs/qtYXRVcd6S7NHbHz3kA=` |
| `github.com/gobwas/httphead` | `v0.1.0` | `pkg:golang/github.com/gobwas/httphead@v0.1.0` | `h1:exrUm0f4YX0L7EBwZHuCF4GDp8aJfVeBrlLQrs6NqWU=` |
| `github.com/gobwas/pool` | `v0.2.1` | `pkg:golang/github.com/gobwas/pool@v0.2.1` | `h1:xfeeEhW7pwmX8nuLVlqbzVc7udMDrwetjEv+TZIz1og=` |
| `github.com/gobwas/ws` | `v1.4.0` | `pkg:golang/github.com/gobwas/ws@v1.4.0` | `h1:CTaoG1tojrh4ucGPcoJFiAQUAsEWekEWvLy7GsVNqGs=` |
| `github.com/jackc/pgpassfile` | `v1.0.0` | `pkg:golang/github.com/jackc/pgpassfile@v1.0.0` | `h1:/6Hmqy13Ss2zCq62VdNG8tM1wchn8zjSGOBJ6icpsIM=` |
| `github.com/jackc/pgservicefile` | `20240606120523-5a60cdf6a761` | `pkg:golang/github.com/jackc/pgservicefile@v0.0.0-20240606120523-5a60cdf6a761` | `h1:iCEnooe7UlwOQYpKFhBabPMi4aNAfoODPEFNiAnClxo=` |
| `github.com/jackc/puddle/v2` | `v2.2.2` | `pkg:golang/github.com/jackc/puddle@v2.2.2` | `h1:PR8nw+E/1w0GLuRFSmiioY6UooMp6KJv0/61nB7icHo=` |
| `golang.org/x/sync` | `v0.22.0` | `pkg:golang/golang.org/x/sync@v0.22.0` | `h1:SZjpbeLmrCk4xhRSZFNZW5gFUeCeFgjekvI/+gfScek=` |
| `golang.org/x/sys` | `v0.47.0` | `pkg:golang/golang.org/x/sys@v0.47.0` | `h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=` |
| `golang.org/x/text` | `v0.37.0` | `pkg:golang/golang.org/x/text@v0.37.0` | `h1:Cqjiwd9eSg8e0QAkyCaQTNHFIIzWtidPahFWR83rTrc=` |
| `golang.org/x/time` | `v0.15.0` | `pkg:golang/golang.org/x/time@v0.15.0` | `h1:bbrp8t3bGUeFOx08pvsMYRTCVSMk89u4tKbNOZbp88U=` |
| `github.com/kr/text` | `v0.2.0` | `pkg:golang/github.com/kr/text@v0.2.0` | `h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=` |
| `github.com/rogpeppe/go-internal` | `v1.14.1` | `pkg:golang/github.com/rogpeppe/go-internal@v1.14.1` | `h1:UQB4HGPB6osV0SQTLymcB4TgvyWu6ZyliaW0tI/otEQ=` |

#### Agent — Go Libraries

| Package | Version | PURL | CPE 2.3 | go.sum h1 Hash |
|---|---|---|---|---|
| `github.com/gorilla/websocket` | `v1.5.3` | `pkg:golang/github.com/gorilla/websocket@v1.5.3` | `cpe:2.3:a:gorilla:websocket:1.5.3:*:*:*:*:*:*:*` | `h1:saDtZ6Pbx/0u+bgYQ3q96pZgCzfhKXGPqt7kZ72aNNg=` |
| `golang.org/x/sys` | `v0.45.0` | `pkg:golang/golang.org/x/sys@v0.45.0` | `cpe:2.3:a:golang:x_sys:0.45.0:*:*:*:*:*:*:*` | `h1:dO4czNzziLiiXplLQgBCEpCvXQ3dnkn0SdaZSYdQ+FY=` |
| `github.com/rodrigocfd/windigo` | `v0.2.6` | `pkg:golang/github.com/rodrigocfd/windigo@v0.2.6` | `cpe:2.3:a:rodrigocfd:windigo:0.2.6:*:*:*:*:*:*:*` | `h1:/rTNYsBqllPKr4qfiPB5iHbtNp4KwZWelBCgYf80mag=` |

**Removed since v1.7.3:** `github.com/jchv/go-webview2` and `github.com/jchv/go-winloader` rows are no longer applicable.

#### Installer — Go Libraries

| Package | Version | PURL | go.sum h1 Hash |
|---|---|---|---|
| `golang.org/x/sys` | `v0.45.0` | `pkg:golang/golang.org/x/sys@v0.45.0` | `h1:dO4czNzziLiiXplLQgBCEpCvXQ3dnkn0SdaZSYdQ+FY=` |

#### API Service — Python Libraries

PURL format follows `pkg:pypi/<name>@<version>`. CPE vendor/product names follow NVD CPE dictionary. PyPI SHA-256 hashes are verified by pip at image build time using `--require-hashes`.

| Package | Version | PURL | CPE 2.3 |
|---|---|---|---|
| `fastapi` | `0.115.0` | `pkg:pypi/fastapi@0.115.0` | `cpe:2.3:a:fastapi:fastapi:0.115.0:*:*:*:*:python:*:*` |
| `uvicorn` | `0.30.6` | `pkg:pypi/uvicorn@0.30.6` | `cpe:2.3:a:encode:uvicorn:0.30.6:*:*:*:*:python:*:*` |
| `sqlalchemy` | `2.0.35` | `pkg:pypi/sqlalchemy@2.0.35` | `cpe:2.3:a:sqlalchemy:sqlalchemy:2.0.35:*:*:*:*:python:*:*` |
| `asyncpg` | `0.29.0` | `pkg:pypi/asyncpg@0.29.0` | `cpe:2.3:a:magicstack:asyncpg:0.29.0:*:*:*:*:python:*:*` |
| `pydantic` | `2.9.2` | `pkg:pypi/pydantic@2.9.2` | `cpe:2.3:a:pydantic:pydantic:2.9.2:*:*:*:*:python:*:*` |
| `pydantic-settings` | `2.5.2` | `pkg:pypi/pydantic-settings@2.5.2` | `cpe:2.3:a:pydantic:pydantic-settings:2.5.2:*:*:*:*:python:*:*` |
| `python-jose` | `3.3.0` | `pkg:pypi/python-jose@3.3.0` | `cpe:2.3:a:python-jose_project:python-jose:3.3.0:*:*:*:*:python:*:*` |
| `passlib` | `1.7.4` | `pkg:pypi/passlib@1.7.4` | `cpe:2.3:a:passlib:passlib:1.7.4:*:*:*:*:python:*:*` |
| `httpx` | `0.27.2` | `pkg:pypi/httpx@0.27.2` | `cpe:2.3:a:encode:httpx:0.27.2:*:*:*:*:python:*:*` |
| `python-multipart` | `0.0.12` | `pkg:pypi/python-multipart@0.0.12` | `cpe:2.3:a:python-multipart_project:python-multipart:0.0.12:*:*:*:*:python:*:*` |
| `weasyprint` | `62.3` | `pkg:pypi/weasyprint@62.3` | `cpe:2.3:a:courtbouillon:weasyprint:62.3:*:*:*:*:python:*:*` |
| `jinja2` | `3.1.4` | `pkg:pypi/jinja2@3.1.4` | `cpe:2.3:a:palletsprojects:jinja2:3.1.4:*:*:*:*:python:*:*` |

#### Container Base Images

| Image | Tag | PURL | CPE 2.3 |
|---|---|---|---|
| `postgres` | `16-alpine` | `pkg:docker/postgres@16-alpine` | `cpe:2.3:a:postgresql:postgresql:16:*:*:*:*:*:*:*` |
| `chromedp/headless-shell` | `latest` | `pkg:docker/chromedp/headless-shell@latest` | `cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*` |
| `ghcr.io/mitre/caldera` | `latest` | `pkg:docker/ghcr.io%2Fmitre/caldera@latest` | `cpe:2.3:a:mitre:caldera:*:*:*:*:*:*:*:*` |
| `gcr.io/distroless/static-debian12` | `latest` | `pkg:docker/gcr.io%2Fdistroless/static-debian12@latest` | `cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*` |
| `golang` | `1.26-alpine` | `pkg:docker/golang@1.26-alpine` | `cpe:2.3:a:golang:go:1.26:*:*:*:*:*:*:*` |

> **Verification note:** Go module hashes in this table are the `h1:` SHA-256 values from the respective `go.sum` files and match exactly what Go's module proxy and `go mod verify` check. To independently verify: `go mod download` + `go mod verify` in any module directory. PyPI package hashes can be cross-referenced at `https://pypi.org/pypi/<package>/<version>/json` under the `urls[].digests.sha256` field.

---

### 2.11 Dependency Relationships

This section documents the dependency graph for each first-party component. Relationships are drawn directly from `go.mod` `require` directives and `go mod graph`.

#### Orchestrator (bas-orchestrator)

```
bas-orchestrator
├── github.com/chromedp/chromedp v0.15.1                         [direct]
│   ├── github.com/chromedp/cdproto 20260321001828-e3e3800016bc  [indirect]
│   ├── github.com/chromedp/sysutil v1.1.0                       [indirect]
│   │   └── golang.org/x/sys v0.47.0                             [indirect]
│   ├── github.com/go-json-experiment/json 20260214004413-...     [indirect]
│   ├── github.com/gobwas/httphead v0.1.0                         [indirect]
│   ├── github.com/gobwas/pool v0.2.1                             [indirect]
│   └── github.com/gobwas/ws v1.4.0                               [indirect]
├── github.com/coreos/go-oidc/v3 v3.20.0                          [direct, NEW v1.7.5]
│   └── github.com/go-jose/go-jose/v4 v4.1.4                      [indirect, NEW v1.7.5]
├── github.com/go-chi/chi/v5 v5.0.12                              [direct]
├── github.com/go-pdf/fpdf v0.9.0                                 [direct]
├── github.com/golang-jwt/jwt/v5 v5.2.1                           [direct]
├── github.com/gorilla/websocket v1.5.3                           [direct]
├── github.com/jackc/pgx/v5 v5.9.2                                [direct]
│   ├── github.com/jackc/pgpassfile v1.0.0                        [indirect]
│   ├── github.com/jackc/pgservicefile 20240606120523-5a60cd...   [indirect]
│   ├── github.com/jackc/puddle/v2 v2.2.2                         [indirect]
│   ├── golang.org/x/sync v0.22.0                                 [indirect]
│   └── golang.org/x/text v0.37.0                                 [indirect]
├── golang.org/x/crypto v0.51.0                                   [direct]
├── golang.org/x/oauth2 v0.36.0                                   [direct, NEW v1.7.5]
├── golang.org/x/time v0.15.0                                     [indirect — used by internal/api/ratelimit.go]
└── gopkg.in/yaml.v3 v3.0.1                                       [direct]

Test-only indirect (not shipped in binary):
├── github.com/kr/text v0.2.0
├── github.com/rogpeppe/go-internal v1.14.1
└── github.com/testcontainers/testcontainers-go (+postgres module) v0.43.0, and its full
    Docker/Moby/OpenTelemetry/testify transitive tree (~40 packages) — see §2.3 callout
```

#### Agent (`audspect/agent`)

```
audspect/agent
├── github.com/gorilla/websocket v1.5.3                           [direct]
├── golang.org/x/sys v0.45.0                                      [direct]
└── github.com/rodrigocfd/windigo v0.2.6                          [direct — NEW v1.7.5, replaces go-webview2/go-winloader]
```

#### Installer (`audspect/installer`)

```
audspect/installer
└── golang.org/x/sys v0.45.0                                      [direct]
```

#### API Service (Python — `api/requirements.txt`)

```
api-service
├── fastapi 0.115.0
│   └── pydantic 2.9.2
│       └── pydantic-settings 2.5.2
├── uvicorn[standard] 0.30.6
├── sqlalchemy[asyncio] 2.0.35
│   └── asyncpg 0.29.0
├── python-jose[cryptography] 3.3.0
├── passlib[bcrypt] 1.7.4
├── httpx 0.27.2
├── python-multipart 0.0.12
├── weasyprint 62.3
└── jinja2 3.1.4
```

#### Container Composition (`docker-compose.yml`)

```
audspect-bas-stack
├── orchestrator  ←  gcr.io/distroless/static-debian12 (runtime)
│                    golang:1.26-alpine (build stage only)
├── postgres      ←  postgres:16-alpine
├── chromium      ←  chromedp/headless-shell:latest
└── caldera       ←  bas-caldera (custom image)
                      └── ghcr.io/mitre/caldera:latest (base; emu + atomic plugins enabled)
```

---

## 4. Compliance Alignment

This mapping is informational. Formal compliance determination requires an authorised audit.

| Framework | Clause / Domain | How This Document Assists |
|---|---|---|
| SEBI CSCRF | Clause 5.3 — Supply Chain Risk Management | SBOM provides the component and third-party dependency inventory required under supply-chain risk controls. CBOM supports algorithm disclosure. |
| RBI Cyber Security Framework | Domain 4 — Data Protection; Annex III | CBOM documents all cryptographic algorithms and key management practices, including the new SSO/OIDC flow (§3.4); supports RBI encryption adequacy assessment. |
| CERT-In Directions 2022 | Section 25(xxv) — Software Inventory & Audit Trail | SBOM fulfils the software inventory disclosure requirement. Component versions and build hashes support audit trail reconstruction. |
| IRDAI Cyber Security Guidelines | Guideline 8 — Third-Party Risk | Third-party library and container image inventory (§2.2–2.7) provides dependency disclosure required for insurer and regulator review. |
| NIST CSF 2.0 | GV.SC-06 — Supply Chain; ID.AM-02 — Asset Management | SBOM satisfies software component identification and inventory requirements. |
| NIST SP 800-132 | Password-Based Key Derivation | PBKDF2-HMAC-SHA256 at 310,000 iterations meets the 2023 NIST minimum iteration count recommendation. |
| DPDP Act 2023 (India) | Section 8 — Data Fiduciary Obligations | CBOM documents encryption and integrity mechanisms protecting personal data at rest (password hashes) and in transit (TLS posture, §3.10–3.11); tenant-scoped JWT claims (§3.3) support data-fiduciary boundary enforcement between tenants. |

---

> **Disclaimer:** This document reflects the state of the software at version 1.7.5 as of 14 August 2026. It supersedes the v1.7.3 document dated 3 July 2026, which remains available for historical/audit reference. Component versions and algorithms may change between releases. Customers should request an updated SBOM & CBOM for each new major or minor release. Licenses are based on well-established knowledge of each package and should be independently verified against each package's own `LICENSE` file in the event of formal legal review.

---

*Audspect BAS v1.7.5 — SBOM & CBOM · Classification: CONFIDENTIAL — Restricted Distribution*
