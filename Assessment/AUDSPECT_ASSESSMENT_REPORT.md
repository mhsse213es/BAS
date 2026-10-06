# Audspect / BAS — Full Assessment, Maturity Review & Root-Cause Remediation Plan

**Repository:** `github.com/mhsse213es/BAS` → analyzed at `E:\Tausif_Audspect\BAS`
**Product:** Audspect BAS — on-premises / air-gapped Breach & Attack Simulation platform (docs version v1.7.5)
**Date of assessment:** 2026-09-26
**Scope:** Whole codebase (orchestrator, endpoint agent, frontend SPA, scenarios, docs, packaging), plus a working local setup.
**Method:** Static review of ~168K LOC of Go + 22K-line SPA + 110 scenarios + 356 docs, corroborated by a live local run.

> This document is the single source of truth for the review. Every finding has a **Root Cause** and a **Fix (root-cause, not band-aid)** written so that the security risk is eliminated *without* changing the product's intended behavior. Actual secret values are deliberately **not** reproduced anywhere in this file.

---

## Table of contents
1. [Executive summary](#1-executive-summary)
2. [How to run it locally (reproducible)](#2-how-to-run-it-locally-reproducible)
3. [System architecture](#3-system-architecture)
4. [Maturity scorecard](#4-maturity-scorecard)
5. [Vision vs. reality](#5-vision-vs-reality)
6. [Findings register (with root-cause fixes)](#6-findings-register-with-root-cause-fixes)
7. [Cross-cutting root-cause themes](#7-cross-cutting-root-cause-themes)
8. [Prioritized remediation roadmap](#8-prioritized-remediation-roadmap)
9. [What to keep — strong security posture](#9-what-to-keep--strong-security-posture)
10. [Evidence appendix](#10-evidence-appendix)

---

## 1. Executive summary

Audspect BAS is a **real, shipping, Beta / release-candidate-grade** on-prem BAS platform — not a prototype. The engineering discipline is unusually high for its stage:

- **~168K LOC Go** in the orchestrator with a **~1:1 test-to-code ratio** (447 test files), real **testcontainers-backed Postgres integration tests**, only **9 TODO/FIXME markers** in 87K non-test lines, **3** panics (all fail-fast at boot), and disciplined error wrapping (261 `%w`).
- A **mature, ~130-permission RBAC**, **PBKDF2-HMAC-SHA256 @ 310K iterations**, boot-time crypto self-test, **RSA-signed licenses + binary integrity manifest**, and **fully parameterized SQL** (zero string-built queries).
- A genuine market differentiator: **India/BFSI regulatory scenarios (RBI CSF, SEBI CSCRF)** cited to the actual circulars.

It is held back from "production-grade" **not by code quality** but by a small number of **architectural gaps** whose root causes are concentrated and fixable:

| # | Theme | Severity | Root cause in one line |
|---|---|---|---|
| A | Secrets committed to the repo | 🔴 Critical | No secret-management discipline / no pre-commit guard |
| B | Endpoint-agent trust model | 🔴 Critical | Shared secret + no per-agent identity + no command signing + no transport pinning |
| C | Multi-tenant isolation not enforced | 🟠 High | RLS designed but `ENABLE/FORCE` left commented; `WithTenant` seam wired in ~5 places |
| D | Supply-chain signing incomplete | 🟠 High | No Authenticode/notarization; GPG-only, out-of-band |
| E | No destructive-action guardrail on agent | 🟠 High | Agent trusts server 100%; safety delegated entirely to server-side curation |
| F | Web/API hardening gaps | 🟡 Medium | CORS `*`, WS `CheckOrigin` always true, non-constant-time secret compare, no JWT-secret entropy check |
| G | Frontend XSS surface | 🟡 Medium | 455 `innerHTML` sinks + duplicated inconsistent escaper |
| H | Schema management | 🟡 Medium | Boot-time idempotent DDL, no versioned migrations |
| I | Observability/test blind spots | 🟡 Medium | No-op exporters; `siem` package untested |
| J | Repo hygiene | 🟡 Medium | 53MB vendored OpenAEV, unrelated `.agents/`, ~40MB media |

**Fix order:** A → B → F → C/D/E → G/H/I → J. Details in [§8](#8-prioritized-remediation-roadmap).

---

## 2. How to run it locally (reproducible)

Verified working on Windows 11 + Docker + Go 1.27, 2026-09-26.

```bash
# 1) Database
docker run -d --name audspect-postgres \
  -e POSTGRES_DB=bas_platform -e POSTGRES_USER=bas_user -e POSTGRES_PASSWORD=123 \
  -p 5432:5432 postgres:16-alpine

# 2) Build the orchestrator with the product's own dev-mode signing placeholders
#    (no source edits — link-time override only)
cd orchestrator
go build -ldflags "\
  -X 'github.com/audspect/bas/internal/license.PublicKeyPEM=KEYGEN_REQUIRED' \
  -X 'github.com/audspect/bas/internal/integrity.ScenarioPublicKeyPEM=SIGNING_KEYGEN_REQUIRED'" \
  -o bas-server-local.exe ./cmd/server

# 3) config.local.json
#    { "database_url":"postgres://bas_user:123@localhost:5432/bas_platform?sslmode=disable",
#      "jwt_secret":"dev-secret-change-in-prod-min32chars!!", "http_port":9000,
#      "scenarios_dir":"../scenarios", "admin_email":"admin@audspect.local",
#      "admin_password":"Admin@12345",
#      "dns_sink_enabled":false, "sftp_sink_enabled":false, "smtp_sink_enabled":false }

# 4) Run
HTTP_PORT=9000 ./bas-server-local.exe config.local.json
# → SPA + API on http://127.0.0.1:9000 ; login POST /api/auth/login
```

**Two boot blockers, both informative:**
1. The baked RSA **license** public key enforces licensing → fatal without a signed `bas.lic`. Dev bypass = the `KEYGEN_REQUIRED` placeholder.
2. The committed **scenarios + `agents/BINARIES.sha256` manifest do not verify** against the embedded scenario-signing key (they were signed in a private release pipeline; the repo ships an unmatched public key). Dev bypass = the `SIGNING_KEYGEN_REQUIRED` placeholder.

The privileged-port DLP sinks (UDP/53, TCP/22, TCP/587) are disabled in the local config because they don't bind cleanly on Windows. The full production stack (orchestrator + Caldera + headless-Chrome PDF sidecar + Postgres) is in `packaging/compose/docker-compose.yml` and needs those images built and an `.env`.

---

## 3. System architecture

```
 ┌────────────────────┐      WebSocket /ws/agent     ┌──────────────────────────────────────┐
 │  Endpoint Agent     │ ───────────────────────────► │  Orchestrator (Go, chi/v5 + pgx)      │
 │  (Go, SYSTEM/root)  │      results over HTTP POST  │  ~80 internal packages, 375 routes    │
 │  "dumb executor"    │ ◄─────────────────────────── │  embeds wwwroot SPA via go:embed       │
 │  ART + posture      │      commands                └───────────────┬──────────────────────┘
 │  snapshot/revert    │                                              │
 │  spool (durable)    │                              ┌───────────────┼───────────────┬───────────────┐
 └────────────────────┘                              │               │               │               │
                                              PostgreSQL 16   Caldera (ATT&CK)  Headless Chrome   Python FastAPI
                                              (~70 tables)    CTID emulation    HTML→PDF          (reporting/AI/scoring)
```

- **Orchestrator** (`orchestrator/`): the core. chi router, pgxpool, WebSocket hub, ~15 background schedulers, RBAC, reporting engine (HTML+PDF), compliance mapper, threat-intel connectors (MISP/OpenCTI/OTX), scenario engine (ART + Caldera), exercise/purple-team engine, DLP exfil sinks (DNS/SFTP/SMTP/telnet/webhook/cloud).
- **Endpoint agent** (`agent/`): a highly-engineered "dumb executor" — cancellable/pausable runs, resource-lock scheduler, 3-layer timeouts, circuit breakers, host-pressure throttling, durable idempotent result spool, disconnect watchdog, Job-Object tree-kill, snapshot/auto-revert. Runs as LocalSystem (Windows) / root (POSIX).
- **Frontend** (`orchestrator/wwwroot/index.html`): a single **22,235-line vanilla-JS SPA**, embedded in the Go binary and hash-verified at boot. ~30 tabs. No framework, no build step.
- **Not product code:** `openaev-main/` (53MB vendored Filigran OpenAEV — unused), `.agents/` (unrelated marketing toolkit), ~40MB of media at root.

---

## 4. Maturity scorecard

| Component | Size | Tests | Verdict | Notes |
|---|---|---|---|---|
| Orchestrator (Go) | 167K LOC (87K non-test) | 447 test files, ~1:1 | **Late-beta / RC** (single-tenant) | Drops to solid Beta if marketed multi-tenant (RLS off) |
| Endpoint agent (Go) | ~32K LOC | 66 test files (~0.6) | **Mature Beta** | Production-grade *engineering*, pre-production *trust model* |
| Frontend SPA | 22,235-line single file | none | **Feature-rich, structurally immature** | No modules/bundler/tests; XSS discipline inconsistent |
| Scenarios | 110 signed YAMLs, 170 ATT&CK techniques | — | **Strong** | RBI/SEBI = real differentiator |
| Docs | 356 files (152 specs + 167 plans) | — | **Thorough & honest** | Version drift v1.7.3 vs v1.7.5 |
| Python API | small | minimal | **Auxiliary** | CORS wildcard needs fixing |

**Bottom line:** Beta / release-candidate for the **single-tenant on-prem appliance** it is actually designed to be. The four architectural gaps (A–E below) are what stand between it and "production-grade."

---

## 5. Vision vs. reality

Source of vision: `PHASE1.txt`, `phase2.txt`, `mythos.txt`.

| Ambition | Reality | Status |
|---|---|---|
| Phase 1: Go core, scenario engine, RBAC, UI, ART+Caldera, 5 BFSI scenarios, Docker/Helm | All present; APT36, ransomware, PurpleSharp AD, UPI-fraud, CSCRF-MII exist | ✅ **Closed** |
| ART + Caldera end-to-end | ~1,210 atomics + Caldera CTID emulation, air-gapped | ✅ **Closed** |
| Phase-2 tools: Infection Monkey, Stratus, APTSimulator, Metta, Cobalt Strike | **Zero** scenarios reference them; still ART + Caldera + 1 PurpleSharp | ❌ **Large gap** |
| Compliance: CSCRF/RBI/IRDAI/CERT-In/NIST/ISO27001 | RBI + SEBI CSCRF real & cited; NIST/CIS partial; ISO27001 claimed-not-mapped; **IRDAI & CERT-In = 0 scenarios** | ⚠️ **Partial** |
| Ransomware behavior framework (reversible) | Multiple family kill-chains + readiness + detection profiles, 3-tier safety | ✅ **Mostly closed** |
| Threat intel (MISP/OpenCTI/OTX) | Connectors shipped and wired | ✅ **Closed** |
| "Mythos" autonomous adversary (AI planning, adaptive TTP selection, campaign memory, attack-graph pathfinding) | **Entirely unbuilt** — 1KB aspiration; attack-path is static SharpHound, not adaptive | ❌ **Biggest gap** |

**Strength:** the docs are honest — they separate the `audspect.html` mockup (vision) from `index.html` (reality), gray out un-backed UI, and refuse to auto-invent compliance mappings.

---

## 6. Findings register (with root-cause fixes)

Each finding: **Location · Description · Impact · Root Cause · Fix (root-cause) · Preserve-behavior note.**

---

### GROUP A — Secrets committed to the repository 🔴 CRITICAL

**A1. Live-looking credentials in version control**
- **Location:** `keys.txt`, `tenantID.txt`, `setting.json`, `Model Configurator.txt` (repo root).
- **Description:** An AWS access key + secret (region ap-south-1), an OpenRouter API key, and an OIDC tenant GUID + client-secret-style token are committed in plaintext. This repo was cloned from a public GitHub URL.
- **Impact:** Anyone with the repo (or its history) has the credentials → potential AWS account compromise, LLM-billing abuse, identity-provider abuse. This is the most urgent item.
- **Root cause:** No secret-management practice — secrets live in files inside the repo, and nothing prevents them being committed.
- **Fix (root-cause):**
  1. **Rotate/revoke every exposed credential now** (AWS keys, OpenRouter key, OIDC client secret). Assume compromised.
  2. **Purge from git history**: `git filter-repo --invert-paths --path keys.txt --path tenantID.txt --path setting.json --path "Model Configurator.txt"` (or BFG), then force-push and have all clones re-clone.
  3. **Prevent recurrence** — the real root-cause fix:
     - Add to `.gitignore`: `keys.txt`, `tenantID.txt`, `setting.json`, `*.lic`, `*.pfx`, `*.pem`, `.env`.
     - Add a **pre-commit secret scanner** (`gitleaks` or `trufflehog`) as a git hook **and** a CI gate that fails the build on any detected secret.
     - Move real secrets to the intended mechanism the code already supports: **environment variables / a secrets manager** (the orchestrator already reads `DATABASE_URL`, `JWT_SECRET`, `AGENT_SECRET`, etc. from env — see `config.Load`).
- **Preserve-behavior note:** None of these files are needed at runtime; the app reads secrets from env/config path. Removing them changes nothing functionally.

---

### GROUP B — Endpoint-agent trust model 🔴 CRITICAL

The agent runs as **SYSTEM/root** and is, by design, a "dumb executor" — it runs whatever the orchestrator sends. That is acceptable for BAS **only if** the channel is mutually authenticated, pinned, and command-authenticated. Today it is not, so the blast radius of a compromised/rogue orchestrator, a MITM, or a leaked shared secret is **fleet-wide RCE as SYSTEM**.

**B1. Shared, fleet-wide agent secret + guessable identity**
- **Location:** `agent/identity.go` (`AgentID = SHA-256(hostname)[:16]`), `agent/config.go`, `main.go --secret`.
- **Description:** One `AgentSecret` appears to be shared across the fleet; `AgentID` is a truncated hash of the hostname (guessable). The only real secret is fleet-wide.
- **Impact:** Compromise of one endpoint's secret allows impersonating **any** agent; there is no per-agent authentication boundary.
- **Root cause:** Authentication was modeled as a single shared bearer secret rather than per-agent identity.
- **Fix (root-cause):** Issue **per-agent credentials** at enrollment. Two viable designs (pick one):
  - **mTLS client certificates** — orchestrator acts as a private CA, mints a per-agent cert at enroll, agent presents it on every WS/HTTP call. Strongest; also solves transport auth (B3).
  - **Per-agent tokens** — enroll returns a random 256-bit per-agent token bound to `agent_id`, stored server-side (hashed). Rotate on a schedule. Simpler to ship.
  Keep a short-lived **enrollment secret** (the current shared secret, rotated) used *only* to bootstrap the first per-agent credential.
- **Preserve-behavior note:** Enrollment flow already exists (`agent/enroll.go`); this extends it to return+store a per-agent credential. Existing deployments migrate on next enroll.

**B2. Agent secret transmitted in the WebSocket URL query string**
- **Location:** `agent/protocol/websocket.go:47-51` (`q.Set("agentSecret", agentSecret)`); server accepts it at `orchestrator/internal/api/handlers.go:238-242`.
- **Description:** The secret is placed in `?agentSecret=…`. URLs are logged by proxies, load balancers, and server access logs.
- **Impact:** Secret leaks into logs across the network path → credential disclosure.
- **Root cause:** Convenience — query params are the easiest thing to set on a WS dial.
- **Fix (root-cause):**
  - Send the credential in a **header** (gorilla's `Dial(url, http.Header{...})` supports request headers on the handshake) or a WebSocket **subprotocol**, never the URL.
  - **Remove the query-param fallback** on the server (`handlers.go:240`) once agents are updated.
- **Preserve-behavior note:** The server already prefers the `X-Agent-Token` header (`handlers.go:238`); this makes header the *only* path. Roll agents first, then delete the fallback.

**B3. No TLS certificate pinning; plaintext `ws://` default**
- **Location:** `agent/config.go` default `http://localhost:9000`; `agent/agent.go:~1210` custom dialer with no `RootCAs`/pinning; no `InsecureSkipVerify`/pinning anywhere in `agent/*.go`.
- **Description:** Transport trust relies on the OS trust store only, and the default scheme is plaintext.
- **Impact:** A MITM presenting any trusted cert — or intercepting plaintext `ws://` in a dev/misconfig — gets fleet-wide SYSTEM RCE.
- **Root cause:** Transport security was left to defaults; no pinning; plaintext allowed unconditionally.
- **Fix (root-cause):**
  - **Pin the orchestrator's certificate/public key** in the agent (ship the expected SPKI hash at enrollment; verify in `tls.Config.VerifyPeerCertificate`).
  - **Refuse plaintext `ws://`** unless an explicit `--dev`/`--insecure` flag is set; make `wss://` the only production path.
  - With mTLS (B1), this becomes mutual pinning.
- **Preserve-behavior note:** On-prem deployments already control both ends, so pinning the server SPKI is operationally easy and invisible to users.

**B4. Commands are not authenticated/signed; no local allow-list**
- **Location:** `agent/agent.go:1249-1341` (WS dispatch); `agent/executor*.go` (executes verbatim).
- **Description:** After the handshake, any well-formed WS frame is executed. There is no per-command signature and no local classifier of what may run.
- **Impact:** Whoever controls the channel controls every endpoint; a rogue/compromised orchestrator = arbitrary code.
- **Root cause:** Trust was placed entirely in the channel + server-side curation, with nothing verifiable at the agent.
- **Fix (root-cause):**
  - **Sign scenario/command payloads server-side** with the existing RSA signing infrastructure (the product already RSA-signs scenarios and the binary manifest — reuse it). The agent verifies the signature against a **pinned public key baked at install** before executing. This means even a compromised orchestrator process cannot forge commands without the offline signing key.
  - Combine with **B5** (a local destructive-action guardrail) for defense-in-depth.
- **Preserve-behavior note:** Scenarios are already signed; extend the same signature to the dispatched command bundle. Legitimate content keeps running unchanged.

**B5. No destructive-action guardrail on the agent** 🟠 High
- **Location:** `agent/sched/riskgate.go` (governs *resource footprint*, not safety); `agent/snapshot_*.go` (best-effort revert of *enumerated* surfaces).
- **Description:** Reversibility covers only enumerated persistence surfaces (temp files, services, tasks, Run keys, units, firewall rules). A destructive command outside those (real encryption, `rm -rf`, `format`) runs unimpeded and irreversibly.
- **Impact:** For a SYSTEM-level simulator, an out-of-scope destructive command is catastrophic and unrecoverable.
- **Root cause:** "Safety" is delegated 100% to server-side curation; the agent has no independent notion of "destructive."
- **Fix (root-cause):**
  - Add a **local, signed policy allow-list/denylist** the agent enforces before execution: allowed executors, blocked patterns (mass file writes, disk-format, bootloader/BCD edits, wiper syscalls), and a hard cap on file-modification rate. Ship it signed (same infra as B4) so it can't be silently overridden.
  - Make the guardrail **fail-closed**: unknown/high-risk actions require an explicit, signed "lab-mode" grant.
- **Preserve-behavior note:** The product already has a three-tier fidelity model (Posture / Telemetry / Lab). Map the guardrail to those tiers so Telemetry stays production-safe and only signed Lab grants unlock full tradecraft — exactly the intended behavior, now enforced at the endpoint too.

---

### GROUP C — Multi-tenant isolation not enforced 🟠 HIGH

**C1. RLS designed but disabled**
- **Location:** `orchestrator/internal/db/postgres.go:1256-1271` (`ENABLE/FORCE ROW LEVEL SECURITY` commented out; policy created on `users` only); `internal/db/tenant.go` (`WithTenant` seam, correct + parameterized) used in ~5 call sites.
- **Description:** `tenant_id` columns exist on ~55 tables and the transaction seam is correct, but RLS is not enabled and the seam is barely wired. Isolation currently depends on application-layer discipline.
- **Impact:** Any query path that forgets the tenant filter leaks cross-tenant data. Claiming multi-tenant isolation today would be inaccurate.
- **Root cause:** Multi-tenancy shipped as scaffolding pending a "future migration" that hasn't landed; enforcement was deferred.
- **Fix (root-cause):**
  1. **Enable + FORCE RLS** on every tenant-scoped table with a `tenant_isolation` policy `USING (tenant_id = current_setting('app.tenant_id')::uuid)`.
  2. **Route every request-scoped DB access through `WithTenant`** (set `app.tenant_id` per transaction) — audit all query sites; add a lint/test that fails if a tenant-scoped table is queried outside a tenant transaction.
  3. **Turn on the DB role hardening** that already exists (`db.HardenRuntimeRole`, `BAS_DB_BREAKGLASS_PASSWORD`) so the runtime role is `NOBYPASSRLS` — otherwise a superuser role silently bypasses policies.
  4. Add **cross-tenant isolation integration tests** (the testcontainers harness already exists — assert tenant A cannot read tenant B).
- **Preserve-behavior note:** For single-tenant on-prem (the current target), set one default tenant and RLS is a no-op that still hardens the code path. It becomes load-bearing only when SaaS is offered — so this can be enabled now with zero behavior change.
- **Decision required:** Either finish this (to sell SaaS) or **explicitly scope the product to single-tenant on-prem** in all messaging until it's done.

---

### GROUP D — Supply-chain / binary signing incomplete 🟠 HIGH

**D1. No Authenticode / macOS notarization**
- **Location:** `packaging/signing/*` (GPG detached sigs + SHA-256 manifest only; `.pfx` gitignored but no `signtool`/`codesign` invocation).
- **Description:** Windows agent + installer and macOS binaries are unsigned for OS-trust purposes; integrity is out-of-band GPG only.
- **Impact:** SmartScreen/Gatekeeper friction, easier trojanization, weaker enterprise trust for a security vendor.
- **Root cause:** Signing pipeline built for air-gapped GPG verification, never extended to OS-native code signing.
- **Fix (root-cause):**
  - Add **Authenticode** signing (`signtool sign /fd sha256 /tr <timestamp> …`) for Windows agent + installer, and **codesign + notarize + staple** for macOS, in the release pipeline using an HSM-backed or EV cert.
  - Keep GPG for air-gapped verification (belt and suspenders).
- **Preserve-behavior note:** Purely additive to the build; runtime behavior unchanged.

**D2. Agent binary not obfuscated (documented)**
- **Location:** `packaging/build.sh:48` — agent uses plain stripped build (garble incompatible with `x/sys` asm); only the orchestrator is garbled.
- **Description:** Agent strings/symbols are trivially reversible.
- **Impact:** Easier for an adversary to understand/evade the agent. Lower severity than B-group.
- **Root cause:** Toolchain incompatibility (garble vs `x/sys`).
- **Fix (root-cause):** Selectively obfuscate the packages that don't pull in `x/sys` assembly, or adopt a garble version/config that tolerates it; accept that endpoint agents are inherently reversible and lean on **B1–B4** (identity + signing) rather than obfuscation for security. Obfuscation is defense-in-depth, not a control.

---

### GROUP E — see B5 (destructive-action guardrail), grouped with the agent trust model.

---

### GROUP F — Web / API hardening 🟡 MEDIUM

**F1. Non-constant-time agent-secret comparison**
- **Location:** `orchestrator/internal/api/handlers.go:242` — `return provided == h.agentSecret`.
- **Description:** String `==` on a secret is a timing side-channel.
- **Impact:** Theoretical secret recovery via timing; low but trivially fixable.
- **Root cause:** Default comparison used for a secret.
- **Fix:** `subtle.ConstantTimeCompare([]byte(provided), []byte(h.agentSecret)) == 1`. (Becomes moot under B1's per-agent tokens but fix regardless.)

**F2. CORS wildcard on the Python API**
- **Location:** `api/main.py:38-40` — `allow_origins=["*"]`, `allow_methods=["*"]`, `allow_headers=["*"]`.
- **Description:** Any origin can call the API from a browser.
- **Impact:** CSRF/data-exposure surface for a security product's API.
- **Root cause:** Permissive default left in.
- **Fix (root-cause):** Set `allow_origins` to the explicit console origin(s) from config; drop wildcard methods/headers to the actual set used; never combine `*` origins with credentials.
- **Preserve-behavior note:** The SPA is same-origin (served by the orchestrator), so locking origins doesn't break it.

**F3. Browser WebSocket `CheckOrigin` always returns true**
- **Location:** `orchestrator/internal/ws/hub.go:17` — `CheckOrigin: func(r *http.Request) bool { return true }`.
- **Description:** The browser hub upgrader accepts any origin.
- **Impact:** Cross-site WebSocket hijacking of the browser channel (agent channel is separately secret-gated).
- **Root cause:** Placeholder permissive check.
- **Fix (root-cause):** Validate `Origin` against the configured public base URL / allowed origins for browser connections. Keep agent WS (non-browser) on its credentialed path.
- **Preserve-behavior note:** Legit console connects same-origin, so validation is invisible to users.

**F4. No JWT-secret strength enforcement**
- **Location:** `orchestrator/config/config.go:280-281` — only checks non-empty.
- **Description:** A weak/short `JWT_SECRET` is accepted; HS256 security depends entirely on secret entropy.
- **Impact:** Forgeable tokens if a weak secret is used.
- **Root cause:** Presence checked, strength not.
- **Fix (root-cause):** Require **≥32 bytes** (ideally reject low-entropy/known-default values); fail closed at boot with a clear message. Optionally support RS256 with a keypair for larger deployments.
- **Preserve-behavior note:** Existing strong secrets pass; only weak ones are rejected — which is the point.

---

### GROUP G — Frontend XSS surface 🟡 MEDIUM

**G1. 455 `innerHTML` sinks + duplicated, inconsistent escaper**
- **Location:** `orchestrator/wwwroot/index.html` — 455 `innerHTML =` assignments; the escape helper `x()` is redefined ≥4× (e.g. lines ~14941, ~15087, ~17088) with differing behavior (some escape quotes, some don't); `x` is also reused as a numeric variable elsewhere (shadowing).
- **Description:** Server/imported data (agent names, scenario/actor names, error messages, OpenAEV-imported fields) flows into `innerHTML`; escaping is applied inconsistently.
- **Impact:** Plausible stored XSS wherever escaping is missed → session/console compromise.
- **Root cause:** No single canonical escaper; DOM built by string concatenation; no sanitizer; monolithic file makes consistency hard.
- **Fix (root-cause):**
  1. Define **one** canonical `escapeHTML()` (escapes `& < > " '`), remove all duplicates, rename the numeric `x` to avoid shadowing.
  2. Audit all 455 sites: prefer `textContent` for text; where HTML is needed, escape all interpolated values, or adopt a tiny templating/`DOMPurify` pass.
  3. Add a lint rule / CI grep that flags new raw `innerHTML =` with unescaped interpolation.
  4. Add a **Content-Security-Policy** header (no inline-eval; restrict script sources) as defense-in-depth — note the SPA is currently all-inline, so CSP needs nonces/hashes; plan this with the modularization in H-adjacent work.
- **Preserve-behavior note:** Rendering output is identical for benign data; only injection is neutralized.

**G2. Structural: 22K-line single-file SPA, no build/tests**
- **Impact:** Maintainability + inability to unit-test the UI; amplifies G1.
- **Root cause:** Grew organically without a module/build system.
- **Fix (longer-term):** Introduce a build step and split into modules; add UI tests; this also enables a strict CSP. Not urgent, but it's the structural root cause behind G1's recurrence risk.

---

### GROUP H — Schema management 🟡 MEDIUM

**H1. Boot-time idempotent DDL, no versioned migrations**
- **Location:** `orchestrator/internal/db/postgres.go` (~110KB of `CREATE TABLE IF NOT EXISTS` / `ALTER … ADD COLUMN IF NOT EXISTS`, ~70 tables) run on every startup; no schema-version table, no down-migrations.
- **Description:** Schema evolution is implicit and unversioned.
- **Impact:** Hard to reason about upgrades/rollbacks; risky column drops/renames; no audit of applied changes; drift between environments.
- **Root cause:** Migrations were deferred in favor of idempotent bootstrap.
- **Fix (root-cause):** Adopt **versioned migrations** (`golang-migrate` or `goose`) with a `schema_migrations` table; snapshot the current schema as the baseline migration; require every schema change to ship as a numbered up/down pair; run migrations as an explicit deploy step (with a `--migrate` mode) rather than implicitly on boot.
- **Preserve-behavior note:** The baseline migration reproduces today's schema exactly; behavior is unchanged, upgrades become auditable and reversible.

---

### GROUP I — Observability & test blind spots 🟡 MEDIUM

**I1. Observability exporters are no-op stubs**
- **Location:** `orchestrator/internal/observability/exporters.go:15-29` (`NewPrometheusRemoteWriteExporter` returns no-op), `otel.go`/`alerting.go` TODOs (8 of 9 non-test TODOs live here).
- **Impact:** No external metrics/traces/alert delivery → running in production partially blind.
- **Root cause:** Feature scaffolded, exporters not implemented.
- **Fix (root-cause):** Implement Prometheus remote-write / OTLP exporters and webhook alert delivery; wire alerting to the (already-real) metrics registry. Gate `/metrics` with the existing `MetricsToken` (already supported).

**I2. `internal/siem` untested**
- **Location:** `orchestrator/internal/siem` (446 LOC, 0 test files) — the only sizeable untested package.
- **Impact:** Regressions in SIEM correlation go undetected.
- **Root cause:** Test coverage gap.
- **Fix:** Add unit + integration tests (harness exists); add a **coverage gate** in CI so no package ships large + untested again.

---

### GROUP J — Repository hygiene 🟡 MEDIUM

**J1. 53MB vendored OpenAEV source (unused) + licensing exposure**
- **Location:** `openaev-main/` (4,759 files; Filigran OpenAEV, dual-licensed Apache-2.0 CE / proprietary EE). Not built, not served; Audspect integrates via the clean `orchestrator/internal/openaev` connector to an *external* instance.
- **Impact:** Repo bloat + licensing risk (EE-headered files vendored into a commercial repo; even Apache CE requires retaining NOTICE/attribution).
- **Root cause:** A reference checkout was dumped into the tree instead of referenced as a dependency.
- **Fix (root-cause):** Delete `openaev-main/`; document the external OpenAEV version the connector targets. If any of it is genuinely needed, pin it as a proper dependency with its LICENSE/NOTICE preserved.

**J2. Unrelated `.agents/` marketing toolkit committed**
- **Location:** `.agents/` (157 files) — generic marketing-skills toolkit with "Shifa Mehendi Nails / Ayisha Bridal Mehendi" placeholder content.
- **Fix:** Remove; it's unrelated to BAS.

**J3. ~40MB media/binaries at repo root**
- **Location:** `*.mp4`, `*.PNG`, sample PDFs, a 10MB `data_exfiltration_csv_report.csv`, `*.docx`, `BASAgent.pdb`.
- **Impact:** Slow clones, bloated history.
- **Fix:** Move to Git LFS or an artifact store; keep the repo to source + small assets.

---

## 7. Cross-cutting root-cause themes

Most findings trace to **five** deeper causes. Fix these and the individual issues stop recurring:

1. **No enforced secret-management boundary.** → Env/secret-manager only + pre-commit + CI secret scanning (fixes A; prevents future leaks).
2. **Trust modeled as one shared secret over an unpinned channel.** → Per-agent identity + pinning + payload signing + local guardrail (fixes B/E; shrinks blast radius from "fleet RCE" to "one host, reversible").
3. **Security features shipped as scaffolding, enforcement deferred.** → Turn on what's already built: RLS `ENABLE/FORCE`, DB role hardening, JWT entropy check (fixes C, F4).
4. **Convenience defaults left in production paths.** → CORS `*`, WS `CheckOrigin=true`, plaintext `ws://`, `==` secret compare, permissive placeholders (fixes F, B2/B3).
5. **Organic growth without structural guardrails.** → Versioned migrations, one canonical escaper + CSP, coverage gate, LFS, dependency pinning (fixes G, H, I, J).

---

## 8. Prioritized remediation roadmap

### Wave 0 — Today (contain the breach)
- **A1:** Rotate/revoke all committed secrets; purge history; add `.gitignore` + gitleaks pre-commit + CI gate.

### Wave 1 — Sprint 1 (shrink the RCE blast radius)
- **B2:** Move agent secret to a header; remove query-param fallback (server-side, after agents update).
- **B3:** Refuse plaintext `ws://` outside `--dev`; pin orchestrator SPKI in the agent.
- **F1/F2/F3/F4:** Constant-time secret compare; lock CORS; validate browser WS origin; enforce JWT-secret entropy.

### Wave 2 — Sprint 2–3 (finish the trust model)
- **B1:** Per-agent credentials (mTLS or per-agent tokens) at enrollment; keep a short-lived rotated enrollment secret.
- **B4 + B5:** Sign dispatched command bundles (reuse RSA infra); agent verifies against pinned key; add a signed, tier-aware destructive-action guardrail (fail-closed, mapped to Posture/Telemetry/Lab).
- **D1:** Authenticode + macOS notarization in the release pipeline.

### Wave 3 — Sprint 4+ (production maturity)
- **C1:** Enable + FORCE RLS on all tenant tables; route all request DB access through `WithTenant`; turn on DB role hardening; add cross-tenant isolation tests. **Or** formally scope to single-tenant on-prem.
- **H1:** Introduce versioned migrations with a baseline snapshot.
- **I1/I2:** Implement observability exporters + alerting; test `siem`; add a coverage gate.
- **G1:** Single canonical escaper + audit all `innerHTML` sites + CSP.

### Wave 4 — Cleanup & strategy
- **J1/J2/J3:** Prune `openaev-main/`, `.agents/`, move media to LFS.
- **D2:** Selective agent obfuscation (defense-in-depth only).
- **Strategy:** Decide Mythos (build the adaptive path from existing telemetry+attack-path data, or retire from the pitch). Deliver IRDAI/CERT-In coverage or label as roadmap. Land one Phase-2 tool (Stratus for cloud is the natural next).
- **Docs:** Reconcile v1.7.3 → v1.7.5 version drift.

---

## 9. What to keep — strong security posture

These are already right; do not regress them:

- **Fully parameterized SQL** — zero string-built queries across the orchestrator.
- **PBKDF2-HMAC-SHA256 @ 310K iterations**, self-describing hashes, bcrypt upgrade-on-login, constant-time password compare.
- **`CryptoSelfTest()` KATs at boot** (fatal on failure).
- **JWT HS256 with explicit signing-method verification** (no `alg=none`/confusion).
- **~130 fine-grained RBAC permissions** across admin/analyst/viewer; sensitive actions admin-gated; viewer has zero writes.
- **RSA-signed licenses + RSA-signed binary integrity manifest** (tampered manifest is fatal) + **filesystem tamper watcher** + **HMAC-hash-chained tamper log**.
- **DPAPI machine-scoped secret storage** on Windows; ACL/DACL service hardening + auto-recovery.
- **Agent execution safety mechanics:** snapshot/auto-revert, per-step cleanup with reconciliation, domain-controller interlock, destructive-prompt auto-decline, Job-Object tree-kill, disconnect watchdog, 3-layer timeouts, circuit breakers.
- **~1:1 test-to-code ratio** with real containerized Postgres integration tests.
- **Honest documentation** (mockup vs. reality separation; no invented compliance mappings).

---

## 10. Evidence appendix

| Metric | Value | Source |
|---|---|---|
| Total files in repo | 6,930 | `git ls-files` |
| Commits | 2,219 | `git log` |
| Orchestrator Go LOC | 167,533 total / 87,743 non-test | `git ls-files … xargs cat wc -l` |
| Orchestrator test files | 447 | `find -name *_test.go` |
| TODO/FIXME/HACK (non-test Go) | 9 | `grep -rIn` |
| `panic(` in non-test Go | 3 | `grep -rIn` |
| String-built SQL (`Sprintf`+SQL) | 0 | `grep -rIn` |
| RLS `ENABLE/FORCE` | commented out | `postgres.go:1256-1257` |
| API routes | ~183–375 (subrouters) | route grep |
| Agent Go files / tests | 111 / 66 | `find` |
| Scenarios (signed YAML) | 110 (+110 `.sig`) | `find scenarios` |
| ATT&CK techniques referenced | 170 unique | scenario grep |
| Compliance frameworks loaded | 7 (CERT-In, IRDAI, RBI, SEBI-CSCRF, NIST, ISO27001, PCI) | live `/api/compliance/frameworks` |
| Frontend SPA | 22,235 lines, ~1.34MB, single file | `wc -l wwwroot/index.html` |
| `innerHTML` sinks | 455 | frontend grep |
| Vendored OpenAEV | 4,759 files, ~53MB | `openaev-main/` |
| Live boot | orchestrator on :9000, DB ok, 81 scenarios, admin login OK | local run 2026-09-26 |

**Key files referenced:** `cmd/server/main.go`, `internal/api/handlers.go`, `internal/db/postgres.go`, `internal/db/tenant.go`, `internal/db/harden.go`, `internal/ws/hub.go`, `internal/auth/{jwt,password,pbkdf2}.go`, `internal/license/license.go`, `internal/integrity/signing.go`, `agent/protocol/websocket.go`, `agent/identity.go`, `agent/agent.go`, `agent/sched/riskgate.go`, `api/main.py`, `packaging/build.sh`, `packaging/compose/docker-compose.yml`.

---

*Prepared from a full static review plus a live local deployment. Secret values are intentionally omitted throughout. For the top items (B1–B4), a follow-up can produce the concrete code changes (per-agent enrollment + header auth + SPKI pinning + command signing) as reviewed patches.*
