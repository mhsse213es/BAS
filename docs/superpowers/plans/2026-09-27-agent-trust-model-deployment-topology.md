# Agent Trust Model Deployment Topology Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the already-shipped B1/B3 agent-trust-model code (deployment CA, per-agent mTLS, four-listener topology) actually deployable — fix the container startup, CA persistence, port publishing, dashboard access, and healthchecks that today would crash-loop or lock out the fleet.

**Architecture:** A new 4th orchestrator listener (`dashboardSrv`, port 9543, server-cert-only TLS) carries browser traffic off the now-mTLS-only 9443. A named Docker volume persists the CA across container recreates. The Dockerfile's distroless final stage gets a writable, correctly-owned CA directory via `COPY --chown` from an earlier build stage (no shell exists in the final stage to run `mkdir`/`chown` directly). Both healthchecks move to the already-unauthenticated `:9444/health`. `install.sh`/`uninstall.sh`/`setup.conf.template`/the existing upgrade guide are updated to match, and a previously-dormant `BAS_TLS`/`TLS_CERT`/`TLS_KEY` option (install.sh already plumbs the files to disk; the orchestrator never read them) is wired up for the new dashboard listener.

**Tech Stack:** Docker/Dockerfile, Docker Compose, bash (install.sh/uninstall.sh), Go (`orchestrator/config`, `orchestrator/cmd/server`), Markdown docs.

**Spec:** `docs/superpowers/specs/2026-09-27-agent-trust-model-deployment-topology-design.md` — this plan implements all 8 sections. Section 1's proposed dashboard port (8443) is corrected to **9543** in this plan: `packaging/compose/setup.conf.template`'s own documented "known conflicts" list flags 8443/8444 as colliding with Trellix/McAfee ePO, Carbon Black, and Forcepoint — exactly the kind of security stack this product's BFSI customers are likely already running. 9543 is one of that same file's listed safe alternatives and stays in the same 9xxx neighborhood as the other three listeners (9000/9443/9444).

## Global Constraints

- Distroless `nonroot` user is UID 65532, GID 65532 — verified directly against `gcr.io/distroless/static-debian12:nonroot`'s `/etc/passwd` (not assumed).
- New dashboard listener port: **9543** (not 8443 — see rationale above).
- Named volume for the CA: `audspect-pki-data`, mounted at `/etc/audspect/pki` (matches `config.go`'s existing `PKIDir` default — no env var override needed).
- `docs/guides/upgrade-guide.md` is the existing, real upgrade-procedures doc (v1.7.5, actively referenced by `install.sh --upgrade`'s own flow) — the migration runbook content is added to this file, not a new separate document.
- `packaging/compose/docker-compose.prod.yml` is a resource-limits overlay only (no port/volume content) — confirmed, out of scope for this plan.
- Bash script changes (`install.sh`, `uninstall.sh`) are verified via `shellcheck` (if available in this environment — check with `which shellcheck` before relying on it) plus a documented manual dry-run procedure per task, not TDD — bash has no equivalent unit-test cycle for these changes. Go changes (`config.go`, `main.go`) and the Dockerfile follow real TDD/build-verification.

## Review Focus

- **Two listener ports resolving equal outside docker-compose's explicit overrides** (e.g. a bare config-file install that sets `HTTP_PORT_LEGACY=9443` by mistake, matching `HTTPPort`) — must fail at startup with a clear error naming both colliding values, not a bare `log.Fatalf` from whichever `ListenAndServeTLS`/`ListenAndServe` call loses the bind race. Pinned in Task 3.
- **A named volume that doesn't exist yet on first `docker compose up`** (fresh install, not an upgrade) — Docker must initialize it from the image's baked-in `/etc/audspect/pki` directory (empty, but with correct `nonroot` ownership) without erroring, and the orchestrator's first-ever CA generation must succeed into that fresh volume. Pinned in Task 2.
- **`BAS_TLS=false` (the default) still works correctly for the dashboard listener** — the new `dashboardSrv` must fall back to the CA's own self-signed certificate when no customer cert is configured, not fail to start. Pinned in Task 4.
- **An operator upgrading from a pre-this-plan install** (today's single `9443` plaintext listener, agents configured for `http://host:9443`) who runs `install.sh --upgrade` *without* first reading the new migration-runbook section — the upgrade must not silently strand the existing fleet with zero indication of what happened; `install.sh --upgrade`'s own output should surface a clear warning when it detects this exact upgrade path. Pinned in Task 6.
- **`runHealthcheck()`'s new HTTPS call against 9444 when the CA/cert files are somehow missing or corrupt** (e.g. `PKI_DIR` volume mount failed) — must fail the healthcheck cleanly (return 1), not panic the healthcheck subprocess itself, which would produce a confusing Docker-level error instead of a clean "unhealthy" status. Pinned in Task 4.

---

### Task 1: Dockerfile — writable, correctly-owned CA directory for `nonroot`

**Files:**
- Modify: `orchestrator/Dockerfile:112-137` (the `builder` stage), `:139-160` (the final distroless stage)

**Interfaces:**
- Produces: `/etc/audspect/pki` present in the final image, owned by `nonroot:nonroot` (65532:65532) — consumed by Task 2's volume mount (Docker initializes a fresh named volume from this directory's existing content/ownership).

- [ ] **Step 1: Add the directory-seeding step to the `builder` stage**

In `orchestrator/Dockerfile`, inside the existing `builder` stage (the one that already has `RUN apk add --no-cache git && go install mvdan.cc/garble@v0.17.0`, around line 124), add a seed-directory step. Insert this right after the existing `RUN apk add --no-cache git && \` line (before `WORKDIR /src`):

```dockerfile
RUN apk add --no-cache git && \
    go install mvdan.cc/garble@v0.17.0
# Seed the CA directory with correct nonroot ownership here, in a stage that
# still has a shell -- gcr.io/distroless/static-debian12 (the final stage)
# has none, so a RUN mkdir/chown there is impossible. This directory is
# COPY --chown'd into the final stage below and becomes the mount point for
# the audspect-pki-data named volume (packaging/compose/docker-compose.yml) --
# Docker initializes a fresh named volume from the image's existing content
# and ownership at that path, so this seed step is what makes the volume
# writable by nonroot from the very first container start.
# 65532:65532 is gcr.io/distroless/static-debian12:nonroot's real nonroot
# UID:GID -- verified directly against the image's /etc/passwd, not assumed.
RUN mkdir -p /pki-seed && chown 65532:65532 /pki-seed
WORKDIR /src
```

- [ ] **Step 2: Copy the seeded directory into the final stage**

In the final stage (`FROM gcr.io/distroless/static-debian12`, around line 139), add the copy before `USER nonroot`:

```dockerfile
COPY --from=art-fetcher /content /content
COPY --from=builder --chown=65532:65532 /pki-seed /etc/audspect/pki
ENV ART_DIR=/art-atomics
ENV ART_PAYLOAD_DIR=/art-payloads
ENV KEV_FILE=/content/cisa-kev.json
USER nonroot
EXPOSE 9000
```

(The `COPY --from=art-fetcher /content /content` line already exists immediately before `ENV ART_DIR=...` — insert the new `COPY --from=builder` line directly after it, in that exact position, so the ordering stays deterministic.)

Also update the stale `EXPOSE 9000` (a leftover from before this product had multiple listeners) to reflect the real port set:

```dockerfile
EXPOSE 9000 9443 9444 9543
```

- [ ] **Step 3: Build and smoke-test as a real container**

This is infrastructure verification, not a Go/TDD cycle — there is no "failing test" to write first for a Dockerfile. Verify by building the real image and running it as `nonroot`:

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud
docker build -t bas-orchestrator-test --target builder -f orchestrator/Dockerfile . 2>&1 | tail -20
```

Expected: build succeeds (this only builds through the `builder` stage, fast — full multi-stage build is expensive and not needed to verify this specific change; the final-stage `COPY --chown` syntax is verified next).

```bash
docker build -t bas-orchestrator-test -f orchestrator/Dockerfile . 2>&1 | tail -40
```

Expected: full build succeeds (this DOES take a while — the image pulls/builds the agent binaries, ART atomics, etc. — this is the existing build, not something this task made slower). If this is impractical in the current environment (no Docker, or a very slow full build), it's acceptable to verify only Step 3's builder-stage build plus a manual read-through of the final Dockerfile diff, and note this limitation in the report — say so explicitly rather than silently skipping verification.

```bash
docker run --rm --entrypoint="" bas-orchestrator-test /orchestrator --healthcheck; echo "exit: $?"
```

Expected: this will still report unhealthy/exit 1 at this point (no listener is running, and `--healthcheck` isn't fixed to point at 9444 until Task 4) — that's fine, this step is only confirming the binary runs at all under `nonroot` without immediately crashing on a permissions error. To specifically verify the CA directory is writable by `nonroot`, run:

```bash
docker create --entrypoint="" bas-orchestrator-test /orchestrator --dummy 2>/dev/null | xargs -I{} sh -c 'docker cp orchestrator/Dockerfile {}:/etc/audspect/pki/test-write-check 2>&1; echo "write test exit: $?"; docker rm {} >/dev/null'
```

Expected: the `docker cp` write succeeds (exit 0) — proving the directory is genuinely writable by whatever user the container runs as, not just present.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/Dockerfile
git commit -m "fix(docker): writable, persisted CA directory for nonroot user"
```

---

### Task 2: docker-compose.yml — named CA volume + publish all four listener ports

**Files:**
- Modify: `packaging/compose/docker-compose.yml:181-230` (orchestrator's `volumes:` and `ports:` blocks), `:250-258` (top-level `volumes:` block)

**Interfaces:**
- Consumes: `/etc/audspect/pki` seeded with correct ownership (Task 1).
- Produces: `audspect-pki-data` named volume, ports 9000/9443/9444/9543 all published — consumed by Task 4's `dashboardSrv` (needs 9543 published to be reachable) and by the manual verification in this task itself.

- [ ] **Step 1: Add the named volume mount**

In `packaging/compose/docker-compose.yml`, inside the `orchestrator` service's existing `volumes:` list, add (anywhere in the list — grouping it near the top for visibility is reasonable):

```yaml
    volumes:
      # Deployment CA (per-agent mTLS trust root, orchestrator/internal/pki) --
      # persisted across container recreates. Losing this invalidates every
      # already-issued agent certificate AND every agent's locally-cached CA
      # root fingerprint -- a fleet-wide lockout, not just data loss. Matches
      # the audspect-postgres-data pattern below exactly.
      - audspect-pki-data:/etc/audspect/pki
      # scenarios is read-write: ...
```

(Insert as the first entry, before the existing `- ./scenarios:/scenarios` line, so it's the first thing a reader sees given how consequential losing it is.)

- [ ] **Step 2: Publish the three additional listener ports**

In the same service's existing `ports:` list, alongside the existing `- "${BAS_PORT:-9443}:9443"` line, add:

```yaml
    ports:
      - "${BAS_PORT:-9443}:9443"
      - "${BAS_ENROLL_PORT:-9444}:9444"
      - "${BAS_LEGACY_PORT:-9000}:9000"
      - "${BAS_DASHBOARD_PORT:-9543}:9543"
      # Bound to a specific host IP, never the 0.0.0.0 wildcard: ...
```

- [ ] **Step 3: Change `HTTP_PORT`'s meaning to match — it's now the mTLS port, not the dashboard port**

The existing `environment:` block already sets `HTTP_PORT: "9443"` — this line is unchanged (9443 stays the mTLS port's env var, matching `config.go`'s `HTTPPort` field), but add the three new env vars the orchestrator's Go code already reads (`EnrollHTTPPort`/`LegacyHTTPPort` from the prior B1/B3 plan; the new dashboard port from Task 3 of this plan) right below it:

```yaml
      HTTP_PORT:        "9443"
      HTTP_PORT_ENROLL: "9444"
      HTTP_PORT_LEGACY: "9000"
      HTTP_PORT_DASHBOARD: "9543"
```

- [ ] **Step 4: Add the top-level named volume**

In the file's top-level `volumes:` block:

```yaml
volumes:
  audspect-postgres-data:
    driver: local
  audspect-pki-data:
    driver: local
```

- [ ] **Step 5: Validate and manually verify persistence**

```bash
cd packaging/compose
docker compose config >/dev/null && echo "compose file valid"
```

Expected: no YAML/schema errors.

A full persistence-across-recreate test requires the complete stack (Postgres, valid `.env`, a license file) and is impractical to fully automate in this plan's scope — instead, verify the volume mechanics directly:

```bash
docker volume create audspect-pki-data-test
docker run --rm -v audspect-pki-data-test:/etc/audspect/pki bas-orchestrator-test /orchestrator --dummy 2>/dev/null; true
docker run --rm -v audspect-pki-data-test:/etc/audspect/pki --entrypoint="" bas-orchestrator-test sh -c 'ls -la /etc/audspect/pki' 2>&1 || \
  docker run --rm -v audspect-pki-data-test:/etc/audspect/pki alpine ls -la /etc/audspect/pki
docker volume rm audspect-pki-data-test
```

Expected: the directory exists inside the volume with the seeded ownership from Task 1 — confirms Docker's volume-initialization-from-image-content behavior works as this design depends on. Note in the report if the full real end-to-end persistence check (start orchestrator against a real Postgres, recreate the container, confirm the CA's public key is byte-identical before/after) is deferred to manual QA against a real staging-like environment rather than done in this task, since that requires the full stack.

- [ ] **Step 6: Commit**

```bash
git add packaging/compose/docker-compose.yml
git commit -m "feat(compose): persist CA in a named volume, publish all four listener ports"
```

---

### Task 3: config.go — reject colliding listener ports, add dashboard TLS cert fields

**Files:**
- Modify: `orchestrator/config/config.go:11-137` (the `Config` struct and `Load()`'s defaults/env-overrides), `:277-297` (the final validation block before `Load()` returns)
- Test: `orchestrator/config/config_test.go` (existing file from the prior plan — add to it)

**Interfaces:**
- Produces: `Config.DashboardHTTPPort int` (default `9543`, env `HTTP_PORT_DASHBOARD`), `Config.DashboardTLSCertPath string` (env `TLS_CERT`), `Config.DashboardTLSKeyPath string` (env `TLS_KEY`), and a new error returned by `Load()` when any two of `HTTPPort`/`EnrollHTTPPort`/`LegacyHTTPPort`/`DashboardHTTPPort` are equal — consumed by Task 4's `main.go` changes.

- [ ] **Step 1: Write the failing tests**

```go
// Add to orchestrator/config/config_test.go
func TestLoad_DashboardDefaults(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DashboardHTTPPort != 9543 {
		t.Errorf("DashboardHTTPPort = %d, want 9543", cfg.DashboardHTTPPort)
	}
	if cfg.DashboardTLSCertPath != "" || cfg.DashboardTLSKeyPath != "" {
		t.Errorf("DashboardTLSCertPath/DashboardTLSKeyPath should default empty (self-signed CA cert fallback), got %q/%q", cfg.DashboardTLSCertPath, cfg.DashboardTLSKeyPath)
	}
}

func TestLoad_DashboardEnvOverrides(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("HTTP_PORT_DASHBOARD", "9555")
	os.Setenv("TLS_CERT", "/etc/bas/certs/bas.crt")
	os.Setenv("TLS_KEY", "/etc/bas/certs/bas.key")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("HTTP_PORT_DASHBOARD")
	defer os.Unsetenv("TLS_CERT")
	defer os.Unsetenv("TLS_KEY")

	cfg, err := Load("/nonexistent/config.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DashboardHTTPPort != 9555 {
		t.Errorf("DashboardHTTPPort = %d, want 9555", cfg.DashboardHTTPPort)
	}
	if cfg.DashboardTLSCertPath != "/etc/bas/certs/bas.crt" {
		t.Errorf("DashboardTLSCertPath = %q, want /etc/bas/certs/bas.crt", cfg.DashboardTLSCertPath)
	}
	if cfg.DashboardTLSKeyPath != "/etc/bas/certs/bas.key" {
		t.Errorf("DashboardTLSKeyPath = %q, want /etc/bas/certs/bas.key", cfg.DashboardTLSKeyPath)
	}
}

func TestLoad_RejectsCollidingListenerPorts(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	os.Setenv("HTTP_PORT", "9443")
	os.Setenv("HTTP_PORT_LEGACY", "9443") // deliberately colliding with HTTP_PORT
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")
	defer os.Unsetenv("HTTP_PORT")
	defer os.Unsetenv("HTTP_PORT_LEGACY")

	_, err := Load("/nonexistent/config.json")
	if err == nil {
		t.Fatal("expected Load to reject colliding HTTP_PORT and HTTP_PORT_LEGACY (both 9443), got nil error")
	}
}

func TestLoad_DistinctPortsSucceed(t *testing.T) {
	os.Setenv("DATABASE_URL", "postgres://test")
	os.Setenv("JWT_SECRET", "test-secret")
	defer os.Unsetenv("DATABASE_URL")
	defer os.Unsetenv("JWT_SECRET")

	// All four ports at their real defaults (9443/9444/9000/9543) -- must
	// NOT be rejected by the same validation the collision test exercises.
	if _, err := Load("/nonexistent/config.json"); err != nil {
		t.Fatalf("Load with all-default (distinct) ports should succeed, got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./config/... -run 'TestLoad_Dashboard|TestLoad_RejectsColliding|TestLoad_DistinctPorts' -v`
Expected: FAIL — `cfg.DashboardHTTPPort undefined`, and `TestLoad_RejectsCollidingListenerPorts` fails because `Load` currently returns no error for colliding ports.

- [ ] **Step 3: Add the fields, defaults, env overrides, and validation**

In `orchestrator/config/config.go`, add to the `Config` struct (right after the existing `LegacyHTTPPort int` field, line ~116):

```go
	// DashboardHTTPPort serves the browser dashboard (StaticHandler + JWT
	// API + /ws/browser) over TLS with NO client-cert requirement --
	// separate from the mTLS agent listener (HTTPPort) so a browser (which
	// has no client certificate) can reach it. See
	// docs/superpowers/specs/2026-09-27-agent-trust-model-deployment-topology-design.md.
	// DashboardTLSCertPath/DashboardTLSKeyPath, if both set, let an operator
	// supply a properly-trusted certificate for this listener instead of
	// the deployment CA's own self-signed one (which browsers show a
	// warning for) -- wires up install.sh's pre-existing BAS_TLS/TLS_CERT/
	// TLS_KEY option, previously dormant (the orchestrator never read it).
	DashboardHTTPPort    int    `json:"dashboard_http_port,omitempty"`
	DashboardTLSCertPath string `json:"dashboard_tls_cert_path,omitempty"`
	DashboardTLSKeyPath  string `json:"dashboard_tls_key_path,omitempty"`
```

In `Load`'s default-value struct literal (right after `LegacyHTTPPort: 9000,`):

```go
		DashboardHTTPPort: 9543,
```

In the env-override section (right after the existing `HTTP_PORT_LEGACY` block):

```go
	if v := os.Getenv("HTTP_PORT_DASHBOARD"); v != "" {
		fmt.Sscanf(v, "%d", &cfg.DashboardHTTPPort)
	}
	if v := os.Getenv("TLS_CERT"); v != "" {
		cfg.DashboardTLSCertPath = v
	}
	if v := os.Getenv("TLS_KEY"); v != "" {
		cfg.DashboardTLSKeyPath = v
	}
```

Add the port-collision validation right before `Load`'s final `return cfg, nil` (after the existing `jwtFromFile`/`agentFromFile` warning block, around line 294):

```go
	// Reject colliding listener ports at startup rather than letting two
	// http.Server goroutines race to bind the same port, where the loser's
	// log.Fatalf is much less diagnosable than a clear error naming both
	// values up front.
	ports := map[string]int{
		"HTTP_PORT":           cfg.HTTPPort,
		"HTTP_PORT_ENROLL":    cfg.EnrollHTTPPort,
		"HTTP_PORT_LEGACY":    cfg.LegacyHTTPPort,
		"HTTP_PORT_DASHBOARD": cfg.DashboardHTTPPort,
	}
	seen := make(map[int]string, len(ports))
	for name, port := range ports {
		if other, ok := seen[port]; ok {
			return nil, fmt.Errorf("%s and %s both resolve to port %d -- listener ports must be distinct", other, name, port)
		}
		seen[port] = name
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./config/... -v`
Expected: PASS (all tests in the package, including the existing ones from the prior plan)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/config/config.go orchestrator/config/config_test.go
git commit -m "feat(config): dashboard listener port/TLS-cert config, reject colliding listener ports"
```

---

### Task 4: main.go — add `dashboardSrv`, fix `runHealthcheck()` to probe 9444

**Files:**
- Modify: `orchestrator/cmd/server/main.go:69-93` (`runHealthcheck`), `:782-866` (listener construction, startup goroutines, graceful shutdown)
- Test: `orchestrator/cmd/server/listeners_test.go` (existing file — add to it), `orchestrator/cmd/server/healthcheck_test.go` (existing file — add to it, confirm exact name via `ls orchestrator/cmd/server/*healthcheck*`)

**Interfaces:**
- Consumes: `cfg.DashboardHTTPPort`, `cfg.DashboardTLSCertPath`, `cfg.DashboardTLSKeyPath` (Task 3).
- Produces: a 4th running `*http.Server` (`dashboardSrv`), `runHealthcheck()` probing `https://127.0.0.1:9444/health`, `resolveDashboardTLSCert(cfg config.Config, fallback tls.Certificate) (tls.Certificate, error)`.

`orchestrator/cmd/server/listeners_test.go`'s new tests (`TestResolveDashboardTLSCert_*`) need these imports added if not already present: `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `crypto/x509/pkix`, `encoding/pem`, `math/big`, `os`, `path/filepath`, and `github.com/audspect/bas/config` (check the real import path/alias by reading how `main.go` itself imports the config package).

- [ ] **Step 1: Write the failing tests**

```go
// Add to orchestrator/cmd/server/listeners_test.go
// TestDashboardListener_AcceptsNoClientCert confirms the new dashboard
// listener, like the enrollment listener, completes a TLS handshake with
// NO client certificate presented -- a browser has none, and this listener
// must not require one (that's the whole reason it exists separately from
// the mTLS listener).
func TestDashboardListener_AcceptsNoClientCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	serverCert, err := ca.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate())

	dashboardSrv := newTLSListenerForTest(t, serverCert, tls.NoClientCert, pool)
	defer dashboardSrv.Close()

	clientCfg := &tls.Config{InsecureSkipVerify: true} // no SANs on the CA's own cert, see existing tests in this file
	if _, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", dashboardSrv.Listener.Addr().String(), clientCfg); err != nil {
		t.Errorf("dashboard listener rejected a no-client-cert handshake: %v", err)
	}
}
```

```go
// Add to orchestrator/cmd/server/healthcheck_test.go (or whatever the
// existing healthcheck test file is actually named -- confirm with
// `ls orchestrator/cmd/server/*healthcheck*` before writing this; the
// existing TestRunHealthcheck_OKResponse/NonOKResponse/NothingListening
// tests already in that file show the exact pattern to match).
func TestRunHealthcheck_ProbesEnrollPortOverHTTPS(t *testing.T) {
	// This test's exact shape depends on how the existing
	// TestRunHealthcheck_* tests in this file construct their test
	// server (plain httptest.Server vs httptest.NewTLSServer) -- read
	// those first and mirror the pattern. The behavior to prove: with
	// HTTP_PORT_ENROLL set to a real httptest TLS server's port (server
	// certificate irrelevant -- runHealthcheck must skip verification,
	// same self-signed-CA reasoning as elsewhere in this codebase) and
	// HTTP_PORT set to something with nothing listening, runHealthcheck()
	// returns 0 (healthy) -- proving it's actually probing the ENROLL
	// port, not the (now-mTLS, healthcheck-hostile) HTTP_PORT.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	enrollPort := srv.Listener.Addr().(*net.TCPAddr).Port
	t.Setenv("HTTP_PORT_ENROLL", fmt.Sprintf("%d", enrollPort))
	t.Setenv("HTTP_PORT", "1") // deliberately nothing listening here -- proves this is NOT what's being probed

	if got := runHealthcheck(); got != 0 {
		t.Errorf("runHealthcheck() = %d, want 0 (healthy) when HTTP_PORT_ENROLL points at a real /health responder", got)
	}
}
```

```go
// Add to orchestrator/cmd/server/listeners_test.go
// TestResolveDashboardTLSCert_FallsBackToCAWhenNoCustomCertConfigured pins
// the Review Focus item: BAS_TLS=false (the default -- no TLS_CERT/TLS_KEY
// configured) must make the dashboard listener use the CA's own
// certificate, not fail to start or use a zero-value tls.Certificate.
func TestResolveDashboardTLSCert_FallsBackToCAWhenNoCustomCertConfigured(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrGenerateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateCA: %v", err)
	}
	fallback, err := ca.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}

	got, err := resolveDashboardTLSCert(config.Config{}, fallback) // no DashboardTLSCertPath/DashboardTLSKeyPath set
	if err != nil {
		t.Fatalf("resolveDashboardTLSCert: %v", err)
	}
	if len(got.Certificate) == 0 || string(got.Certificate[0]) != string(fallback.Certificate[0]) {
		t.Error("expected the CA's own certificate to be used when no custom cert is configured")
	}
}

// TestResolveDashboardTLSCert_UsesCustomCertWhenConfigured pins the other
// half: when TLS_CERT/TLS_KEY ARE configured (BAS_TLS=true), the dashboard
// listener must use that certificate, not the CA's.
func TestResolveDashboardTLSCert_UsesCustomCertWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	// Build a throwaway self-signed cert+key pair on disk to stand in for
	// an operator-supplied certificate -- reuses the same
	// crypto/x509.CreateCertificate pattern already established in this
	// codebase's other tests (see agent/certstore_test.go's
	// selfSignedTestCertPEM for the reference shape).
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "custom-dashboard-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPath := filepath.Join(dir, "custom.crt")
	keyPath := filepath.Join(dir, "custom.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	fallback := tls.Certificate{Certificate: [][]byte{[]byte("not-the-real-fallback")}}
	cfg := config.Config{DashboardTLSCertPath: certPath, DashboardTLSKeyPath: keyPath}

	got, err := resolveDashboardTLSCert(cfg, fallback)
	if err != nil {
		t.Fatalf("resolveDashboardTLSCert: %v", err)
	}
	if string(got.Certificate[0]) == "not-the-real-fallback" {
		t.Error("expected the custom cert to be used, got the fallback")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./cmd/server/... -run 'TestDashboardListener|TestRunHealthcheck_ProbesEnrollPort|TestResolveDashboardTLSCert' -v`
Expected: FAIL — `TestDashboardListener_AcceptsNoClientCert` is a new standalone test (passes trivially once written, same as the existing `TestThreeListeners_*` test's own Step 2 note — it pins the design property before Step 3 wires the real listener to match); `TestRunHealthcheck_ProbesEnrollPortOverHTTPS` fails because `runHealthcheck()` still reads `HTTP_PORT` over plain HTTP; both `TestResolveDashboardTLSCert_*` tests fail with `resolveDashboardTLSCert undefined`.

- [ ] **Step 3: Fix `runHealthcheck()` and add `dashboardSrv`**

Replace `runHealthcheck()` (lines 69-93):

```go
// runHealthcheck is invoked as `orchestrator --healthcheck` by Docker's
// container HEALTHCHECK (packaging/compose/docker-compose.yml). Probes the
// enrollment listener (:9444), not the mTLS listener (:9443) -- 9443
// requires a client certificate, which this in-process self-check has no
// way to present, so a probe against it would always report unhealthy
// regardless of real app health. GET /health on 9444 is unauthenticated by
// design (api.MountEnrollment). The image is gcr.io/distroless/
// static-debian12 -- no shell, no wget/curl -- so this must be the binary
// checking itself in-process via an argv flag (array-form CMD, no shell
// involved). Reads HTTP_PORT_ENROLL directly rather than going through
// config.Load(), since that requires DATABASE_URL/JWT_SECRET this
// short-lived self-check has no need for. Returns a process exit code (0 =
// healthy) -- that exit code is the only signal Docker's HEALTHCHECK reads.
func runHealthcheck() int {
	port := 9444
	if v := os.Getenv("HTTP_PORT_ENROLL"); v != "" {
		fmt.Sscanf(v, "%d", &port)
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			// The enrollment listener's server identity is the deployment
			// CA's own self-signed certificate (see ca.TLSCertificate()) --
			// this is a loopback liveness probe, not a security boundary,
			// so skipping verification here is correct, not a shortcut.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/health", port))
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
```

This requires adding `"crypto/tls"` to the imports at the top of `main.go` if not already present (it already is, per the existing `mtlsSrv`/`enrollSrv` TLS config code below).

Add a new package-level function, placed after `runHealthcheck()` and before `main()`:

```go
// resolveDashboardTLSCert picks the certificate the dashboard listener
// presents: an operator-supplied one (cfg.DashboardTLSCertPath/KeyPath --
// install.sh's BAS_TLS/TLS_CERT/TLS_KEY option) when both are set, or
// fallback (the deployment CA's own certificate, same as the mTLS and
// enrollment listeners use) otherwise. Extracted as its own function --
// rather than left inline in main() -- specifically so this decision is
// unit-testable: BAS_TLS=false (fallback) is the default for every
// existing and new install, so its behavior needs direct test coverage,
// not just a read-through of main()'s startup sequence.
func resolveDashboardTLSCert(cfg config.Config, fallback tls.Certificate) (tls.Certificate, error) {
	if cfg.DashboardTLSCertPath == "" || cfg.DashboardTLSKeyPath == "" {
		return fallback, nil
	}
	return tls.LoadX509KeyPair(cfg.DashboardTLSCertPath, cfg.DashboardTLSKeyPath)
}
```

(Check the exact import alias `main.go` already uses for the `orchestrator/config` package — e.g. `config.Config` vs. a different local name — and match it; the existing `cfg := config.Load(...)` call earlier in this same file shows the real usage to mirror.)

Add `dashboardSrv` construction right after the existing `legacySrv` block (after line 831, before the `go func()` goroutines):

```go
	// 9543 (default) — browser dashboard: static SPA, JWT-authenticated
	// API, /ws/browser. Server-cert-only TLS, no client-cert requirement --
	// a browser has none, and this listener exists specifically so browser
	// traffic doesn't need one (unlike the mTLS agent listener). Uses an
	// operator-supplied certificate (cfg.DashboardTLSCertPath/KeyPath, from
	// install.sh's pre-existing BAS_TLS/TLS_CERT/TLS_KEY option, previously
	// dormant) when configured, falling back to the deployment CA's own
	// self-signed certificate otherwise -- browsers show a warning for the
	// self-signed fallback, which is expected and documented in
	// docs/guides/upgrade-guide.md, not a bug.
	dashboardTLSCert, err := resolveDashboardTLSCert(cfg, serverTLSCert)
	if err != nil {
		log.Fatalf("[FATAL] load dashboard TLS cert/key (TLS_CERT=%s, TLS_KEY=%s): %v", cfg.DashboardTLSCertPath, cfg.DashboardTLSKeyPath, err)
	}
	dashboardSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.DashboardHTTPPort),
		Handler: router,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{dashboardTLSCert},
			ClientAuth:   tls.NoClientCert,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
```

Add its startup goroutine alongside the other three (after the existing `legacySrv` goroutine, before the `// ── Graceful Shutdown ──` comment):

```go
	go func() {
		log.Printf("[*] BAS Orchestrator dashboard listening on :%d", cfg.DashboardHTTPPort)
		if err := dashboardSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] dashboard listen: %v", err)
		}
	}()
```

Extend graceful shutdown's server list (the existing `for _, s := range []*http.Server{mtlsSrv, enrollSrv, legacySrv} {` line):

```go
	for _, s := range []*http.Server{mtlsSrv, enrollSrv, legacySrv, dashboardSrv} {
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./cmd/server/... -v`
Expected: build succeeds, all tests pass including the two new ones and the existing `TestThreeListeners_*`/`TestRunHealthcheck_*` tests (unmodified, still passing).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/cmd/server/main.go orchestrator/cmd/server/listeners_test.go orchestrator/cmd/server/healthcheck_test.go
git commit -m "feat(server): add dashboard listener on :9543, point healthcheck at :9444"
```

---

### Task 5: uninstall.sh — remove the CA volume alongside Postgres's

**Files:**
- Modify: `packaging/compose/uninstall.sh:49` (the pre-removal warning), `:93-99` (the volume-discovery/removal step), `:150-155` (the post-removal verification step)

**Interfaces:**
- Consumes: `audspect-pki-data` volume name (Task 2).

**Verification approach for this task:** bash script changes have no TDD cycle in the Go sense. Verify via `shellcheck` (if available: `which shellcheck`) for syntax/lint correctness, plus a manual dry-run against a throwaway Docker volume (not the real deployment) to confirm the matching/removal logic actually catches the new volume name, since that's the one behavior change worth exercising concretely rather than just reading the diff.

- [ ] **Step 1: Extend the pre-removal warning**

In `packaging/compose/uninstall.sh`, change (line ~49):

```bash
echo "    • Docker volumes     (ALL database data)"
```

to:

```bash
echo "    • Docker volumes     (ALL database data AND the deployment CA -- every"
echo "                          already-enrolled agent certificate becomes invalid)"
```

- [ ] **Step 2: Extend the volume-discovery pattern**

Change (line ~94):

```bash
mapfile -t vols < <(docker volume ls --format '{{.Name}}' | grep -E 'audspect.*postgres|bas.*postgres' || true)
```

to:

```bash
mapfile -t vols < <(docker volume ls --format '{{.Name}}' | grep -E 'audspect.*postgres|bas.*postgres|audspect.*pki|bas.*pki' || true)
```

- [ ] **Step 3: Extend the post-removal verification's matching pattern**

Find the post-removal check (line ~150-155, `mapfile -t remaining_vols < <(docker volume ls --format '{{.Name}}' \` — read the actual current multi-line grep pattern here first with `sed -n '148,156p' packaging/compose/uninstall.sh`, since the plan text above only shows a fragment) and extend its grep pattern the same way Step 2's was extended, so a leftover `audspect-pki-data` volume is correctly flagged as a verification failure, not silently ignored.

- [ ] **Step 4: Verify**

```bash
which shellcheck && shellcheck packaging/compose/uninstall.sh || echo "shellcheck not available in this environment -- skipping lint, relying on manual read-through + dry-run below"
```

Manual dry-run against throwaway volumes (does not touch any real deployment):

```bash
docker volume create audspect-postgres-data-drytest
docker volume create audspect-pki-data-drytest
docker volume ls --format '{{.Name}}' | grep -E 'audspect.*postgres|bas.*postgres|audspect.*pki|bas.*pki'
```

Expected: both throwaway volume names appear in the output, confirming the extended pattern matches both. Clean up:

```bash
docker volume rm audspect-postgres-data-drytest audspect-pki-data-drytest
```

- [ ] **Step 5: Commit**

```bash
git add packaging/compose/uninstall.sh
git commit -m "fix(uninstall): remove the CA volume alongside Postgres's on full teardown"
```

---

### Task 6: install.sh — new port variables, healthcheck probe, dashboard URLs, upgrade warning

**Files:**
- Modify: `packaging/compose/install.sh:42` (port defaults), `:143-230` (variable declarations + parsing + default-filling), `:1380` (health probe), `:1486` (setup-wizard URL), `:1512-1526` (status/summary output), and the `--upgrade` code path (search for it — not yet read in detail; read the real current upgrade flow before editing, per this task's own verification step)

**Interfaces:**
- Consumes: `HTTP_PORT_ENROLL`/`HTTP_PORT_LEGACY`/`HTTP_PORT_DASHBOARD` (Task 2/3's env var names), `TLS_CERT`/`TLS_KEY` (already-existing install.sh variables, now actually consumed by `config.go`/`main.go` per Task 3/4).

**Verification approach for this task:** same as Task 5 — `shellcheck` if available, plus manual dry-runs of the specific new logic (port-default resolution, URL construction) rather than a full `--install` run against a live host (destructive/stateful, not appropriate to run repeatedly during development).

- [ ] **Step 1: Add the new port variables, following the exact existing `BAS_PORT` pattern**

Near the existing `readonly DEFAULT_PORT="9443"` (line ~42), add:

```bash
readonly DEFAULT_ENROLL_PORT="9444"
readonly DEFAULT_LEGACY_PORT="9000"
readonly DEFAULT_DASHBOARD_PORT="9543"
```

Near the existing `BAS_PORT=""` declaration (line ~143), add:

```bash
BAS_ENROLL_PORT=""
BAS_LEGACY_PORT=""
BAS_DASHBOARD_PORT=""
```

Near the existing `BAS_PORT)             BAS_PORT="$val"             ;;` case-parsing line (line ~193), add:

```bash
      BAS_ENROLL_PORT)      BAS_ENROLL_PORT="$val"      ;;
      BAS_LEGACY_PORT)      BAS_LEGACY_PORT="$val"      ;;
      BAS_DASHBOARD_PORT)   BAS_DASHBOARD_PORT="$val"   ;;
```

Near the existing default-filling line `[[ -z "$BAS_PORT"           ]] && BAS_PORT="$DEFAULT_PORT"` (line ~222), add:

```bash
[[ -z "$BAS_ENROLL_PORT"    ]] && BAS_ENROLL_PORT="$DEFAULT_ENROLL_PORT"
[[ -z "$BAS_LEGACY_PORT"    ]] && BAS_LEGACY_PORT="$DEFAULT_LEGACY_PORT"
[[ -z "$BAS_DASHBOARD_PORT" ]] && BAS_DASHBOARD_PORT="$DEFAULT_DASHBOARD_PORT"
```

- [ ] **Step 2: Write the new port variables into the generated `.env`**

Note on which names go here: `docker-compose.yml`'s `environment:` block (Task 2 Step 3) hardcodes `HTTP_PORT_ENROLL`/`HTTP_PORT_LEGACY`/`HTTP_PORT_DASHBOARD` as fixed literals (`"9444"`/`"9000"`/`"9543"`) — these are the FIXED ports the process binds to *inside* the container, matching how the existing `HTTP_PORT: "9443"` line is already a hardcoded literal today, not a `.env`-supplied value. install.sh's `.env` does NOT write these. What install.sh's `.env` DOES need to supply is the *host-side* port mapping compose's `ports:` block reads via `${BAS_ENROLL_PORT:-9444}:9444` (Task 2 Step 2) — the operator-configurable side of the mapping, exactly mirroring how the existing `BAS_PORT=${BAS_PORT}` line already supplies `${BAS_PORT:-9443}:9443`'s host side today.

Find where the existing `BAS_PORT=${BAS_PORT}` line (line ~1110) writes into the generated `.env` file (read the surrounding ~20 lines with `sed -n '1095,1120p' packaging/compose/install.sh` to see the exact heredoc/append context before editing) and add the three new vars immediately after it, in the same style:

```bash
BAS_ENROLL_PORT=${BAS_ENROLL_PORT}
BAS_LEGACY_PORT=${BAS_LEGACY_PORT}
BAS_DASHBOARD_PORT=${BAS_DASHBOARD_PORT}
```

- [ ] **Step 3: Fix the health probe**

Change (line ~1380):

```bash
if curl -fsSk "https://localhost:${BAS_PORT:-9443}/health" >/dev/null 2>&1 || curl -fs "http://localhost:${BAS_PORT:-9443}/health" >/dev/null 2>&1; then
```

to:

```bash
if curl -fsSk "https://localhost:${BAS_ENROLL_PORT:-9444}/health" >/dev/null 2>&1; then
```

(Drop the plaintext fallback entirely — 9444 is always TLS now, there's no plaintext case to fall back to; `-k` skips verification of the self-signed CA cert, same reasoning as `runHealthcheck()`'s `InsecureSkipVerify`.)

- [ ] **Step 4: Fix the setup-wizard URL and dashboard-access message**

Change (line ~1486):

```bash
  local url="http://localhost:${BAS_PORT}/api/auth/setup"
```

to:

```bash
  local url="https://localhost:${BAS_DASHBOARD_PORT:-9543}/api/auth/setup"
```

and wherever this `$url` is passed to `curl`/`wget` in the same function, add `-k`/`--no-check-certificate` (read the surrounding lines to find the exact call and match its existing flag style).

Change the summary output (line ~1526):

```bash
  echo "  Access dashboard : ${proto}://${host}:${BAS_PORT}"
```

to:

```bash
  echo "  Access dashboard : https://${host}:${BAS_DASHBOARD_PORT:-9543}"
  echo "                     (your browser will show a certificate warning on first"
  echo "                     visit -- the dashboard uses a self-signed certificate by"
  echo "                     default; this is expected. Set TLS_CERT/TLS_KEY in"
  echo "                     setup.conf to use a properly-trusted certificate instead.)"
```

(This also removes the need for the `proto` variable at line ~1522 if it's not used elsewhere in the function — check before removing it outright; leave it in place if other code in the same function still references it.)

- [ ] **Step 5: Add an upgrade-path warning for pre-this-plan installs**

Find the `--upgrade` code path (search: `grep -n '\-\-upgrade' packaging/compose/install.sh`) and read its current flow in full before editing. Add a check, early in the upgrade flow, for whether the *existing* deployment (before this upgrade applies) has `HTTP_PORT_ENROLL`/`HTTP_PORT_LEGACY`/`HTTP_PORT_DASHBOARD` in its current `.env` — their absence means this is an upgrade FROM a pre-this-plan install (today's single-listener code), which is exactly the case `docs/guides/upgrade-guide.md`'s new migration section (Task 8) warns needs the existing-fleet repoint-to-`:9000` step done FIRST. Print a prominent warning (not silent, not merely logged) directing the operator to that guide section before the upgrade proceeds — this pins the Review Focus item about `install.sh --upgrade` not silently stranding the fleet. Use this codebase's existing `warn`/`err` shell functions (already used throughout the script, e.g. `warn "No matching volumes found."` in `uninstall.sh`) rather than a bare `echo`.

- [ ] **Step 6: Verify**

```bash
which shellcheck && shellcheck packaging/compose/install.sh || echo "shellcheck not available -- skipping lint"
```

Manual verification of the port-default logic specifically (extract and test in isolation rather than running the full script):

```bash
bash -c '
readonly DEFAULT_ENROLL_PORT="9444"
BAS_ENROLL_PORT=""
[[ -z "$BAS_ENROLL_PORT" ]] && BAS_ENROLL_PORT="$DEFAULT_ENROLL_PORT"
echo "BAS_ENROLL_PORT resolved to: $BAS_ENROLL_PORT"
[[ "$BAS_ENROLL_PORT" == "9444" ]] && echo "PASS" || echo "FAIL"
'
```

Expected: `PASS`.

- [ ] **Step 7: Commit**

```bash
git add packaging/compose/install.sh
git commit -m "feat(install): publish new listener ports, fix healthcheck/dashboard URLs, warn on legacy-topology upgrades"
```

---

### Task 7: setup.conf.template — document the new ports, update conflict guidance

**Files:**
- Modify: `packaging/compose/setup.conf.template` (the `[network]` section, ~lines 10-24, and the `BAS_PORT=9443` line)

**Interfaces:**
- Consumes: nothing code-level — this is operator-facing documentation embedded in a config template.

**Verification approach:** manual read-through for consistency with Task 6's actual `install.sh` variable names — there's no automated check for a comment/template file's accuracy.

- [ ] **Step 1: Add the new port fields and update the conflict-guidance comment**

Replace the `[network]` section's port documentation:

```
# ── [network] ──────────────────────────────────────────────────────────────────
# BAS_HOST is informational only (used in report URLs and setup summary).
#
# This platform now uses four separate listeners, each serving a different
# kind of traffic -- do not point browsers or agents at the wrong one:
#   BAS_PORT           mTLS agent traffic only (no browser access -- requires
#                       a client certificate). Default: 9443
#   BAS_ENROLL_PORT     New-agent enrollment + healthcheck. Default: 9444
#   BAS_LEGACY_PORT     Temporary, pre-migration agents only. Default: 9000
#   BAS_DASHBOARD_PORT  Browser dashboard access. Default: 9543
#
# Run --check first — it will FAIL if any of these ports are already in use
# on this host.
#
# Known conflicts (change the relevant port above if any of these run on
# this server):
#   8443 / 8444  Trellix/McAfee ePO, Carbon Black, Forcepoint
#   8834         Tenable Nessus
#   9000         SonarQube, PHP-FPM  <- also this platform's own BAS_LEGACY_PORT default
#   9090         Prometheus, Cockpit
#   9200         Elasticsearch REST
#   9443         IBM WebSphere AS default HTTPS  <- common in Indian banking cores
#
# Safe alternatives if a default conflicts: 9543/9643/9743 for BAS_PORT or
# BAS_DASHBOARD_PORT; any unclaimed port in the same 9xxx range otherwise.
#
# BAS_TLS enables a properly-trusted certificate on BAS_DASHBOARD_PORT
# (requires TLS_CERT and TLS_KEY below). Leave false to use the deployment
# CA's own self-signed certificate -- browsers will show a one-time warning
# on first visit, which is expected.

BAS_HOST=                         # ← REQUIRED  e.g. bas.corp.internal
BAS_PORT=9443                     # Default: 9443 (mTLS agent traffic)
BAS_ENROLL_PORT=9444              # Default: 9444 (agent enrollment)
BAS_LEGACY_PORT=9000              # Default: 9000 (temporary, pre-migration agents)
BAS_DASHBOARD_PORT=9543           # Default: 9543 (browser dashboard)
BAS_TLS=false                     # true | false
```

- [ ] **Step 2: Verify**

Read the edited file back and confirm the variable names (`BAS_PORT`/`BAS_ENROLL_PORT`/`BAS_LEGACY_PORT`/`BAS_DASHBOARD_PORT`) match EXACTLY what Task 6 actually implemented in `install.sh`'s parsing/defaulting code — a mismatch here would silently produce a template that doesn't do what it claims. This is a manual cross-check, not an automated test.

- [ ] **Step 3: Commit**

```bash
git add packaging/compose/setup.conf.template
git commit -m "docs(setup): document the four-listener port layout and updated conflict guidance"
```

---

### Task 8: `docs/guides/upgrade-guide.md` — port references, working BAS_TLS, migration runbook

**Files:**
- Modify: `docs/guides/upgrade-guide.md` (Step 4's health-check command, the `setup.conf Reference` table, and a new section for this specific upgrade)

**Interfaces:**
- Consumes: the final port numbers and variable names from Tasks 2/3/6/7.

**Verification approach:** manual read-through for accuracy against what was actually implemented — this is a documentation-only task.

- [ ] **Step 1: Fix Step 4's health-check command**

Change:

```bash
curl -sf http://localhost:9443/health
```

to:

```bash
curl -sfk https://localhost:9444/health
```

with a short note that 9443 now requires a client certificate and is no longer the right port for a manual health check.

- [ ] **Step 2: Update the `setup.conf Reference` table**

Update the `BAS_PORT` row's description from "Dashboard/API listening port" to "mTLS agent traffic port (no browser access)", and add three new rows matching Task 7's template:

| Key | Required | Default | Description |
|---|---|---|---|
| `BAS_ENROLL_PORT` | | `9444` | New-agent enrollment + healthcheck port |
| `BAS_LEGACY_PORT` | | `9000` | Temporary, pre-migration agent traffic |
| `BAS_DASHBOARD_PORT` | | `9543` | Browser dashboard access port |

- [ ] **Step 3: Add the migration-runbook section**

Add a new section, positioned prominently (right after "## Before You Upgrade", before "## Step 1"), titled to stand out from routine upgrades:

```markdown
## ⚠ Upgrading From a Pre-mTLS Install (v1.7.5 and earlier's single-listener topology)

If your current deployment predates this platform's per-agent mTLS trust
model, every enrolled agent is configured to talk to `http://<host>:9443`
in plaintext. After this upgrade, port 9443 requires a client certificate
-- a plaintext request to it fails outright, and existing agent binaries
have no built-in awareness of the new port layout to fall back to
automatically. Skipping the steps below will disconnect your entire fleet
until each agent is manually repointed.

**Do this BEFORE running `install.sh --upgrade`:**

1. Repoint every existing agent's configured server URL from
   `http://<host>:9443` to `http://<host>:9000` (the new temporary legacy
   listener this upgrade publishes) -- this works against your CURRENT,
   not-yet-upgraded orchestrator, since it doesn't care what port number
   the agent uses as long as it's reachable. Per-platform:
   ```bash
   # Re-run the agent installer with the new URL (Linux/macOS)
   sudo ./bas-agent --install --server http://<host>:9000
   ```
   ```powershell
   # Windows: re-run the installer with the new URL, or edit the service
   # config directly and restart the BAS Agent service
   ```
2. Confirm agents are checking in against the *current* orchestrator on
   `:9000` before proceeding (Agents page in the dashboard, or
   `docker logs audspect-orchestrator | grep enroll`).
3. **Now** run `install.sh --upgrade --config setup.conf` as normal (Step 3
   below). All four listeners come up; your already-repointed agents keep
   working unaffected on `:9000`.
4. New agent installs, from this point on, enroll via the new mTLS flow
   automatically (`--ca-root` flag, bundled CA root + bootstrap secret) --
   no `:9000` involvement.
5. Existing agents migrate off `:9000` automatically on their *next binary
   upgrade* (agents already re-enroll on every upgrade) -- no further
   manual action needed per-agent.
6. `:9000` traffic is logged distinctly in the orchestrator's logs
   (`legacy_listener_requests_total` metric / `"legacy listener request"`
   log lines) -- use this to confirm when migration is complete (zero
   remaining `:9000` traffic) before a future release retires it entirely.

**If you're already running a version with the four-listener topology**
(i.e. this isn't your first upgrade since mTLS was introduced), skip this
section -- your agents are already using the new topology and this
upgrade is routine.
```

- [ ] **Step 4: Verify**

Read the full edited file back and confirm the port numbers/variable names throughout match Tasks 2/3/6/7 exactly, and that the new section's positioning (right after "Before You Upgrade", before "Step 1") reads naturally in context.

- [ ] **Step 5: Commit**

```bash
git add docs/guides/upgrade-guide.md
git commit -m "docs(upgrade): fix port references, document the mTLS migration path"
```

---

## Final Verification

After all 8 tasks:

```bash
cd orchestrator && go build ./... && go test ./config/... ./cmd/server/... -v
```

Expected: build succeeds, all tests pass (existing tests from the prior B1/B3 plan plus this plan's new ones).

```bash
which shellcheck && shellcheck packaging/compose/install.sh packaging/compose/uninstall.sh
```

Expected: no new lint errors introduced by this plan's changes (pre-existing warnings in untouched parts of these large scripts are not this plan's concern).

```bash
cd packaging/compose && docker compose config >/dev/null && echo "compose valid"
```

Expected: no errors.

Manual, end-to-end (documented as a follow-up if genuinely impractical in this dev environment, not silently skipped): a real `docker build` of the full image, a real `install.sh --install --config setup.conf` against a clean host with a valid license file, confirming the dashboard is reachable at `https://<host>:9543`, the healthcheck reports healthy, and a fresh agent successfully bootstraps via `--ca-root` against the new topology end-to-end.
