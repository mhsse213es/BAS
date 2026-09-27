# Agent Trust Model — Deployment Topology Fix

**Date:** 2026-09-27
**Status:** Approved for planning

## Context

The B1/B3 agent-trust-model foundation (deployment CA, per-agent mTLS, three-listener topology: 9443 mTLS / 9444 enrollment / 9000 legacy) is fully implemented, reviewed, and merged to `main` — see `docs/superpowers/specs/2026-09-27-agent-trust-model-b1-b3-b4-design.md` and `docs/superpowers/plans/2026-09-27-agent-trust-model-foundation-b1-b3.md`. That work's final whole-branch review found the Go code correct but identified four real, independently-confirmed deployment/infrastructure problems deliberately left out of that plan's scope (it covered Go code only). This spec covers those four problems as their own piece of work.

**The four problems, as found and confirmed:**

1. **Container won't start.** `orchestrator/Dockerfile`'s final stage is `gcr.io/distroless/static-debian12` running as `USER nonroot`. Nothing creates `/etc/audspect/pki` (the CA's default storage directory, `orchestrator/config/config.go`'s `PKIDir` default) or grants `nonroot` write access to it. `pki.LoadOrGenerateCA(cfg.PKIDir)` (called at startup in `orchestrator/cmd/server/main.go`) fails with a permission error, and the process `log.Fatalf`s — a crash loop on every fresh deploy of this code.
2. **CA has no persistence.** `packaging/compose/docker-compose.yml` has no volume for `PKIDir`. Every `docker compose up` that recreates the orchestrator container generates a brand-new CA, invalidating every already-issued agent certificate and every agent's locally-cached CA root — a fleet-wide lockout on every routine container recreate, recoverable today only via manual SQL against `agent_certificates`.
3. **Port topology breaks the dashboard, the existing fleet, and the healthcheck simultaneously.** `docker-compose.yml` publishes only `${BAS_PORT:-9443}:9443` and sets `HTTP_PORT=9443` — and per the B1/B3 work, 9443 is now the mandatory-mTLS listener (`tls.RequireAndVerifyClientCert`). Confirmed via `packaging/compose/install.sh` that port 9443 is *also* today's browser-dashboard port: the first-run setup wizard calls `http://localhost:${BAS_PORT}/api/auth/setup` (line ~1486) and the install summary prints `Access dashboard : ${proto}://${host}:${BAS_PORT}` (line ~1526). So today's single port number is overloaded three ways that the B1/B3 code split apart: browsers, legacy plaintext agents, and (new) mTLS agents. Ports 9444 and 9000 aren't published in compose at all.
4. **No validation that listener ports are distinct.** `config.go`'s `Load()` defaults both `HTTPPort` and `LegacyHTTPPort` to 9000 for any install that doesn't go through `docker-compose.yml`'s explicit overrides — the mTLS and legacy servers then both try to bind `:9000`, and one `log.Fatalf`s. Nothing catches this before startup.

## Goals

1. Make the shipped container start and stay healthy under the real B1/B3 code.
2. Give the CA durable, correctly-owned storage that survives routine container recreation.
3. Give the browser dashboard, agent mTLS traffic, agent enrollment, and legacy agent traffic each their own reachable listener, correctly published.
4. Fix both healthchecks (Docker's own, and `install.sh`'s) to probe something that doesn't require a client certificate.
5. Document a safe migration sequence for the existing fleet (e.g. staging, referenced in project memory as `zain@audspecterver 192.168.10.78:9443`), which is running today's single-listener plaintext code and would otherwise go dark the moment this image is deployed.

## Non-goals

- B2 (retiring the legacy `:9000` listener) — still a separate, later piece of work; this spec makes `:9000` correctly reachable during migration, not removes it.
- An admin UI for CA/certificate recovery (final review's Important #8) — separate follow-up.
- Extending mTLS-derived identity to every HTTP handler beyond `/ws/agent` and `/api/agents/enroll-csr` (final review's Important #6) — separate follow-up.
- Actually executing the staging migration — this spec produces the runbook; running it is a later, live-ops action.

## Section 1 — Listener/port layout

Four listeners, not three:

| Port | TLS mode | Serves | Status |
|---|---|---|---|
| 9443 | `RequireAndVerifyClientCert` | Agent mTLS operation + renewal (unchanged from B1/B3) | Existing |
| 9444 | `NoClientCert` | Agent enrollment (`POST /api/agents/enroll-csr`) + unauthenticated `GET /health` (unchanged — already scoped this way by the B1/B3 final-review fix wave's `MountEnrollment`) | Existing |
| 9000 | none (plaintext) | Legacy pre-migration agents (unchanged) | Existing, temporary |
| **8443 (new)** | server-cert-only HTTPS, `NoClientCert` | **Browser dashboard**: `api.Mount(...)`'s static SPA handler, JWT-authenticated API, `/ws/browser` | **New** |

`dashboardSrv` is a 4th `*http.Server` in `orchestrator/cmd/server/main.go`, added alongside the existing three, using the same server TLS identity (the CA's own certificate, per B1/B3's existing `ca.TLSCertificate()`) with `ClientAuth: tls.NoClientCert` — structurally identical to how `enrollSrv` is already built, just serving the full `router` (unrestricted, like the legacy listener) instead of `MountEnrollment`'s narrow subset. Graceful shutdown extends to cover this 4th server alongside the existing three.

Port 8443 is a placeholder; the implementation plan should confirm it doesn't collide with anything else this product exposes (checked so far: 9000/9443/9444 agent listeners, 5432 internal-only Postgres, 8888 internal-only Caldera, 9222 internal-only Chrome CDP, 22→2222 SFTP sink, 53 DNS sink, 587 SMTP sink — 8443 is clear of all of these).

## Section 2 — Dockerfile: writable, persistent CA directory under `nonroot`

Distroless's final stage (`gcr.io/distroless/static-debian12`) has no shell — a `RUN mkdir`/`RUN chown` in that stage is impossible, since there's no `/bin/sh` to execute it. The fix follows the standard distroless pattern already used elsewhere in this exact file for getting build-stage output into the shell-less final stage (`COPY --from=<stage> ...`):

1. In an existing shell-capable stage (e.g. reuse the `builder` stage, which already has Alpine's shell available before its own `FROM gcr.io/distroless/...` final stage begins), add: `RUN mkdir -p /pki-seed && chown 65532:65532 /pki-seed` (`65532` is distroless's `nonroot` UID/GID — confirm the exact value via `docker run --rm gcr.io/distroless/static-debian12 id` or the image's published docs rather than assuming; the implementation plan should verify this exactly).
2. In the final stage, add `COPY --from=builder --chown=nonroot:nonroot /pki-seed /etc/audspect/pki` (or equivalent), placed before `USER nonroot`.
3. This directory becomes the mount point for the new named volume (Section 3). Docker initializes a fresh named volume by copying the image's existing directory content and ownership at that path on first container start, so the volume mount and the ownership fix compose correctly — this is standard Docker volume-initialization behavior, not something this Dockerfile needs to handle specially.

## Section 3 — CA persistence: named Docker volume

Add to `packaging/compose/docker-compose.yml`, matching the existing `audspect-postgres-data` pattern exactly (`docker-compose.yml:16-17,256-257`):

```yaml
  orchestrator:
    volumes:
      # ...existing volumes...
      - audspect-pki-data:/etc/audspect/pki

volumes:
  audspect-postgres-data:
    driver: local
  audspect-pki-data:
    driver: local
```

`PKI_DIR` env var (already supported by `config.go`, from the B1/B3 work) is left at its default (`/etc/audspect/pki`) rather than overridden in compose — the volume mount targets that same default path, so no new env var is needed.

## Section 4 — `uninstall.sh`: CA volume removed by default, same as Postgres

Extend the existing volume-discovery regex in `packaging/compose/uninstall.sh` (currently `docker volume ls --format '{{.Name}}' | grep -E 'audspect.*postgres|bas.*postgres'`, line ~94) to also match the new PKI volume — either broaden the pattern (e.g. `audspect.*(postgres|pki)`) or add a second explicit match. Extend the pre-removal warning (currently "Docker volumes (ALL database data)", line ~49) to also mention the CA/PKI data, so an operator running `--uninstall` sees the full scope of what's being destroyed before confirming — matching the existing warn-then-confirm flow, not a new confirmation gate.

## Section 5 — Healthcheck: probe 9444, not 9443

**Docker's own `HEALTHCHECK`** (`docker-compose.yml`'s `healthcheck:` block, currently `test: ["CMD", "/orchestrator", "--healthcheck"]`) doesn't need to change — it already delegates to the binary's own `--healthcheck` flag. The fix is inside `runHealthcheck()` in `orchestrator/cmd/server/main.go`:

```go
func runHealthcheck() int {
	port := 9444 // enrollment listener -- unauthenticated /health, unlike 9443's mTLS requirement
	if v := os.Getenv("HTTP_PORT_ENROLL"); v != "" {
		fmt.Sscanf(v, "%d", &port)
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // self-signed against the deployment CA; this is a loopback liveness probe, not a security boundary
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/health", port))
	// ...unchanged from here
}
```

Note the scheme changes from `http://` to `https://` (9444 is TLS, just without a client-cert requirement) and the default port changes from 9000 to 9444, reading `HTTP_PORT_ENROLL` (the existing B1/B3 env var, `config.go`) instead of `HTTP_PORT`.

**`install.sh`'s own probe** (currently `curl -fsSk "https://localhost:${BAS_PORT:-9443}/health" ... || curl -fs "http://localhost:${BAS_PORT:-9443}/health"`, line ~1380) changes to target the enrollment port instead — introduce a new `BAS_ENROLL_PORT` variable (default 9444, following the exact pattern `BAS_PORT`/`DEFAULT_PORT` already use at the top of the script) and probe `https://localhost:${BAS_ENROLL_PORT:-9444}/health` with `-k` (self-signed cert, matching the existing `-k` usage already present). Drop the plaintext-fallback `curl` call — 9444 is always TLS now, there's no plaintext case to fall back to.

## Section 6 — `install.sh`: dashboard URL moves to the new port

- First-run setup wizard call (line ~1486, `local url="http://localhost:${BAS_PORT}/api/auth/setup"`) moves to the new dashboard port and scheme: `https://localhost:${BAS_DASHBOARD_PORT:-8443}/api/auth/setup`, with `-k` (self-signed cert) added to whatever `curl`/`wget` call uses this URL.
- Install summary (line ~1526, `echo "  Access dashboard : ${proto}://${host}:${BAS_PORT}"`) moves to `https://${host}:${BAS_DASHBOARD_PORT:-8443}`, and the summary should add a one-line note that the browser will show a certificate warning on first visit (self-signed against the deployment CA, not a publicly-trusted CA) and that this is expected — an operator seeing an unexplained cert warning on a security product's own dashboard is a bad first impression worth heading off explicitly.
- New `BAS_DASHBOARD_PORT` variable, default 8443, following the exact `BAS_PORT`/`DEFAULT_PORT` pattern already established at the top of the script (`readonly DEFAULT_PORT="9443"`, `BAS_PORT=""`, parsed from `--config`/flags, defaulted if unset).
- `docker-compose.yml`'s `ports:` section gains `"${BAS_DASHBOARD_PORT:-8443}:8443"` and `"${BAS_ENROLL_PORT:-9444}:9444"` and `"${BAS_LEGACY_PORT:-9000}:9000"` alongside the existing `"${BAS_PORT:-9443}:9443"` — all four listeners published, matching `config.go`'s existing env vars (`HTTP_PORT_ENROLL`, `HTTP_PORT_LEGACY`) plus the new dashboard port.

## Section 7 — Config validation: reject equal listener ports at startup

In `orchestrator/config/config.go`'s `Load()`, after all env-var overrides are applied and before returning, add a check that `HTTPPort`, `EnrollHTTPPort`, `LegacyHTTPPort`, and the new dashboard port are all pairwise distinct — return a clear error (`fmt.Errorf("HTTP_PORT and HTTP_PORT_LEGACY must be different (both resolved to %d)", ...)` or similar per pair) rather than letting two servers silently race to bind the same port and one `log.Fatalf` with a less diagnosable error later in `main.go`.

## Section 8 — Migration runbook (existing fleet, e.g. staging)

Staging (`zain@audspecterver`, `192.168.10.78:9443` per project memory) is running today's single-listener plaintext code, with every enrolled agent configured for `http://<host>:9443`. Once this deployment fix ships and the orchestrator image is upgraded, port 9443 becomes real mTLS — a plaintext HTTP request to it fails outright (TLS handshake garbage), and old agent binaries have no built-in awareness of port 9000 or the new topology to fall back to. The sequence must be:

1. **Before upgrading the orchestrator image**, repoint every existing agent's configured server URL from `http://<host>:9443` to `http://<host>:9000` (the legacy plaintext listener this deployment fix newly publishes). This is a per-agent config/service change on the *existing* orchestrator (today's single-listener code doesn't care what port number is in the agent's config as long as it's reachable) — concretely, re-run the agent installer with `--server http://<host>:9000` (agent's existing `--install` flag, unchanged) or edit the stored service config directly, per-platform, and restart the agent service. This step has no orchestrator-side dependency and can happen at any time before the upgrade.
2. **Upgrade the orchestrator** to the new image (this deployment fix + the B1/B3 code). All four listeners come up; existing agents (now pointed at `:9000`) continue working exactly as before, unaffected by the new mTLS/enrollment listeners.
3. **New agent installs**, from this point on, use the installer's bundled CA root + bootstrap secret (per B1/B3's `--ca-root` flag) and enroll via `:9444`/`:9443` from day one — no `:9000` involvement.
4. **Existing agents migrate off `:9000` naturally** on their next binary upgrade, via the already-established re-enroll-on-upgrade mechanism (project memory: agents already re-enroll after every binary upgrade) — the upgraded agent binary performs the CSR bootstrap against `:9444` and switches to `:9443` for all subsequent operation, per B1/B3's `ensureCertificate`/`bootstrap.go`.
5. `:9000` traffic is already logged distinctly (B1/B3 final-review fix wave, `WithLegacyListenerTag`) — use that logging to confirm when migration is actually complete (zero remaining `:9000` traffic) before considering B2 (removing `:9000` entirely).

This runbook should be written to `packaging/compose/MIGRATION.md` (or appended to an existing relevant doc if one already covers upgrade procedures — check `packaging/compose/` and `docs/` for one before creating a new file) as part of this work's implementation, not just left in this spec.

## Testing / verification approach

- A real `docker build` of the fixed `Dockerfile`, followed by `docker run` as `nonroot`, confirming the orchestrator starts (no crash-loop) and successfully creates/loads the CA at `/etc/audspect/pki` without a permission error.
- A `docker compose up` cycle (start, stop, recreate) confirming the CA's public key / fingerprint is identical before and after recreation (proving the named volume persists it).
- `curl -k https://localhost:9444/health` succeeds with no client certificate; `curl -k https://localhost:9443/health` (or any 9443 request) fails at the TLS layer without one — confirms the healthcheck fix targets the right listener.
- `curl -k https://localhost:8443/` reaches the dashboard SPA; the same request against 9443 fails.
- A `config.Load()` unit test asserting the new distinct-ports validation actually rejects a configuration where two of the four ports collide.
- Manual: run `install.sh --install` end to end against a clean host and confirm the printed dashboard URL and setup-wizard flow both work against the new port/scheme.

## Open implementation-level details (for the plan to resolve)

- Exact distroless `nonroot` UID/GID to use in the Dockerfile's `chown` (verify against the actual base image rather than assuming `65532`).
- Exact final filename/location for the migration runbook (check for an existing upgrade-procedures doc first).
- Whether `BAS_DASHBOARD_PORT`/`BAS_ENROLL_PORT`/`BAS_LEGACY_PORT` need entries in `packaging/compose/setup.conf.template` (the file `install.sh --install --config setup.conf` reads) alongside their env-var wiring — check that file's current structure before assuming.
