# Audspect BAS — Developer Guide

**Classification:** Internal — Audspect Engineering / Confidential  
**Platform Version:** v1.7.3

---

## Repository Layout

```
Audspect_Cloud/
├── orchestrator/               # Go orchestrator (primary service)
│   ├── cmd/server/             # Main entrypoint + wwwroot (static files)
│   │   └── wwwroot/            # Windows Junction → orchestrator/wwwroot
│   ├── wwwroot/                # Actual static files: index.html, og/index.html
│   ├── internal/
│   │   ├── api/                # HTTP handler functions
│   │   ├── auth/               # Password hashing, JWT, RBAC
│   │   ├── integrity/          # Scenario signing, binary trust, tamper watch
│   │   ├── models/             # Database schema, WS message types
│   │   ├── scoring/            # Score calculation engine
│   │   └── reporting/          # HTML/PDF/CSV/JSON report generation
│   └── config/                 # Config loading (env vars override JSON)
├── agent/                      # Go agent binary
├── scenarios/                  # Signed scenario YAML files
├── docs/                       # Documentation
│   ├── guides/                 # Customer sub-guides
│   └── internal/               # This set of internal docs
└── windows-build.ps1           # Build pipeline (Windows)
```

**Important:** `orchestrator/cmd/server/wwwroot` is a Windows Junction pointing to `orchestrator/wwwroot`. Only edit files in `orchestrator/wwwroot/`. The two source files are:
- `orchestrator/wwwroot/index.html` — primary dashboard
- `orchestrator/wwwroot/og/index.html` — legacy dashboard (kept for backward compat)

---

## Development Environment

### Prerequisites

- Go 1.22+
- PostgreSQL 16 (via Docker or local install)
- Docker (for running dependencies)
- `garble` (for production builds only; dev builds use `go build`)

### Start development database

```bash
docker run -d \
  --name bas-postgres-dev \
  -e POSTGRES_USER=bas \
  -e POSTGRES_PASSWORD=basdev \
  -e POSTGRES_DB=bas \
  -p 5432:5432 \
  postgres:16
```

### Configure environment

```bash
export DATABASE_URL="postgres://bas:basdev@localhost:5432/bas?sslmode=disable"
export JWT_SECRET="dev-jwt-secret-minimum-32-characters"
export AGENT_SECRET="dev-agent-secret"
export HTTP_PORT=9000
export BAS_ADMIN_EMAIL="admin@dev.local"
export BAS_ADMIN_PASSWORD="DevPassword1!"
export SCENARIOS_DIR="scenarios"
```

### Run the orchestrator (dev mode, no garble)

```bash
cd orchestrator
go run ./cmd/server/...
```

Dashboard available at `http://localhost:9000`.

---

## Key Architectural Decisions

### Agent is a dumb executor

The agent receives fully-formed commands (ready to execute in PowerShell/Bash). All intelligence — ART YAML parsing, technique resolution, Caldera ability fetching, output interpretation — happens server-side. The agent has zero knowledge of ART, Caldera, or the ATT&CK framework.

**Why:** Simplifies agent updates (logic stays on server), reduces agent binary complexity, makes the agent harder to reverse-engineer for adversaries inspecting it on endpoints.

### Garble breaks reflection — use JSON-tag maps

The orchestrator binary is built with `garble -literals -tiny`. Garble obfuscates struct field names, breaking Go's `html/template` when templates reference struct fields by name (e.g., `{{.FieldName}}`).

**Pattern to follow:** Never pass structs to `html/template.Execute()`. Always convert to `map[string]interface{}` using JSON marshaling and the JSON tag names:

```go
// Wrong — field names obfuscated by garble at runtime
tmpl.Execute(w, reportData)

// Correct — JSON tags are strings (not symbol names), survive obfuscation
jsonBytes, _ := json.Marshal(reportData)
var m map[string]interface{}
json.Unmarshal(jsonBytes, &m)
tmpl.Execute(w, m)
```

### Result delivery is at-least-once + idempotent

Agents retry result submission on failure. The server REPLACES results for a run step (never appends). No status guard prevents late submission from healing a Partial run to Completed. This means:
- Duplicate submissions are safe
- Late submissions (after an agent reconnects) heal partial runs
- The orchestrator never says "you're too late to submit this result"

### Config: env vars override JSON

Config is loaded from `/etc/bas/config.json` first, then env vars override individual fields. The `config.Load()` function applies overrides in order. In Docker Compose deployments, all config comes from env vars (no JSON file needed).

---

## Adding a New API Endpoint

1. **Define handler** in the appropriate `internal/api/` file (or create a new file for a new resource)

2. **Register route** in `orchestrator/cmd/server/main.go` (or wherever routes are registered)

3. **Auth check:** Use the `requireAuth(role)` middleware for role-gating

4. **Input validation:** Validate IDs with regex; validate JSON with `json.Decoder`. Return `400` with `{"error": "..."}` on invalid input

5. **Response format:** Always return `application/json`. Use `httpError(w, code, message)` for error responses

6. **Document** in `docs/guides/api-reference.md`

---

## Adding a New WebSocket Message Type

1. Define the message type constant in `orchestrator/internal/models/schema.go`:
   ```go
   const MsgMyNewEvent = "my_new_event"
   ```

2. Define the payload struct (if needed):
   ```go
   type MsgMyNewEventPayload struct {
       ResourceID string `json:"resourceId"`
       // ...
   }
   ```

3. Broadcast via the hub:
   ```go
   hub.BroadcastJSON(models.WSMessage{
       Type: models.MsgMyNewEvent,
       Data: MsgMyNewEventPayload{...},
   })
   ```

4. Handle in the dashboard JS (`orchestrator/wwwroot/index.html`):
   ```javascript
   case 'my_new_event':
     handleMyNewEvent(msg.data);
     break;
   ```

5. **Keep JS string literals in sync with Go constants.** There is no code-gen between Go and JS — they are coupled by convention.

---

## Database Schema Migrations

Migrations are plain SQL files in `orchestrator/internal/models/migrations/`:

```
001_initial.sql
002_add_findings.sql
...
042_add_ap_jobs.sql
```

Migrations run in order on orchestrator startup. The `schema_migrations` table tracks which have been applied.

**Writing a migration:**
- One migration = one `.sql` file
- Number sequentially
- Migrations must be idempotent (`CREATE TABLE IF NOT EXISTS`, etc.)
- Never modify a previously-released migration — always add a new one
- Test on a fresh database before release

---

## Testing

```bash
cd orchestrator
go test ./...
go test ./... -race           # Race detector
go test -cover ./...          # Coverage
```

Handler tests use `httptest.NewRecorder()` and `httptest.NewRequest()`. Database-dependent tests require a real PostgreSQL instance (set `DATABASE_URL` env var). No mock database — see `feedback_agent_architecture` memory.

---

## Common Development Pitfalls

| Pitfall | Description | Solution |
|---|---|---|
| Template field not found at runtime | Struct field obfuscated by garble | Use JSON-tag map pattern (see above) |
| WebSocket message not received in browser | JS string literal doesn't match Go constant | Verify both sides use the same string |
| Score returns 0 | All steps ERROR or SKIPPED; denominator is 0 | Division-by-zero guard in scoring engine returns 0 |
| Agent binary trust all yellow | BINARIES.sha256 not updated after agent binary change | Re-run Step 0b / Step 5 of windows-build.ps1 |
| `jwt_secret required` on startup | `.env` file not loaded by Docker Compose | Verify `.env` path and `env_file:` in compose |
| Config file secrets in logs | `jwt_secret`/`agent_secret` loaded from JSON file | Move to env vars; remove from config.json |

---

## Release Checklist

- [ ] Update version string in `orchestrator/cmd/server/version.go`, `docker-compose.yml`, `windows-build.ps1`
- [ ] Run `go mod tidy`
- [ ] Run `go test ./...` — all green
- [ ] Run `windows-build.ps1` — full pipeline
- [ ] Verify scenario signatures: `gpg --verify scenarios/*.yaml.sig`
- [ ] Verify `BINARIES.sha256.sig`: `gpg --verify BINARIES.sha256.sig BINARIES.sha256`
- [ ] Smoke-test the delivery ZIP on a clean Ubuntu VM
- [ ] Update `docs/guides/release-notes.md`
- [ ] Git tag: `git tag v1.7.3 && git push --tags`

---

*© Audspect Engineering — Internal / Confidential*
