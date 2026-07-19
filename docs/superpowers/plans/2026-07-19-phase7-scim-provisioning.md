# Phase 7, Sub-project 2 (Identity & Access) — Part 3: SCIM Provisioning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a tenant's IdP (Okta, Azure AD, OneLogin) push user lifecycle events to Audspect via SCIM 2.0 — proactive create/deactivate, complementing SSO's reactive JIT provisioning.

**Architecture:** A new `internal/scim` package implements RFC 7644's wire schema (types, SCIM↔Audspect-user translation, the one supported filter shape). A new per-tenant `scim_configs` table (hashed bearer token, `UNIQUE(tenant_id)`) backs a JWT-authenticated admin CRUD API and a separate `scimAuth` bearer-token middleware that resolves a tenant entirely outside the JWT/RBAC system — mirroring how agent-facing endpoints already sit outside it. `/scim/v2/*` endpoints (discovery + User CRUD) run under that middleware; the admin config endpoints run under the normal JWT+permission chain.

**Tech Stack:** Go, `crypto/rand`/`crypto/sha256` (stdlib — no new external dependency), chi router, PostgreSQL/pgx.

## Global Constraints

- **Users only, no Groups** — no SCIM Group resource, no group-to-role mapping.
- **Per-tenant static bearer token**, stored **hashed (SHA-256)**, shown in cleartext exactly once (creation/rotation response).
- **Token-only tenant resolution, flat URL** (`/scim/v2/Users`, no tenant slug in the path).
- **Soft-deactivate only, never hard-delete** — `DELETE` and `PATCH{active:false}` both set `users.is_active = false`.
- **Role source: tenant-wide `scim_configs.default_role`** — no per-user role via SCIM attributes/extensions.
- **Separate `scim_configs` table**, not folded into `sso_configs`.
- **Practical RFC 7644 compliance**: discovery endpoints (`ServiceProviderConfig`/`ResourceTypes`/`Schemas`) + full User CRUD + the one filter shape (`userName eq "value"`) + `startIndex`/`count` pagination. No fuller filter grammar, no OAuth-based SCIM auth, no session/JWT revocation on deactivation.

---

### Task 1: Database schema — `scim_configs`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (append to the `stmts` slice, before its closing `}`)

**Interfaces:**
- Produces: `scim_configs` table (`id, tenant_id, token_hash, default_role, enabled, created_at, updated_at`, `UNIQUE(tenant_id)`, `tenant_id REFERENCES tenants(id)`).

- [ ] **Step 1: Ground the current end of the migration slice**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n "auth_source text NOT NULL DEFAULT 'local'" internal/db/postgres.go`
Expected: one match — this is the last line of the existing `stmts` slice (the end of the SSO migration block, itself the end of Multi-Tenancy's). Confirm the line immediately after it is `}` closing the slice.

- [ ] **Step 2: Add `scim_configs`**

Using Edit, replace:

```go
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local'`,
	}
```

with:

```go
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local'`,

		// SCIM provisioning — Phase 7 Identity & Access, Part 3. One SCIM
		// config per tenant; token_hash is a SHA-256 hash, the cleartext
		// token is never stored and is shown to the admin exactly once
		// (creation/rotation response). UNIQUE(tenant_id) — exactly one
		// SCIM app per tenant for this slice. See
		// docs/superpowers/specs/2026-07-19-phase7-scim-provisioning-design.md.
		`CREATE TABLE IF NOT EXISTS scim_configs (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			tenant_id     text        NOT NULL REFERENCES tenants(id),
			token_hash    text        NOT NULL,
			default_role  text        NOT NULL DEFAULT 'viewer',
			enabled       boolean     NOT NULL DEFAULT true,
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			updated_at    timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (tenant_id)
		)`,
	}
```

- [ ] **Step 3: Build and run the DB regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/db/... -v`
Expected: all PASS — proves the new `CREATE TABLE` statement is valid and idempotent alongside every prior migration statement.

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/db/postgres.go
git commit -m "feat(scim): add scim_configs table

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: `internal/auth` — 2 new SCIM permissions

**Files:**
- Modify: `orchestrator/internal/auth/permissions.go`
- Modify: `orchestrator/internal/auth/permissions_test.go`

**Interfaces:**
- Produces: `auth.CanViewSCIMConfig` (`"scim:config:view"`), `auth.CanManageSCIMConfig` (`"scim:config:manage"`), granted to `RoleAdmin` only. Consumed by Task 4 (admin config handlers).

- [ ] **Step 1: Ground the current end of the permission list**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n "CanManageSSOConfig" internal/auth/permissions.go`
Expected: 3 matches — the `const` declaration, the `rolePermissions[RoleAdmin]` grant, and the `Permissions()` ordered slice entry.

- [ ] **Step 2: Add the 2 new permissions**

In `orchestrator/internal/auth/permissions.go`, inside the `const ( ... )` block, immediately after the SSO permissions, add:

```go
	CanViewSSOConfig   Permission = "sso:config:view"
	CanManageSSOConfig Permission = "sso:config:manage"

	// SCIM provisioning — Admin only. Separate from SSO's permissions:
	// different protocol, different admin action (rotate a token vs.
	// configure an IdP issuer).
	CanViewSCIMConfig   Permission = "scim:config:view"
	CanManageSCIMConfig Permission = "scim:config:manage"
)
```

In `rolePermissions[RoleAdmin]`, immediately after `CanViewSSOConfig: true, CanManageSSOConfig: true,`, add:

```go
		CanViewSCIMConfig: true, CanManageSCIMConfig: true,
```

In `Permissions()`'s ordered slice, immediately after `CanViewSSOConfig, CanManageSSOConfig,`, add:

```go

		CanViewSCIMConfig, CanManageSCIMConfig,
```

- [ ] **Step 3: Update the 2 pre-existing tests that hard-code the permission count**

In `orchestrator/internal/auth/permissions_test.go`, `TestHasPermission_MatrixIsComplete`'s `tested` map gains, immediately after `CanViewSSOConfig: true, CanManageSSOConfig: true,`:

```go
		CanViewSCIMConfig: true, CanManageSCIMConfig: true,
```

`TestPermissions_Ordering`'s `want` slice gains, immediately after `CanViewSSOConfig, CanManageSSOConfig,`:

```go

		CanViewSCIMConfig, CanManageSCIMConfig,
```

- [ ] **Step 4: Build and test**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/auth/... -v`
Expected: clean build; all tests pass, including `TestHasPermission_MatrixIsComplete` and `TestPermissions_Ordering` now covering 96 permissions (94 + 2).

- [ ] **Step 5: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/auth/permissions.go internal/auth/permissions_test.go
git commit -m "feat(scim): add 2 new SCIM config permissions

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: `internal/scim` — RFC 7644 types, translation, filter parsing

**Files:**
- Create: `orchestrator/internal/scim/types.go`
- Create: `orchestrator/internal/scim/translate.go`
- Create: `orchestrator/internal/scim/filter.go`
- Create: `orchestrator/internal/scim/scim_test.go`

**Interfaces:**
- Produces: `scim.User`, `scim.IncomingUser`, `scim.UserRow`, `scim.ListResponse`, `scim.Error`, `scim.PatchOp`, `scim.ServiceProviderConfig`, `scim.ResourceType`, `scim.Schema` (+ nested types); `scim.FromUserRow(UserRow) User`; `(IncomingUser).ActiveOrDefault() bool`; `scim.ParseUserNameFilter(filter string) (string, error)`; `scim.ParsePatchActive(body []byte) (active bool, found bool, err error)`. All consumed by Task 5 (`internal/api/scim_handlers.go`).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/scim/scim_test.go`:

```go
package scim

import "testing"

func TestFromUserRow_MapsFieldsAndSchema(t *testing.T) {
	u := FromUserRow(UserRow{
		ID: "u1", Username: "person@example.com", Active: true,
		CreatedAt: "2026-07-19T00:00:00Z", UpdatedAt: "2026-07-19T00:00:00Z",
	})
	if u.ID != "u1" || u.UserName != "person@example.com" || !u.Active {
		t.Errorf("got %+v", u)
	}
	if len(u.Schemas) != 1 || u.Schemas[0] != SchemaUser {
		t.Errorf("Schemas = %v, want [%s]", u.Schemas, SchemaUser)
	}
	if len(u.Emails) != 1 || u.Emails[0].Value != "person@example.com" || !u.Emails[0].Primary {
		t.Errorf("Emails = %+v", u.Emails)
	}
	if u.Meta == nil || u.Meta.ResourceType != "User" {
		t.Errorf("Meta = %+v", u.Meta)
	}
}

func TestIncomingUser_ActiveOrDefault(t *testing.T) {
	trueVal := true
	falseVal := false
	cases := []struct {
		name string
		in   IncomingUser
		want bool
	}{
		{"omitted defaults true", IncomingUser{UserName: "a"}, true},
		{"explicit true", IncomingUser{UserName: "a", Active: &trueVal}, true},
		{"explicit false", IncomingUser{UserName: "a", Active: &falseVal}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.ActiveOrDefault(); got != c.want {
				t.Errorf("ActiveOrDefault() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestParseUserNameFilter_SupportedShape(t *testing.T) {
	v, err := ParseUserNameFilter(`userName eq "person@example.com"`)
	if err != nil {
		t.Fatalf("ParseUserNameFilter: %v", err)
	}
	if v != "person@example.com" {
		t.Errorf("value = %q, want person@example.com", v)
	}
}

func TestParseUserNameFilter_Empty(t *testing.T) {
	v, err := ParseUserNameFilter("")
	if err != nil {
		t.Fatalf("ParseUserNameFilter: %v", err)
	}
	if v != "" {
		t.Errorf("value = %q, want empty", v)
	}
}

func TestParseUserNameFilter_UnsupportedShapeRejected(t *testing.T) {
	if _, err := ParseUserNameFilter(`userName co "person"`); err == nil {
		t.Fatal("expected an error for an unsupported filter expression, got nil")
	}
	if _, err := ParseUserNameFilter(`active eq true`); err == nil {
		t.Fatal("expected an error for a non-userName filter, got nil")
	}
}

func TestParsePatchActive_PathShape(t *testing.T) {
	body := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)
	active, found, err := ParsePatchActive(body)
	if err != nil {
		t.Fatalf("ParsePatchActive: %v", err)
	}
	if !found || active {
		t.Errorf("active=%v found=%v, want false/true", active, found)
	}
}

func TestParsePatchActive_ValueObjectShape(t *testing.T) {
	body := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":false}}]}`)
	active, found, err := ParsePatchActive(body)
	if err != nil {
		t.Fatalf("ParsePatchActive: %v", err)
	}
	if !found || active {
		t.Errorf("active=%v found=%v, want false/true", active, found)
	}
}

func TestParsePatchActive_NoActiveOperation(t *testing.T) {
	body := []byte(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"userName","value":"new@example.com"}]}`)
	_, found, err := ParsePatchActive(body)
	if err != nil {
		t.Fatalf("ParsePatchActive: %v", err)
	}
	if found {
		t.Error("found = true, want false — no active operation in this body")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/scim/... -v`
Expected: FAIL to build — `undefined: FromUserRow`, `undefined: IncomingUser`, `undefined: ParseUserNameFilter`, `undefined: ParsePatchActive` (the package has no implementation yet).

- [ ] **Step 3: Implement the types**

Create `orchestrator/internal/scim/types.go`:

```go
// Package scim implements the wire schema and translation layer for
// Audspect's SCIM 2.0 provisioning endpoints — practical RFC 7644
// compliance for Okta/Azure AD, Users-only, no Groups. See
// docs/superpowers/specs/2026-07-19-phase7-scim-provisioning-design.md.
package scim

import "encoding/json"

const (
	SchemaUser                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaListResponse          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatchOp                = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaServiceProviderConfig = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	SchemaResourceType          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaSchema                = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// Meta is the standard SCIM resource metadata block.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
}

// Email is one entry of a SCIM User's multi-valued emails attribute.
type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

// User is the outgoing wire shape for a SCIM User resource — Active is
// always serialized (never omitted), since Audspect's users.is_active is
// always a concrete boolean.
type User struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id,omitempty"`
	UserName string   `json:"userName"`
	Active   bool     `json:"active"`
	Emails   []Email  `json:"emails,omitempty"`
	Meta     *Meta    `json:"meta,omitempty"`
}

// IncomingUser is the wire shape Audspect accepts for POST/PUT request
// bodies. Active is a pointer so ActiveOrDefault can distinguish "omitted"
// (defaults to true, SCIM's convention for a newly created/replaced
// resource) from "explicitly false".
type IncomingUser struct {
	Schemas  []string `json:"schemas"`
	UserName string   `json:"userName"`
	Active   *bool    `json:"active"`
	Emails   []Email  `json:"emails,omitempty"`
}

// ActiveOrDefault returns the incoming active flag, defaulting to true
// when omitted.
func (u IncomingUser) ActiveOrDefault() bool {
	if u.Active == nil {
		return true
	}
	return *u.Active
}

// ListResponse is the wire shape for GET /Users.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []User   `json:"Resources"`
}

// Error is the wire shape for every SCIM error response.
type Error struct {
	Schemas []string `json:"schemas"`
	Status  string   `json:"status"`
	Detail  string   `json:"detail,omitempty"`
}

// PatchOp is the wire shape for PATCH /Users/{id} request bodies.
type PatchOp struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one entry of a PatchOp's Operations array. Path is
// optional — some IdPs (Azure AD) send path-less operations with the
// changed attributes nested inside Value instead.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ServiceProviderConfig is the wire shape for GET /ServiceProviderConfig —
// IdPs fetch this during SCIM app setup and refuse to proceed without it.
type ServiceProviderConfig struct {
	Schemas        []string        `json:"schemas"`
	Patch          Supported       `json:"patch"`
	Bulk           BulkSupported   `json:"bulk"`
	Filter         FilterSupported `json:"filter"`
	ChangePassword Supported       `json:"changePassword"`
	Sort           Supported       `json:"sort"`
	ETag           Supported       `json:"etag"`
}

type Supported struct {
	Supported bool `json:"supported"`
}

type BulkSupported struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

type FilterSupported struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// ResourceType is the wire shape for one entry of GET /ResourceTypes.
type ResourceType struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Endpoint    string   `json:"endpoint"`
	Description string   `json:"description"`
	Schema      string   `json:"schema"`
}

// Schema is the wire shape for one entry of GET /Schemas.
type Schema struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Attributes  []SchemaAttribute `json:"attributes"`
}

// SchemaAttribute describes one attribute of a Schema.
type SchemaAttribute struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	MultiValued bool   `json:"multiValued"`
	Required    bool   `json:"required"`
	CaseExact   bool   `json:"caseExact"`
	Mutability  string `json:"mutability"`
	Returned    string `json:"returned"`
	Uniqueness  string `json:"uniqueness"`
}
```

- [ ] **Step 4: Implement the translation layer**

Create `orchestrator/internal/scim/translate.go`:

```go
package scim

// UserRow is the subset of an Audspect users row needed to build a SCIM
// User resource — the only place SCIM's schema and Audspect's users table
// meet.
type UserRow struct {
	ID        string
	Username  string
	Active    bool
	CreatedAt string
	UpdatedAt string
}

// FromUserRow builds the outgoing SCIM User wire shape for one users row.
// Audspect's username doubles as the user's email — SCIM's userName and
// primary email are both set from it.
func FromUserRow(row UserRow) User {
	return User{
		Schemas:  []string{SchemaUser},
		ID:       row.ID,
		UserName: row.Username,
		Active:   row.Active,
		Emails:   []Email{{Value: row.Username, Primary: true}},
		Meta: &Meta{
			ResourceType: "User",
			Created:      row.CreatedAt,
			LastModified: row.UpdatedAt,
		},
	}
}
```

- [ ] **Step 5: Implement filter and PATCH parsing**

Create `orchestrator/internal/scim/filter.go`:

```go
package scim

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseUserNameFilter extracts the value from the one supported SCIM
// filter shape: userName eq "value" — the only filter Okta/Azure AD send
// for a Users-only sync, used to check for an existing user before
// creating one. An empty filter string returns ("", nil) — no filter was
// requested. Any other expression returns an error: a SCIM
// misconfiguration should be visible, not silently ignored.
func ParseUserNameFilter(filter string) (string, error) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return "", nil
	}
	const prefix = `userName eq "`
	if !strings.HasPrefix(strings.ToLower(filter), strings.ToLower(prefix)) || !strings.HasSuffix(filter, `"`) {
		return "", fmt.Errorf(`unsupported filter expression: only userName eq "value" is supported`)
	}
	value := filter[len(prefix) : len(filter)-1]
	if value == "" {
		return "", fmt.Errorf("unsupported filter expression: empty userName value")
	}
	return value, nil
}

// ParsePatchActive extracts an active:true/false operation from a SCIM
// PatchOp body, tolerating both shapes real IdPs send: a "path":"active"
// operation with a boolean value (Okta), or a path-less operation whose
// "value" object contains "active" (Azure AD). found=false means the body
// contained no active operation — Audspect only implements the
// active-toggle PATCH path, per the spec's Users-only scope.
func ParsePatchActive(body []byte) (active bool, found bool, err error) {
	var op PatchOp
	if err := json.Unmarshal(body, &op); err != nil {
		return false, false, err
	}
	for _, o := range op.Operations {
		if strings.EqualFold(o.Path, "active") {
			var v bool
			if jsonErr := json.Unmarshal(o.Value, &v); jsonErr == nil {
				return v, true, nil
			}
			continue
		}
		if o.Path == "" {
			var obj struct {
				Active *bool `json:"active"`
			}
			if jsonErr := json.Unmarshal(o.Value, &obj); jsonErr == nil && obj.Active != nil {
				return *obj.Active, true, nil
			}
		}
	}
	return false, false, nil
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/scim/... -v`
Expected: all 9 PASS.

- [ ] **Step 7: Build the whole repo and commit**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go vet ./...`
Expected: clean.

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/scim/
git commit -m "feat(scim): add internal/scim — RFC 7644 types, translation, filter parsing

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: `internal/api` — SCIM admin config CRUD

**Files:**
- Create: `orchestrator/internal/api/scim_token.go`
- Create: `orchestrator/internal/api/scim_token_test.go`
- Create: `orchestrator/internal/api/scim_config_handlers.go`
- Create: `orchestrator/internal/api/scim_config_test.go`
- Modify: `orchestrator/internal/api/sso_handlers.go` (rename `effectiveSSOTenantID` → `effectiveCallerTenantID`, reused by this task's handlers)
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `auth.CanViewSCIMConfig`/`auth.CanManageSCIMConfig` (Task 2), `h.effectiveCallerTenantID` (renamed in this task).
- Produces: `generateSCIMToken() (string, error)`, `hashSCIMToken(token string) string` (consumed by Task 5's `scimAuth`), `h.GetSCIMConfig`, `h.CreateSCIMConfig`, `h.UpdateSCIMConfig`, `h.RotateSCIMConfig`, `h.DeleteSCIMConfig`.

**Grounding note (why the rename):** the spec's admin config handlers need the exact same "tenant user acts on own tenant; platform-admin needs `?tenantId=`" resolution logic `effectiveSSOTenantID` already implements in `sso_handlers.go`. Rather than duplicate it, this task renames it to a name that reflects what it actually does (nothing in its body is SSO-specific), so both `sso_handlers.go` and this task's `scim_config_handlers.go` share one definition. A pure rename, zero behavior change — proven by the existing SSO config tests still passing unmodified.

- [ ] **Step 1: Rename `effectiveSSOTenantID` to `effectiveCallerTenantID`**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && sed -i 's/effectiveSSOTenantID/effectiveCallerTenantID/g' internal/api/sso_handlers.go`
Expected: 6 occurrences replaced (the doc comment, the definition, and 5 call sites across `GetSSOConfig`/`CreateSSOConfig`/`UpdateSSOConfig`/`DeleteSSOConfig`/`TestSSOConfig`).

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/api/... -run TestCreateSSOConfig -v`
Expected: clean build; `TestCreateSSOConfig_ThenGet` and `TestCreateSSOConfig_DuplicateForSameTenantConflicts` still PASS — proves the rename changed nothing behaviorally.

- [ ] **Step 2: Write the failing tests for token generation/hashing**

Create `orchestrator/internal/api/scim_token_test.go`:

```go
package api

import "testing"

func TestGenerateSCIMToken_UniqueAndNonEmpty(t *testing.T) {
	t1, err := generateSCIMToken()
	if err != nil {
		t.Fatalf("generateSCIMToken: %v", err)
	}
	t2, err := generateSCIMToken()
	if err != nil {
		t.Fatalf("generateSCIMToken: %v", err)
	}
	if t1 == "" || t2 == "" {
		t.Fatal("token must not be empty")
	}
	if t1 == t2 {
		t.Fatal("two calls to generateSCIMToken must not produce the same token")
	}
}

func TestHashSCIMToken_DeterministicAndDistinguishesInputs(t *testing.T) {
	h1 := hashSCIMToken("token-a")
	h2 := hashSCIMToken("token-a")
	h3 := hashSCIMToken("token-b")
	if h1 != h2 {
		t.Error("hashSCIMToken must be deterministic for the same input")
	}
	if h1 == h3 {
		t.Error("hashSCIMToken must distinguish different inputs")
	}
	if h1 == "token-a" {
		t.Error("hashSCIMToken must not return the input unchanged")
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... -run 'TestGenerateSCIMToken|TestHashSCIMToken' -v`
Expected: FAIL to build — `undefined: generateSCIMToken`, `undefined: hashSCIMToken`.

- [ ] **Step 4: Implement token generation/hashing**

Create `orchestrator/internal/api/scim_token.go`:

```go
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// generateSCIMToken returns a fresh, high-entropy bearer token — shown to
// the admin in cleartext exactly once (creation/rotation response), never
// stored or returned again.
func generateSCIMToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashSCIMToken hashes a presented bearer token for storage/lookup. A
// fast hash (not bcrypt/PBKDF2) is appropriate here: the token is already
// high-entropy random data, not a human-chosen password, so brute-force
// resistance from a slow hash buys nothing — the hash exists purely to
// protect the live credential at rest.
func hashSCIMToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... -run 'TestGenerateSCIMToken|TestHashSCIMToken' -v`
Expected: both PASS.

- [ ] **Step 6: Write the failing tests for the admin config CRUD**

Create `orchestrator/internal/api/scim_config_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCreateSCIMConfig_ReturnsTokenOnceThenGetOmitsIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")

		body := `{"defaultRole":"analyst"}`
		req := httptest.NewRequest(http.MethodPost, "/api/scim/config", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("CreateSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var created struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.Token == "" {
			t.Fatal("expected a cleartext token in the create response")
		}

		req = httptest.NewRequest(http.MethodGet, "/api/scim/config", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.GetSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), created.Token) {
			t.Fatal("GetSCIMConfig must never return the token again")
		}
	})
}

func TestCreateSCIMConfig_DuplicateForSameTenantConflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")

		req := httptest.NewRequest(http.MethodPost, "/api/scim/config", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("first create status = %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodPost, "/api/scim/config", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.CreateSCIMConfig(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("duplicate create status = %d, want 409", rec.Code)
		}
	})
}

func TestRotateSCIMConfig_InvalidatesOldTokenHash(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scim_configs (tenant_id, token_hash) VALUES ('default', $1) RETURNING id`,
			hashSCIMToken("old-token"),
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}

		req := httptest.NewRequest(http.MethodPost, "/api/scim/config/"+id+"/rotate", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.RotateSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("RotateSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var got struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Token == "" || got.Token == "old-token" {
			t.Fatalf("expected a fresh token, got %q", got.Token)
		}
		var hash string
		pool.QueryRow(t.Context(), `SELECT token_hash FROM scim_configs WHERE id=$1`, id).Scan(&hash)
		if hash == hashSCIMToken("old-token") {
			t.Error("old token's hash is still stored after rotation")
		}
		if hash != hashSCIMToken(got.Token) {
			t.Error("stored hash does not match the newly issued token")
		}
	})
}

func TestUpdateSCIMConfig_ChangesRoleAndEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scim_configs (tenant_id, token_hash, default_role, enabled) VALUES ('default', $1, 'viewer', true) RETURNING id`,
			hashSCIMToken("tok"),
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}

		req := httptest.NewRequest(http.MethodPut, "/api/scim/config/"+id, strings.NewReader(`{"defaultRole":"analyst","enabled":false}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.UpdateSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("UpdateSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var role string
		var enabled bool
		pool.QueryRow(t.Context(), `SELECT default_role, enabled FROM scim_configs WHERE id=$1`, id).Scan(&role, &enabled)
		if role != "analyst" || enabled {
			t.Errorf("role=%q enabled=%v, want analyst/false", role, enabled)
		}
	})
}

func TestDeleteSCIMConfig_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scim_configs (tenant_id, token_hash) VALUES ('default', $1) RETURNING id`,
			hashSCIMToken("tok"),
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}
		req := httptest.NewRequest(http.MethodDelete, "/api/scim/config/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.DeleteSCIMConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("DeleteSCIMConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM scim_configs WHERE id=$1`, id).Scan(&n)
		if n != 0 {
			t.Error("row still present after delete")
		}
	})
}

func TestSCIMConfig_CrossTenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		var otherTenantID string
		if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ('Other', 'other-scim') RETURNING id`).Scan(&otherTenantID); err != nil {
			t.Fatalf("seed other tenant: %v", err)
		}
		var otherConfigID string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO scim_configs (tenant_id, token_hash) VALUES ($1, $2) RETURNING id`,
			otherTenantID, hashSCIMToken("other-tok"),
		).Scan(&otherConfigID); err != nil {
			t.Fatalf("seed other config: %v", err)
		}

		defaultTok := tenantAdminToken(t, "default")

		req := httptest.NewRequest(http.MethodGet, "/api/scim/config", nil)
		req.Header.Set("Authorization", "Bearer "+defaultTok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.GetSCIMConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GetSCIMConfig cross-tenant status = %d, want 404", rec.Code)
		}

		req = httptest.NewRequest(http.MethodDelete, "/api/scim/config/"+otherConfigID, nil)
		req.Header.Set("Authorization", "Bearer "+defaultTok)
		req = withURLParam(req, "id", otherConfigID)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.DeleteSCIMConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("DeleteSCIMConfig cross-tenant status = %d, want 404", rec.Code)
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM scim_configs WHERE id=$1`, otherConfigID).Scan(&n)
		if n != 1 {
			t.Error("other tenant's config was deleted cross-tenant — isolation failed")
		}
	})
}
```

- [ ] **Step 7: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... -run 'TestCreateSCIMConfig|TestRotateSCIMConfig|TestUpdateSCIMConfig|TestDeleteSCIMConfig|TestSCIMConfig' -v`
Expected: FAIL to build — `undefined: SCIMConfigResponse`, `h.CreateSCIMConfig undefined`, etc.

- [ ] **Step 8: Implement the admin config CRUD handlers**

Create `orchestrator/internal/api/scim_config_handlers.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// SCIMConfigResponse is the admin-facing view of a scim_configs row. The
// token itself is never included here — GetSCIMConfig only reports that a
// config exists. The cleartext token is returned exactly once, from
// Create/Rotate, and never again.
type SCIMConfigResponse struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenantId"`
	DefaultRole string `json:"defaultRole"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"createdAt"`
}

// GetSCIMConfig returns the caller's tenant's SCIM config, without the token.
// GET /api/scim/config
func (h *Handler) GetSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	var cfg SCIMConfigResponse
	err := h.db.QueryRow(r.Context(),
		`SELECT id, tenant_id, default_role, enabled,
		        to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		   FROM scim_configs WHERE tenant_id = $1`, tenantID,
	).Scan(&cfg.ID, &cfg.TenantID, &cfg.DefaultRole, &cfg.Enabled, &cfg.CreatedAt)
	if err != nil {
		jsonError(w, "no SCIM config for this tenant", http.StatusNotFound)
		return
	}
	respond(w, cfg)
}

// CreateSCIMConfig creates the caller's tenant's SCIM config and returns
// the bearer token in cleartext — the only time it is ever returned.
// POST /api/scim/config
func (h *Handler) CreateSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	var req struct {
		DefaultRole string `json:"defaultRole"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.DefaultRole == "" {
		req.DefaultRole = "viewer"
	}
	if !validSSORoles[req.DefaultRole] {
		jsonError(w, "defaultRole must be viewer, analyst, or admin", http.StatusBadRequest)
		return
	}
	token, err := generateSCIMToken()
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	var id string
	err = h.db.QueryRow(r.Context(),
		`INSERT INTO scim_configs (tenant_id, token_hash, default_role) VALUES ($1,$2,$3) RETURNING id`,
		tenantID, hashSCIMToken(token), req.DefaultRole,
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			jsonError(w, "this tenant already has a SCIM config", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "scim.config_created", id, map[string]any{"tenantId": tenantID}, "ok")
	respond(w, map[string]any{"id": id, "token": token})
}

// UpdateSCIMConfig changes the caller's tenant's SCIM config's defaultRole
// and enabled flag. Does not change the token — use RotateSCIMConfig for
// that. Callers must always send both fields; enabled has no "unchanged"
// sentinel (matches UpdateSSOConfig's own convention).
// PUT /api/scim/config/{id}
func (h *Handler) UpdateSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		DefaultRole string `json:"defaultRole"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.DefaultRole != "" && !validSSORoles[req.DefaultRole] {
		jsonError(w, "defaultRole must be viewer, analyst, or admin", http.StatusBadRequest)
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE scim_configs SET default_role=COALESCE(NULLIF($1,''), default_role), enabled=$2, updated_at=NOW()
		  WHERE id=$3 AND tenant_id=$4`,
		req.DefaultRole, req.Enabled, id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SCIM config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.config_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// RotateSCIMConfig issues a fresh token for the caller's tenant's SCIM
// config, invalidating the old one immediately (its hash is overwritten,
// so any SCIM request presenting it 401s from then on). Returns the new
// token in cleartext — the only time it is ever returned.
// POST /api/scim/config/{id}/rotate
func (h *Handler) RotateSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	token, err := generateSCIMToken()
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE scim_configs SET token_hash=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3`,
		hashSCIMToken(token), id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SCIM config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.config_rotated", id, nil, "ok")
	respond(w, map[string]any{"token": token})
}

// DeleteSCIMConfig deletes the caller's tenant's SCIM config, immediately
// invalidating its token — any further SCIM request 401s. Existing
// SCIM-provisioned users are unaffected.
// DELETE /api/scim/config/{id}
func (h *Handler) DeleteSCIMConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveCallerTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM scim_configs WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SCIM config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.config_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}
```

- [ ] **Step 9: Wire the admin config routes**

In `orchestrator/internal/api/routes.go`, immediately after `r.With(auth.RequirePermission(auth.CanManageSSOConfig)).Post("/api/sso/config/{id}/test", h.TestSSOConfig)`, add:

```go

		// SCIM provisioning config — tenant-scoped CRUD. See
		// docs/superpowers/specs/2026-07-19-phase7-scim-provisioning-design.md.
		r.With(auth.RequirePermission(auth.CanViewSCIMConfig)).Get("/api/scim/config", h.GetSCIMConfig)
		r.With(auth.RequirePermission(auth.CanManageSCIMConfig)).Post("/api/scim/config", h.CreateSCIMConfig)
		r.With(auth.RequirePermission(auth.CanManageSCIMConfig)).Put("/api/scim/config/{id}", h.UpdateSCIMConfig)
		r.With(auth.RequirePermission(auth.CanManageSCIMConfig)).Post("/api/scim/config/{id}/rotate", h.RotateSCIMConfig)
		r.With(auth.RequirePermission(auth.CanManageSCIMConfig)).Delete("/api/scim/config/{id}", h.DeleteSCIMConfig)
```

- [ ] **Step 10: Add the 5 new routes to the RBAC drift matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after `{http.MethodPost, "/api/sso/config/{id}/test", tierPermission, auth.CanManageSSOConfig},`, add:

```go
	{http.MethodGet, "/api/scim/config", tierPermission, auth.CanViewSCIMConfig},
	{http.MethodPost, "/api/scim/config", tierPermission, auth.CanManageSCIMConfig},
	{http.MethodPut, "/api/scim/config/{id}", tierPermission, auth.CanManageSCIMConfig},
	{http.MethodPost, "/api/scim/config/{id}/rotate", tierPermission, auth.CanManageSCIMConfig},
	{http.MethodDelete, "/api/scim/config/{id}", tierPermission, auth.CanManageSCIMConfig},
```

- [ ] **Step 11: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/api/... -run 'TestCreateSCIMConfig|TestRotateSCIMConfig|TestUpdateSCIMConfig|TestDeleteSCIMConfig|TestSCIMConfig' -v`
Expected: all 6 PASS.

- [ ] **Step 12: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/scim_token.go internal/api/scim_token_test.go internal/api/scim_config_handlers.go internal/api/scim_config_test.go internal/api/sso_handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(scim): add tenant-scoped SCIM admin config CRUD API

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 5: `internal/api` — SCIM protocol endpoints (bearer-token authenticated)

**Files:**
- Create: `orchestrator/internal/api/scim_auth_middleware.go`
- Create: `orchestrator/internal/api/scim_handlers.go`
- Create: `orchestrator/internal/api/scim_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `hashSCIMToken` (Task 4), `scim.*` types/`FromUserRow`/`ParseUserNameFilter`/`ParsePatchActive` (Task 3), `randomSSOPlaceholder`/`auth.HashPassword` (already in `sso_handlers.go`/`internal/auth`).
- Produces: `h.scimAuth` (middleware), `h.SCIMServiceProviderConfig`, `h.SCIMResourceTypes`, `h.SCIMSchemas`, `h.SCIMCreateUser`, `h.SCIMListUsers`, `h.SCIMGetUser`, `h.SCIMReplaceUser`, `h.SCIMPatchUser`, `h.SCIMDeleteUser`.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/api/scim_handlers_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scim"
)

func seedSCIMConfig(t *testing.T, pool *pgxpool.Pool, tenantID, token, defaultRole string, enabled bool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(t.Context(),
		`INSERT INTO scim_configs (tenant_id, token_hash, default_role, enabled) VALUES ($1,$2,$3,$4) RETURNING id`,
		tenantID, hashSCIMToken(token), defaultRole, enabled,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedSCIMConfig: %v", err)
	}
	return id
}

func TestSCIMAuth_MissingWrongDisabledToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		seedSCIMConfig(t, pool, mustSeedTenant(t, pool, "disabled-tenant"), "disabled-token", "viewer", false)

		cases := []struct {
			name  string
			token string
		}{
			{"missing", ""},
			{"wrong", "no-such-token"},
			{"disabled config", "disabled-token"},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
				if c.token != "" {
					req.Header.Set("Authorization", "Bearer "+c.token)
				}
				rec := httptest.NewRecorder()
				h.scimAuth(http.HandlerFunc(h.SCIMListUsers)).ServeHTTP(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("status = %d, want 401", rec.Code)
				}
			})
		}
	})
}

func TestSCIMCreateUser_JITDefaultRoleAndAuthSource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "analyst", true)

		body := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"newhire@example.com","active":true}`
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer good-token")
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMCreateUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var role, authSource string
		var isActive bool
		err := pool.QueryRow(t.Context(), `SELECT role, auth_source, is_active FROM users WHERE username='newhire@example.com'`).
			Scan(&role, &authSource, &isActive)
		if err != nil {
			t.Fatalf("provisioned user not found: %v", err)
		}
		if role != "analyst" || authSource != "sso" || !isActive {
			t.Errorf("role=%q authSource=%q isActive=%v, want analyst/sso/true", role, authSource, isActive)
		}
	})
}

func TestSCIMCreateUser_DuplicateUserNameConflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		body := `{"userName":"dup@example.com"}`

		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer good-token")
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMCreateUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("first create status = %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer good-token")
		rec = httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMCreateUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("duplicate create status = %d, want 409", rec.Code)
		}
	})
}

func TestSCIMListUsers_FilterByUserName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		seedUser(t, pool, "alice@example.com", "pw", "viewer", true)
		seedUser(t, pool, "bob@example.com", "pw", "viewer", true)
		pool.Exec(t.Context(), `UPDATE users SET tenant_id='default' WHERE username IN ('alice@example.com','bob@example.com')`)

		req := httptest.NewRequest(http.MethodGet, `/scim/v2/Users?filter=`+`userName+eq+%22alice%40example.com%22`, nil)
		req.Header.Set("Authorization", "Bearer good-token")
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMListUsers)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var got scim.ListResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.TotalResults != 1 || len(got.Resources) != 1 || got.Resources[0].UserName != "alice@example.com" {
			t.Errorf("got %+v", got)
		}
	})
}

func TestSCIMPatchUser_ActiveFalseDeactivates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		userID := seedUser(t, pool, "person@example.com", "pw", "viewer", true)
		pool.Exec(t.Context(), `UPDATE users SET tenant_id='default' WHERE id=$1`, userID)

		body := `{"Operations":[{"op":"replace","path":"active","value":false}]}`
		req := httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/"+userID, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer good-token")
		req = withURLParam(req, "id", userID)
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMPatchUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var isActive bool
		pool.QueryRow(t.Context(), `SELECT is_active FROM users WHERE id=$1`, userID).Scan(&isActive)
		if isActive {
			t.Error("user still active after PATCH active:false")
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM users WHERE id=$1`, userID).Scan(&n)
		if n != 1 {
			t.Error("row was removed — PATCH must deactivate, never delete")
		}
	})
}

func TestSCIMDeleteUser_DeactivatesNeverHardDeletes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)
		userID := seedUser(t, pool, "leaving@example.com", "pw", "viewer", true)
		pool.Exec(t.Context(), `UPDATE users SET tenant_id='default' WHERE id=$1`, userID)

		req := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+userID, nil)
		req.Header.Set("Authorization", "Bearer good-token")
		req = withURLParam(req, "id", userID)
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMDeleteUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204, body=%s", rec.Code, rec.Body.String())
		}

		var isActive bool
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM users WHERE id=$1`, userID).Scan(&n)
		if n != 1 {
			t.Fatal("row was hard-deleted — must only soft-deactivate")
		}
		pool.QueryRow(t.Context(), `SELECT is_active FROM users WHERE id=$1`, userID).Scan(&isActive)
		if isActive {
			t.Error("user still active after DELETE")
		}
	})
}

func TestSCIMUsers_CrossTenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		otherTenantID := mustSeedTenant(t, pool, "other-scim-users")
		seedSCIMConfig(t, pool, "default", "default-token", "viewer", true)
		seedSCIMConfig(t, pool, otherTenantID, "other-token", "viewer", true)
		otherUserID := seedUser(t, pool, "other-tenant-user@example.com", "pw", "viewer", true)
		pool.Exec(t.Context(), `UPDATE users SET tenant_id=$1 WHERE id=$2`, otherTenantID, otherUserID)

		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+otherUserID, nil)
		req.Header.Set("Authorization", "Bearer default-token")
		req = withURLParam(req, "id", otherUserID)
		rec := httptest.NewRecorder()
		h.scimAuth(http.HandlerFunc(h.SCIMGetUser)).ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("cross-tenant GET status = %d, want 404", rec.Code)
		}
	})
}

func TestSCIMServiceProviderConfig_DiscoveryEndpoints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		seedSCIMConfig(t, pool, "default", "good-token", "viewer", true)

		for _, tc := range []struct {
			path    string
			handler http.HandlerFunc
		}{
			{"/scim/v2/ServiceProviderConfig", h.SCIMServiceProviderConfig},
			{"/scim/v2/ResourceTypes", h.SCIMResourceTypes},
			{"/scim/v2/Schemas", h.SCIMSchemas},
		} {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer good-token")
			rec := httptest.NewRecorder()
			h.scimAuth(tc.handler).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("%s status = %d, body=%s", tc.path, rec.Code, rec.Body.String())
			}
			var probe map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &probe); err != nil {
				t.Errorf("%s: invalid JSON: %v", tc.path, err)
			}
		}
	})
}

// mustSeedTenant inserts a tenant row for tests that need a second tenant
// beyond the bootstrap "default" one.
func mustSeedTenant(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ($1, $1) RETURNING id`, slug).Scan(&id); err != nil {
		t.Fatalf("mustSeedTenant: %v", err)
	}
	return id
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... -run 'TestSCIMAuth|TestSCIMCreateUser|TestSCIMListUsers|TestSCIMPatchUser|TestSCIMDeleteUser|TestSCIMUsers|TestSCIMServiceProviderConfig' -v`
Expected: FAIL to build — `h.scimAuth undefined`, `h.SCIMCreateUser undefined`, etc.

- [ ] **Step 3: Implement the auth middleware**

Create `orchestrator/internal/api/scim_auth_middleware.go`:

```go
package api

import (
	"context"
	"net/http"
	"strings"
)

type ctxSCIMTenantKey struct{}

// scimAuth authenticates a SCIM request by its per-tenant bearer token,
// entirely outside the JWT/RBAC system — there is no user identity or
// role here, only a resolved tenant. A missing token, an unrecognized
// token, or a token belonging to a disabled config are all treated
// identically: 401, fail closed.
func (h *Handler) scimAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authz, "Bearer ")
		if token == "" || !strings.HasPrefix(authz, "Bearer ") {
			scimErrorResponse(w, "missing or invalid bearer token", http.StatusUnauthorized)
			return
		}
		var tenantID string
		var enabled bool
		err := h.db.QueryRow(r.Context(),
			`SELECT tenant_id, enabled FROM scim_configs WHERE token_hash = $1`, hashSCIMToken(token),
		).Scan(&tenantID, &enabled)
		if err != nil || !enabled {
			scimErrorResponse(w, "invalid or disabled token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ctxSCIMTenantKey{}, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// scimTenantFrom retrieves the tenant resolved by scimAuth.
func scimTenantFrom(ctx context.Context) (string, bool) {
	tid, ok := ctx.Value(ctxSCIMTenantKey{}).(string)
	return tid, ok
}
```

- [ ] **Step 4: Implement the SCIM protocol handlers**

Create `orchestrator/internal/api/scim_handlers.go`:

```go
package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scim"
)

func scimErrorResponse(w http.ResponseWriter, detail string, status int) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(scim.Error{
		Schemas: []string{scim.SchemaError},
		Status:  strconv.Itoa(status),
		Detail:  detail,
	})
}

func scimRespond(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// SCIMServiceProviderConfig — GET /scim/v2/ServiceProviderConfig. Fetched
// by IdPs during SCIM app setup; they refuse to proceed without it.
func (h *Handler) SCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	scimRespond(w, scim.ServiceProviderConfig{
		Schemas:        []string{scim.SchemaServiceProviderConfig},
		Patch:          scim.Supported{Supported: true},
		Bulk:           scim.BulkSupported{Supported: false},
		Filter:         scim.FilterSupported{Supported: true, MaxResults: 200},
		ChangePassword: scim.Supported{Supported: false},
		Sort:           scim.Supported{Supported: false},
		ETag:           scim.Supported{Supported: false},
	}, http.StatusOK)
}

// SCIMResourceTypes — GET /scim/v2/ResourceTypes.
func (h *Handler) SCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	scimRespond(w, []scim.ResourceType{{
		Schemas:     []string{scim.SchemaResourceType},
		ID:          "User",
		Name:        "User",
		Endpoint:    "/Users",
		Description: "Audspect user account",
		Schema:      scim.SchemaUser,
	}}, http.StatusOK)
}

// SCIMSchemas — GET /scim/v2/Schemas.
func (h *Handler) SCIMSchemas(w http.ResponseWriter, r *http.Request) {
	scimRespond(w, []scim.Schema{{
		Schemas:     []string{scim.SchemaSchema},
		ID:          scim.SchemaUser,
		Name:        "User",
		Description: "Audspect user account",
		Attributes: []scim.SchemaAttribute{
			{Name: "userName", Type: "string", Required: true, Mutability: "readWrite", Returned: "default", Uniqueness: "server"},
			{Name: "active", Type: "boolean", Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
			{Name: "emails", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
		},
	}}, http.StatusOK)
}

// SCIMCreateUser — POST /scim/v2/Users.
func (h *Handler) SCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		scimErrorResponse(w, "invalid body", http.StatusBadRequest)
		return
	}
	var in scim.IncomingUser
	if err := json.Unmarshal(body, &in); err != nil || in.UserName == "" {
		scimErrorResponse(w, "userName is required", http.StatusBadRequest)
		return
	}
	var defaultRole string
	if err := h.db.QueryRow(r.Context(), `SELECT default_role FROM scim_configs WHERE tenant_id=$1`, tenantID).Scan(&defaultRole); err != nil {
		scimErrorResponse(w, "SCIM not configured for this tenant", http.StatusInternalServerError)
		return
	}
	placeholder, hErr := auth.HashPassword(randomSSOPlaceholder())
	if hErr != nil {
		scimErrorResponse(w, "internal error", http.StatusInternalServerError)
		return
	}
	var id, createdAt string
	err = h.db.QueryRow(r.Context(),
		`INSERT INTO users (username, password_hash, role, tenant_id, auth_source, is_active)
		 VALUES ($1,$2,$3,$4,'sso',$5) RETURNING id, to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`,
		in.UserName, placeholder, defaultRole, tenantID, in.ActiveOrDefault(),
	).Scan(&id, &createdAt)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			scimErrorResponse(w, "a user with this userName already exists", http.StatusConflict)
			return
		}
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "scim.user_provisioned", id, map[string]any{"username": in.UserName, "tenantId": tenantID}, "ok")
	scimRespond(w, scim.FromUserRow(scim.UserRow{
		ID: id, Username: in.UserName, Active: in.ActiveOrDefault(), CreatedAt: createdAt, UpdatedAt: createdAt,
	}), http.StatusCreated)
}

// SCIMListUsers — GET /scim/v2/Users. Supports the one filter shape
// (userName eq "value") and startIndex/count pagination.
func (h *Handler) SCIMListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	q := r.URL.Query()
	startIndex := 1
	if v, err := strconv.Atoi(q.Get("startIndex")); err == nil && v > 0 {
		startIndex = v
	}
	count := 100
	if v, err := strconv.Atoi(q.Get("count")); err == nil && v > 0 {
		count = v
	}
	usernameFilter, err := scim.ParseUserNameFilter(q.Get("filter"))
	if err != nil {
		scimErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	var total int
	h.db.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM users WHERE tenant_id=$1 AND ($2 = '' OR username = $2)`,
		tenantID, usernameFilter).Scan(&total)

	rows, err := h.db.Query(r.Context(),
		`SELECT id, username, is_active, to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"'), to_char(updated_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		   FROM users WHERE tenant_id=$1 AND ($2 = '' OR username = $2)
		  ORDER BY created_at ASC OFFSET $3 LIMIT $4`,
		tenantID, usernameFilter, startIndex-1, count)
	if err != nil {
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	resources := []scim.User{}
	for rows.Next() {
		var row scim.UserRow
		if rows.Scan(&row.ID, &row.Username, &row.Active, &row.CreatedAt, &row.UpdatedAt) != nil {
			continue
		}
		resources = append(resources, scim.FromUserRow(row))
	}
	scimRespond(w, scim.ListResponse{
		Schemas:      []string{scim.SchemaListResponse},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}, http.StatusOK)
}

func (h *Handler) loadSCIMUserRow(r *http.Request, id, tenantID string) (*scim.UserRow, error) {
	var row scim.UserRow
	err := h.db.QueryRow(r.Context(),
		`SELECT id, username, is_active, to_char(created_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"'), to_char(updated_at,'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		   FROM users WHERE id=$1 AND tenant_id=$2`, id, tenantID,
	).Scan(&row.ID, &row.Username, &row.Active, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// SCIMGetUser — GET /scim/v2/Users/{id}.
func (h *Handler) SCIMGetUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	row, err := h.loadSCIMUserRow(r, chi.URLParam(r, "id"), tenantID)
	if err != nil {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	scimRespond(w, scim.FromUserRow(*row), http.StatusOK)
}

// SCIMReplaceUser — PUT /scim/v2/Users/{id}.
func (h *Handler) SCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		scimErrorResponse(w, "invalid body", http.StatusBadRequest)
		return
	}
	var in scim.IncomingUser
	if err := json.Unmarshal(body, &in); err != nil || in.UserName == "" {
		scimErrorResponse(w, "userName is required", http.StatusBadRequest)
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE users SET username=$1, is_active=$2 WHERE id=$3 AND tenant_id=$4`,
		in.UserName, in.ActiveOrDefault(), id, tenantID)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			scimErrorResponse(w, "a user with this userName already exists", http.StatusConflict)
			return
		}
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.user_replaced", id, nil, "ok")
	row, err := h.loadSCIMUserRow(r, id, tenantID)
	if err != nil {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	scimRespond(w, scim.FromUserRow(*row), http.StatusOK)
}

// SCIMPatchUser — PATCH /scim/v2/Users/{id}. Only an active:true/false
// operation is supported — the only PATCH real IdPs send for a
// Users-only sync.
func (h *Handler) SCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		scimErrorResponse(w, "invalid body", http.StatusBadRequest)
		return
	}
	active, found, err := scim.ParsePatchActive(body)
	if err != nil {
		scimErrorResponse(w, "invalid PatchOp body", http.StatusBadRequest)
		return
	}
	if !found {
		scimErrorResponse(w, "only an active operation is supported", http.StatusBadRequest)
		return
	}
	ct, err := h.db.Exec(r.Context(), `UPDATE users SET is_active=$1 WHERE id=$2 AND tenant_id=$3`, active, id, tenantID)
	if err != nil {
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	action := "scim.user_deactivated"
	if active {
		action = "scim.user_reactivated"
	}
	h.auditLog(r, action, id, nil, "ok")
	row, err := h.loadSCIMUserRow(r, id, tenantID)
	if err != nil {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	scimRespond(w, scim.FromUserRow(*row), http.StatusOK)
}

// SCIMDeleteUser — DELETE /scim/v2/Users/{id}. Soft-deactivates only
// (is_active=false) — never removes the row. Too many tables
// (audit_logs, scenario_runs, findings, campaigns) reference users.id.
func (h *Handler) SCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := scimTenantFrom(r.Context())
	if !ok {
		scimErrorResponse(w, "no tenant context", http.StatusUnauthorized)
		return
	}
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `UPDATE users SET is_active=false WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		scimErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		scimErrorResponse(w, "User not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "scim.user_deactivated", id, nil, "ok")
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 5: Wire the SCIM routes, outside the JWT group**

In `orchestrator/internal/api/routes.go`, immediately after `r.Post("/api/ticketing/webhook/{configId}", h.ReceiveTicketingWebhook)`, add:

```go

	// SCIM (RFC 7644) — own per-tenant bearer-token auth, not JWT. See
	// docs/superpowers/specs/2026-07-19-phase7-scim-provisioning-design.md.
	r.Group(func(r chi.Router) {
		r.Use(h.scimAuth)
		r.Get("/scim/v2/ServiceProviderConfig", h.SCIMServiceProviderConfig)
		r.Get("/scim/v2/ResourceTypes", h.SCIMResourceTypes)
		r.Get("/scim/v2/Schemas", h.SCIMSchemas)
		r.Post("/scim/v2/Users", h.SCIMCreateUser)
		r.Get("/scim/v2/Users", h.SCIMListUsers)
		r.Get("/scim/v2/Users/{id}", h.SCIMGetUser)
		r.Put("/scim/v2/Users/{id}", h.SCIMReplaceUser)
		r.Patch("/scim/v2/Users/{id}", h.SCIMPatchUser)
		r.Delete("/scim/v2/Users/{id}", h.SCIMDeleteUser)
	})
```

- [ ] **Step 6: Add the 9 new routes to the drift-guard's exclusion list**

In `orchestrator/internal/api/rbac_matrix_test.go`, in the `publicRoutes` map, immediately after `"GET /api/auth/sso/callback": true,`, add:

```go
	"GET /scim/v2/ServiceProviderConfig": true,
	"GET /scim/v2/ResourceTypes":         true,
	"GET /scim/v2/Schemas":               true,
	"POST /scim/v2/Users":                true,
	"GET /scim/v2/Users":                 true,
	"GET /scim/v2/Users/{id}":            true,
	"PUT /scim/v2/Users/{id}":            true,
	"PATCH /scim/v2/Users/{id}":          true,
	"DELETE /scim/v2/Users/{id}":         true,
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/api/... -run 'TestSCIMAuth|TestSCIMCreateUser|TestSCIMListUsers|TestSCIMPatchUser|TestSCIMDeleteUser|TestSCIMUsers|TestSCIMServiceProviderConfig' -v`
Expected: all 8 PASS.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... -run 'TestRBACMatrix|TestPlatformAdminRoutes_Gating' -v`
Expected: all PASS — proves `TestRBACMatrix_NoDrift` recognizes every new `/scim/v2/*` route via `publicRoutes`, and `TestRBACMatrix_AuthorizationBoundary`/`TestPlatformAdminRoutes_Gating` are unaffected by the new JWT-gated admin routes (already using tenant-aware matrix tokens since the SSO slice's fixture fix).

- [ ] **Step 8: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/scim_auth_middleware.go internal/api/scim_handlers.go internal/api/scim_handlers_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(scim): add SCIM protocol endpoints — discovery, User CRUD, JIT provisioning

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 6: Full regression + capture

**Files:** none (verification + vault/memory).

- [ ] **Step 1: Full repo test suite**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./...`
Expected: PASS across every package.

- [ ] **Step 2: Whole-build + vet + gofmt**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go vet ./...`
Expected: clean.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/db/postgres.go internal/auth/permissions.go internal/auth/permissions_test.go internal/scim/ internal/api/scim_token.go internal/api/scim_token_test.go internal/api/scim_config_handlers.go internal/api/scim_config_test.go internal/api/scim_auth_middleware.go internal/api/scim_handlers.go internal/api/scim_handlers_test.go internal/api/sso_handlers.go internal/api/routes.go internal/api/rbac_matrix_test.go`
Expected: no output. If anything is listed, `gofmt -w` it and commit as a dedicated `style:` commit.

- [ ] **Step 3: Update the vault (outside the git repo)**

The vault at `C:\Users\Administrator\Audspect-Vault` is NOT in the repo — update it directly, do not `git add` it.
- Create `04 Features/SCIM Provisioning.md` (feature note: architecture, the bearer-token/hash-once auth model, soft-deactivate-only semantics, cross-tenant isolation, the `effectiveCallerTenantID` rename, RFC 7644 discovery-endpoint compliance).
- Edit `11 Roadmaps/Roadmap.md`: mark Identity & Access's SCIM piece done — this completes all 3 pieces of the sub-project.
- Append to the current daily note: this session's work.

- [ ] **Step 4: Update Claude memory**

Edit `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_platform_roadmap_2026h2.md`: mark Identity & Access's SCIM piece done under the Phase 7 section — note that this completes Phase 7 Sub-project 2 in full. Update the `MEMORY.md` index line.

- [ ] **Step 5: Report completion**

Announce the feature is done, list the commits, and state plainly: this completes Phase 7 Sub-project 2 (Identity & Access) in full — RBAC expansion, SSO (OIDC), and SCIM provisioning are all shipped. Note explicitly what's still out of scope for a future slice if ever needed: SCIM Groups/group-to-role mapping, SAML, IdP-initiated login, session/JWT revocation on deactivation (existing tokens remain valid until natural 24h expiry) — none of these are gaps to rediscover, they were deliberate cuts.

---

## Self-Review

**Spec coverage:**
- Users only, no Groups → Tasks 3-5 (no Group type/endpoint anywhere). ✓
- Per-tenant static bearer token, hashed, shown once → Task 1 (schema), Task 4 (`generateSCIMToken`/`hashSCIMToken`, `CreateSCIMConfig`/`RotateSCIMConfig` return `token` only in their own response). ✓
- Token-only tenant resolution, flat URL → Task 5 (`scimAuth`, `/scim/v2/*` with no tenant slug). ✓
- Soft-deactivate only → Task 5 (`SCIMDeleteUser`/`SCIMPatchUser` both `UPDATE ... is_active`, never `DELETE FROM users`), proven by `TestSCIMDeleteUser_DeactivatesNeverHardDeletes`/`TestSCIMPatchUser_ActiveFalseDeactivates`. ✓
- Role source: tenant-wide default role → Task 5 (`SCIMCreateUser` reads `scim_configs.default_role`), proven by `TestSCIMCreateUser_JITDefaultRoleAndAuthSource`. ✓
- Separate `scim_configs` table → Task 1. ✓
- Practical RFC 7644 compliance (discovery + CRUD + one filter shape + pagination) → Task 3 (`filter.go`), Task 5 (discovery handlers + `SCIMListUsers`). ✓
- 2 new permissions, RBAC-matrix coverage → Tasks 2, 4, 5. ✓
- Cross-tenant isolation on both config and Users endpoints → `TestSCIMConfig_CrossTenantIsolation` (Task 4), `TestSCIMUsers_CrossTenantIsolation` (Task 5). ✓
- Out-of-scope items (Groups, fuller filter grammar, OAuth SCIM auth, session revocation) → none touched by any task, restated in Task 6 Step 5's completion report. ✓

**Grounding corrections made while writing this plan:**
1. The spec's Components & Files section listed exactly 4 admin config endpoints (Get/Create/Rotate/Delete) but the schema includes an `enabled` column with no endpoint that could ever set it to `false` without deleting the whole config and losing the token. Added a 5th endpoint, `UpdateSCIMConfig` (`PUT /api/scim/config/{id}`), so an admin can pause SCIM (or change `default_role`) without rotating/losing the token — makes the `enabled` column reachable via normal API usage, consistent with how `sso_configs.enabled` is already reachable through `UpdateSSOConfig`.
2. `effectiveSSOTenantID` (from the SSO slice) implements generic "resolve the caller's tenant, requiring `?tenantId=` for platform-admins" logic with nothing SSO-specific in its body. Rather than duplicate ~15 lines of identical logic for SCIM's admin config handlers, Task 4 renames it to `effectiveCallerTenantID` (one `sed` pass, 6 occurrences, zero behavior change) and both `sso_handlers.go` and `scim_config_handlers.go` share the one definition.

**Placeholder scan:** no TBD/TODO; every code step shows complete code; every command has an expected result.

**Type consistency:** `scim.User`/`IncomingUser`/`UserRow`/`ListResponse`/`Error`/`PatchOp`/`ServiceProviderConfig`/`ResourceType`/`Schema` (Task 3) are used identically in Task 5's handlers. `scim.FromUserRow`/`ParseUserNameFilter`/`ParsePatchActive` (Task 3) signatures match their call sites in Task 5 exactly. `generateSCIMToken`/`hashSCIMToken` (Task 4) are consumed by Task 5's `scimAuth` without re-declaration — same package, no import needed. `h.effectiveCallerTenantID` (renamed in Task 4) is used identically by both `sso_handlers.go`'s existing 5 call sites and `scim_config_handlers.go`'s new ones.
