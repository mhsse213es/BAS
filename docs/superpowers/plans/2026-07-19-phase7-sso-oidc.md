# Phase 7, Sub-project 2 (Identity & Access) — Part 2: SSO (OIDC) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OIDC-based SSO as a second, parallel way to reach the platform's existing tenant-aware JWT login — per-tenant IdP config, JIT user provisioning, zero disruption to local password login.

**Architecture:** A new `internal/oidcauth` package wraps OIDC discovery + Authorization Code/PKCE token exchange. A new `sso_configs` table (real tenant-scoped query enforcement, not just schema) holds one IdP config per tenant. Two new public endpoints (`/login/{tenantSlug}/sso`, `/api/auth/sso/callback`) drive the browser through the flow and mint a token via the same `auth.GenerateTenantToken` `Login` already uses. A small side-fix corrects a naming collision discovered in the prior Multi-Tenancy migration.

**Tech Stack:** Go, `github.com/coreos/go-oidc/v3` (new dependency — OIDC discovery + ID-token verification), `golang.org/x/oauth2` (new dependency — Authorization Code exchange), existing `golang-jwt/jwt/v5`, chi router, PostgreSQL/pgx.

## Global Constraints

- **OIDC only** — no SAML in this slice (spec Decision).
- **Per-tenant config**, `UNIQUE (tenant_id)` — one IdP per tenant, no multi-IdP-per-tenant.
- **JIT provisioning only** — no IdP-group-to-role claim mapping; role comes from the tenant's flat `default_role` setting.
- **Tenant-slug URL discovery** (`/login/{tenantSlug}/sso`) — no email-domain lookup.
- **Real tenant-scoped query enforcement on `sso_configs`** — every handler filters `WHERE tenant_id = $callerTenant` explicitly, ahead of the rest of the still-deferred Multi-Tenancy rollout.
- **No SLO, no IdP-initiated login, no SAML, no SCIM** — see spec's "Out of scope."
- **`client_secret` is masked in every API response** (`"***"` placeholder), same convention as `ticketing_configs`/`detection_connectors`.

---

### Task 1: Database schema — side-fix + `sso_configs` + `users.auth_source`

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (append to the `stmts` slice, before its closing `}` — same insertion point every prior Phase 7 slice used)
- Modify: `orchestrator/internal/api/detectverify_handlers.go:22, 91, 138, 199` (rename `tenant_id` → `azure_tenant_id` in 4 raw SQL statements)

**Interfaces:**
- Produces: `sso_configs` table (`id, tenant_id, issuer_url, client_id, client_secret, default_role, enabled, created_at, updated_at`, `UNIQUE(tenant_id)`, `tenant_id REFERENCES tenants(id)`); `users.auth_source text NOT NULL DEFAULT 'local'`; `detection_connectors.azure_tenant_id` (renamed from the old `tenant_id`) + a genuine new `detection_connectors.tenant_id text NOT NULL DEFAULT 'default'`.

- [ ] **Step 1: Ground the current end of the migration slice**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n "ALTER TABLE verification_history ADD COLUMN" internal/db/postgres.go`
Expected: one match — this is the last line of the existing `stmts` slice (the end of the Multi-Tenancy migration block). Confirm the line immediately after it is `}` closing the slice, then `for _, s := range stmts {`.

- [ ] **Step 2: Fix the `detection_connectors` tenant_id collision, in place**

The existing line (added by the prior Multi-Tenancy slice, currently a silent no-op) reads:

```go
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
```

Using Edit, replace it with:

```go
		// detection_connectors already had a column named tenant_id — the
		// Azure AD tenant ID for that connector's OAuth (client_id/client_secret
		// neighbor), unrelated to Audspect's own multi-tenancy. The ADD COLUMN
		// IF NOT EXISTS above silently no-op'd on this table when the prior
		// Multi-Tenancy migration ran. Renamed here first (idempotent: only
		// fires once, since after the first run tenant_id no longer exists
		// under the old meaning), then the real column is added. See
		// docs/superpowers/specs/2026-07-19-phase7-sso-oidc-design.md.
		`DO $$
		BEGIN
			IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'detection_connectors' AND column_name = 'tenant_id')
			   AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'detection_connectors' AND column_name = 'azure_tenant_id')
			THEN
				ALTER TABLE detection_connectors RENAME COLUMN tenant_id TO azure_tenant_id;
			END IF;
		END $$`,
		`ALTER TABLE detection_connectors ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default'`,
```

- [ ] **Step 3: Add `sso_configs` and `users.auth_source`, at the end of the slice**

Immediately before the `}` that closes the `stmts` slice (right after the `verification_history` line from Step 1's grounding), add:

```go

		// SSO (OIDC) — Phase 7 Identity & Access, Part 2. One OIDC config per
		// tenant; client_secret is masked in every API response (never
		// returned in cleartext once saved). UNIQUE(tenant_id) — exactly one
		// IdP per tenant for this slice. See
		// docs/superpowers/specs/2026-07-19-phase7-sso-oidc-design.md.
		`CREATE TABLE IF NOT EXISTS sso_configs (
			id            text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			tenant_id     text        NOT NULL REFERENCES tenants(id),
			issuer_url    text        NOT NULL,
			client_id     text        NOT NULL,
			client_secret text        NOT NULL,
			default_role  text        NOT NULL DEFAULT 'viewer',
			enabled       boolean     NOT NULL DEFAULT true,
			created_at    timestamptz NOT NULL DEFAULT NOW(),
			updated_at    timestamptz NOT NULL DEFAULT NOW(),
			UNIQUE (tenant_id)
		)`,

		// users.auth_source: 'local' or 'sso'. Login (password flow) rejects
		// outright when auth_source = 'sso', in addition to the password
		// check already failing against a random placeholder hash — explicit
		// defense-in-depth, not reliance on the hash being merely
		// impractical to guess.
		`ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_source text NOT NULL DEFAULT 'local'`,
```

- [ ] **Step 4: Rename the 4 `tenant_id` SQL references in `detectverify_handlers.go`**

Using Edit, apply these 4 replacements in `orchestrator/internal/api/detectverify_handlers.go`:

1. In `ListDetectionConnectors` — old: `` `SELECT id, name, provider, enabled, auto_verify, tenant_id, workspace_id, base_url, `` → new: `` `SELECT id, name, provider, enabled, auto_verify, azure_tenant_id, workspace_id, base_url, ``

2. In `CreateDetectionConnector` — old: `` `INSERT INTO detection_connectors\n\t\t (name, provider, enabled, auto_verify, tenant_id, client_id, client_secret, workspace_id, base_url, api_token, verify_delay_seconds) `` → new: same but `tenant_id` → `azure_tenant_id` in the column list.

3. In `UpdateDetectionConnector` — old: `` `UPDATE detection_connectors SET name=$1, enabled=$2, auto_verify=$3, tenant_id=$4, `` → new: `` `UPDATE detection_connectors SET name=$1, enabled=$2, auto_verify=$3, azure_tenant_id=$4, ``

4. In `loadDetectionConnector` — old: `` `SELECT id, name, provider, enabled, auto_verify, tenant_id, client_id, client_secret, `` → new: `` `SELECT id, name, provider, enabled, auto_verify, azure_tenant_id, client_id, client_secret, ``

The Go struct field name (`Config.TenantID`) and the JSON field name (`"tenantId"`) are **unchanged** — this is a DB-column-only rename; package context already disambiguates the Go/JSON side, and renaming those too would be unnecessary API-contract churn.

- [ ] **Step 5: Build and run the affected regression**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/detectverify/... ./internal/api/... -run 'TestListDetectionConnectors|TestCreateDetectionConnector|TestUpdateDetectionConnector|TestDeleteDetectionConnector|TestTestDetectionConnector|TestDefenderXDR|TestSentinel' -v`
Expected: all PASS — proves the rename didn't break the existing detection-connector CRUD or the Entra token-source connectors (which use `Config.TenantID` in Go, untouched).

- [ ] **Step 6: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/db/postgres.go internal/api/detectverify_handlers.go
git commit -m "feat(sso): fix detection_connectors tenant_id collision, add sso_configs + users.auth_source

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 2: `internal/auth` — SSO state signing + 2 new permissions

**Files:**
- Create: `orchestrator/internal/auth/sso_state.go`
- Create: `orchestrator/internal/auth/sso_state_test.go`
- Modify: `orchestrator/internal/auth/permissions.go`
- Modify: `orchestrator/internal/auth/permissions_test.go`

**Interfaces:**
- Produces: `auth.GenerateSSOState(tenantID, codeVerifier, secret string, ttl time.Duration) (string, error)`, `auth.ValidateSSOState(tokenStr, secret string) (*SSOStateClaims, error)` with `SSOStateClaims{TenantID, CodeVerifier string}`. Two new permissions: `auth.CanViewSSOConfig` (`"sso:config:view"`), `auth.CanManageSSOConfig` (`"sso:config:manage"`), granted to `RoleAdmin` only. Consumed by Task 4 (handlers) and Task 5 (login flow).

- [ ] **Step 1: Write the failing tests for SSO state signing**

Create `orchestrator/internal/auth/sso_state_test.go`:

```go
package auth

import (
	"testing"
	"time"
)

func TestSSOState_RoundTrip(t *testing.T) {
	tok, err := GenerateSSOState("acme", "verifier-abc123", "secret", 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateSSOState: %v", err)
	}
	claims, err := ValidateSSOState(tok, "secret")
	if err != nil {
		t.Fatalf("ValidateSSOState: %v", err)
	}
	if claims.TenantID != "acme" {
		t.Errorf("TenantID = %q, want acme", claims.TenantID)
	}
	if claims.CodeVerifier != "verifier-abc123" {
		t.Errorf("CodeVerifier = %q, want verifier-abc123", claims.CodeVerifier)
	}
}

func TestSSOState_Expired(t *testing.T) {
	tok, err := GenerateSSOState("acme", "verifier-abc123", "secret", -time.Minute)
	if err != nil {
		t.Fatalf("GenerateSSOState: %v", err)
	}
	if _, err := ValidateSSOState(tok, "secret"); err == nil {
		t.Fatal("expected an error for an expired state token, got nil")
	}
}

func TestSSOState_WrongSecret(t *testing.T) {
	tok, err := GenerateSSOState("acme", "verifier-abc123", "secret", 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateSSOState: %v", err)
	}
	if _, err := ValidateSSOState(tok, "wrong-secret"); err == nil {
		t.Fatal("expected an error for a state token signed with a different secret, got nil")
	}
}

func TestSSOState_Tampered(t *testing.T) {
	tok, err := GenerateSSOState("acme", "verifier-abc123", "secret", 10*time.Minute)
	if err != nil {
		t.Fatalf("GenerateSSOState: %v", err)
	}
	tampered := tok[:len(tok)-1] + "x"
	if _, err := ValidateSSOState(tampered, "secret"); err == nil {
		t.Fatal("expected an error for a tampered state token, got nil")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/auth/... -run TestSSOState -v`
Expected: FAIL — `undefined: GenerateSSOState` (the function doesn't exist yet).

- [ ] **Step 3: Implement SSO state signing**

Create `orchestrator/internal/auth/sso_state.go`:

```go
package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SSOStateClaims is the signed payload carried through the OIDC "state"
// parameter — the browser round-trips it opaquely to the IdP and back, so it
// must be tamper-evident (HMAC-signed, reusing the same JWT mechanism the
// platform's own login tokens use) and short-lived. It carries the raw PKCE
// code_verifier (not a hash — the token-exchange step must present the
// verifier in cleartext to the IdP; only the derived code_challenge, sent in
// the initial authorization request, is a hash). Carrying the raw verifier
// inside a signed token is safe here: state's threat model is tamper
// evidence via the browser round-trip, not confidentiality from the
// browser completing its own legitimate login.
type SSOStateClaims struct {
	TenantID     string `json:"tenant_id"`
	CodeVerifier string `json:"code_verifier"`
	jwt.RegisteredClaims
}

// GenerateSSOState creates a signed, short-lived state token binding one
// login attempt to one tenant and one PKCE code verifier.
func GenerateSSOState(tenantID, codeVerifier, secret string, ttl time.Duration) (string, error) {
	claims := SSOStateClaims{
		TenantID:     tenantID,
		CodeVerifier: codeVerifier,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
}

// ValidateSSOState parses and validates a state token, returning its claims.
func ValidateSSOState(tokenStr, secret string) (*SSOStateClaims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &SSOStateClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*SSOStateClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("invalid state claims")
	}
	return claims, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/auth/... -run TestSSOState -v`
Expected: all 4 PASS.

- [ ] **Step 5: Add the 2 new permissions to `permissions.go`**

In `orchestrator/internal/auth/permissions.go`, inside the `const ( ... )` block, immediately after the `CanInstantiateExerciseTemplate` line (the last one from the RBAC-expansion slice), add:

```go

	// SSO (OIDC) config — Admin only. New capability, not a route that
	// existed before this slice, so it doesn't inherit a Group A/B grant
	// from the RBAC-expansion migration.
	CanViewSSOConfig   Permission = "sso:config:view"
	CanManageSSOConfig Permission = "sso:config:manage"
```

In `rolePermissions[RoleAdmin]`, immediately after the `CanInstantiateExerciseTemplate: true,` line, add:

```go
		CanViewSSOConfig: true, CanManageSSOConfig: true,
```

In `Permissions()`'s ordered slice, immediately after `CanCreateExerciseTemplate, CanInstantiateExerciseTemplate,` add:

```go

		CanViewSSOConfig, CanManageSSOConfig,
```

- [ ] **Step 6: Update the 2 pre-existing tests that hard-code the permission count**

In `orchestrator/internal/auth/permissions_test.go`, `TestHasPermission_MatrixIsComplete`'s `tested` map gains, immediately after `CanCreateExerciseTemplate: true, CanInstantiateExerciseTemplate: true,`:

```go
		CanViewSSOConfig: true, CanManageSSOConfig: true,
```

`TestPermissions_Ordering`'s `want` slice gains, immediately after `CanCreateExerciseTemplate, CanInstantiateExerciseTemplate,`:

```go

		CanViewSSOConfig, CanManageSSOConfig,
```

- [ ] **Step 7: Build and test**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/auth/... -v`
Expected: clean build; all tests pass, including `TestHasPermission_MatrixIsComplete` and `TestPermissions_Ordering` now covering 94 permissions (92 + 2).

- [ ] **Step 8: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/auth/sso_state.go internal/auth/sso_state_test.go internal/auth/permissions.go internal/auth/permissions_test.go
git commit -m "feat(sso): add SSO state signing and 2 new SSO config permissions

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 3: `internal/oidcauth` — OIDC provider wrapper

**Files:**
- Create: `orchestrator/internal/oidcauth/provider.go`
- Create: `orchestrator/internal/oidcauth/provider_test.go`
- Modify: `orchestrator/go.mod`, `orchestrator/go.sum` (via `go get`)

**Interfaces:**
- Produces: `oidcauth.NewProvider(ctx, issuerURL, clientID, clientSecret, redirectURL string) (*Provider, error)`, `oidcauth.GeneratePKCE() (verifier, challenge string, err error)`, `(*Provider).AuthCodeURL(state, codeChallenge string) string`, `(*Provider).Exchange(ctx, code, codeVerifier string) (email string, err error)`. Consumed by Task 4 (`TestSSOConfig`) and Task 5 (login flow).

- [ ] **Step 1: Add the new dependencies**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go get github.com/coreos/go-oidc/v3@latest golang.org/x/oauth2@latest`
Expected: `go.mod`/`go.sum` updated with `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` (plus their transitive deps).

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./...`
Expected: clean build (no source uses the new packages yet, so this just confirms the module resolves).

- [ ] **Step 2: Write the failing test — fake OIDC provider + discovery/exchange round-trip**

Create `orchestrator/internal/oidcauth/provider_test.go`:

```go
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeOIDCProvider spins up a minimal local OIDC discovery + JWKS + token
// endpoint set, so Provider can be tested without a real IdP. Signs ID
// tokens with a locally generated RSA key, served via a hand-built JWKS
// document — the same shape go-oidc's verifier expects from a real IdP.
type fakeOIDCProvider struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	email    string
	clientID string
}

func newFakeOIDCProvider(t *testing.T, clientID, email string) *fakeOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := &fakeOIDCProvider{key: key, email: email, clientID: clientID}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks", f.jwks)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeOIDCProvider) discovery(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                 f.server.URL,
		"authorization_endpoint":                 f.server.URL + "/authorize",
		"token_endpoint":                         f.server.URL + "/token",
		"jwks_uri":                               f.server.URL + "/jwks",
		"id_token_signing_alg_values_supported":  []string{"RS256"},
	})
}

func (f *fakeOIDCProvider) jwks(w http.ResponseWriter, r *http.Request) {
	pub := f.key.PublicKey
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"kid": "test-key",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

func (f *fakeOIDCProvider) token(w http.ResponseWriter, r *http.Request) {
	claims := jwt.MapClaims{
		"iss":   f.server.URL,
		"sub":   "test-subject",
		"aud":   f.clientID,
		"email": f.email,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	signed, err := tok.SignedString(f.key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "test-access-token",
		"id_token":     signed,
		"token_type":   "Bearer",
	})
}

func TestNewProvider_DiscoveryAndExchange(t *testing.T) {
	fake := newFakeOIDCProvider(t, "test-client", "user@example.com")
	ctx := context.Background()
	p, err := NewProvider(ctx, fake.server.URL, "test-client", "test-secret", "http://localhost/callback")
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	email, err := p.Exchange(ctx, "any-code", "any-verifier")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if email != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", email)
	}
}

func TestNewProvider_DiscoveryFailsOnBadIssuer(t *testing.T) {
	ctx := context.Background()
	if _, err := NewProvider(ctx, "http://127.0.0.1:1/not-a-real-idp", "c", "s", "http://localhost/callback"); err == nil {
		t.Fatal("expected an error discovering against an unreachable issuer, got nil")
	}
}

func TestGeneratePKCE_VerifierAndChallengeAreLinkedAndUnique(t *testing.T) {
	v1, c1, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	v2, c2, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE: %v", err)
	}
	if v1 == "" || c1 == "" {
		t.Fatal("verifier and challenge must not be empty")
	}
	if v1 == v2 || c1 == c2 {
		t.Fatal("two calls to GeneratePKCE must not produce the same verifier/challenge")
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/oidcauth/... -v`
Expected: FAIL to build — `undefined: NewProvider`, `undefined: GeneratePKCE` (the package has no implementation yet).

- [ ] **Step 4: Implement the OIDC provider wrapper**

Create `orchestrator/internal/oidcauth/provider.go`:

```go
// Package oidcauth wraps OIDC discovery and the Authorization Code + PKCE
// flow for Phase 7's SSO slice. One Provider is built per login attempt
// (or per admin "test config" call) from a tenant's sso_configs row — see
// docs/superpowers/specs/2026-07-19-phase7-sso-oidc-design.md.
package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Provider wraps OIDC discovery and the OAuth2 config for one tenant's IdP.
type Provider struct {
	oauth2Config oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

// NewProvider performs OIDC discovery against issuerURL and builds a
// Provider configured for the Authorization Code flow with the given client
// credentials and redirect URL.
func NewProvider(ctx context.Context, issuerURL, clientID, clientSecret, redirectURL string) (*Provider, error) {
	p, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &Provider{
		oauth2Config: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
	}, nil
}

// GeneratePKCE returns a fresh code_verifier and its derived S256
// code_challenge for one login attempt.
func GeneratePKCE() (verifier, challenge string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}

// AuthCodeURL builds the redirect URL to the IdP's authorization endpoint.
func (p *Provider) AuthCodeURL(state, codeChallenge string) string {
	return p.oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange completes the Authorization Code flow: exchanges code (with the
// PKCE verifier) for tokens, verifies the ID token, and returns its email
// claim.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier string) (email string, err error) {
	tok, err := p.oauth2Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return "", fmt.Errorf("no id_token in token response")
	}
	idTok, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("id_token verification: %w", err)
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := idTok.Claims(&claims); err != nil {
		return "", fmt.Errorf("decode id_token claims: %w", err)
	}
	if claims.Email == "" {
		return "", fmt.Errorf("id_token has no email claim")
	}
	return claims.Email, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/oidcauth/... -v`
Expected: all 4 PASS.

- [ ] **Step 6: Build the whole repo and commit**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go vet ./...`
Expected: clean.

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add go.mod go.sum internal/oidcauth/
git commit -m "feat(sso): add internal/oidcauth — OIDC discovery + PKCE Authorization Code exchange

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 4: `internal/api` — SSO config CRUD

**Files:**
- Create: `orchestrator/internal/api/sso_handlers.go`
- Create: `orchestrator/internal/api/sso_config_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `auth.CanViewSSOConfig`/`auth.CanManageSSOConfig` (Task 2), `oidcauth.NewProvider` (Task 3).
- Produces: `h.GetSSOConfig`, `h.CreateSSOConfig`, `h.UpdateSSOConfig`, `h.DeleteSSOConfig`, `h.TestSSOConfig`, `h.effectiveSSOTenantID(r) (string, bool)` (also consumed by Task 5's login-flow handlers, which need the same tenant-resolution logic in one direction — see Task 5's `InitiateSSOLogin`/`SSOCallback`, which resolve tenant from the URL slug instead and don't call this helper, but share its underlying pattern).

- [ ] **Step 1: Ground the exact insertion point in `routes.go`**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n 'CanReviewThreatIntel)).Post("/api/relationships/{id}/status"' internal/api/routes.go`
Expected: one match — the new SSO CRUD routes go immediately after this line.

- [ ] **Step 2: Write the failing CRUD tests**

Create `orchestrator/internal/api/sso_config_test.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func ssoHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
}

func tenantAdminToken(t *testing.T, tenantID string) string {
	t.Helper()
	tok, err := auth.GenerateTenantToken("ta-1", auth.RoleAdmin, &tenantID, false, testJWTSecret, time.Hour)
	if err != nil {
		t.Fatalf("GenerateTenantToken: %v", err)
	}
	return tok
}

func TestCreateSSOConfig_ThenGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")

		body := `{"issuerUrl":"https://idp.example.com","clientId":"c1","clientSecret":"s1","defaultRole":"analyst","enabled":true}`
		req := httptest.NewRequest(http.MethodPost, "/api/sso/config", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("CreateSSOConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}

		req = httptest.NewRequest(http.MethodGet, "/api/sso/config", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.GetSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GetSSOConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var got SSOConfig
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.IssuerURL != "https://idp.example.com" || got.DefaultRole != "analyst" || !got.Enabled {
			t.Errorf("got %+v", got)
		}
	})
}

func TestCreateSSOConfig_DuplicateForSameTenantConflicts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		body := `{"issuerUrl":"https://idp.example.com","clientId":"c1","clientSecret":"s1"}`

		req := httptest.NewRequest(http.MethodPost, "/api/sso/config", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.CreateSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("first create status = %d", rec.Code)
		}

		req = httptest.NewRequest(http.MethodPost, "/api/sso/config", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.CreateSSOConfig(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("duplicate create status = %d, want 409", rec.Code)
		}
	})
}

func TestUpdateSSOConfig_MaskedSecretPreservesExisting(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret) VALUES ('default','https://idp.example.com','c1','real-secret') RETURNING id`,
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}

		body := `{"issuerUrl":"https://idp2.example.com","clientId":"c1","clientSecret":"***","defaultRole":"viewer","enabled":true}`
		req := httptest.NewRequest(http.MethodPut, "/api/sso/config/"+id, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.UpdateSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("UpdateSSOConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var secret string
		if err := pool.QueryRow(t.Context(), `SELECT client_secret FROM sso_configs WHERE id=$1`, id).Scan(&secret); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if secret != "real-secret" {
			t.Errorf("client_secret = %q, want unchanged real-secret", secret)
		}
	})
}

func TestDeleteSSOConfig_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		tok := tenantAdminToken(t, "default")
		var id string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret) VALUES ('default','https://idp.example.com','c1','s1') RETURNING id`,
		).Scan(&id); err != nil {
			t.Fatalf("seed: %v", err)
		}
		req := httptest.NewRequest(http.MethodDelete, "/api/sso/config/"+id, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req = withURLParam(req, "id", id)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.DeleteSSOConfig(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("DeleteSSOConfig status = %d, body=%s", rec.Code, rec.Body.String())
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM sso_configs WHERE id=$1`, id).Scan(&n)
		if n != 0 {
			t.Errorf("row still present after delete")
		}
	})
}

func TestSSOConfig_CrossTenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		var otherTenantID string
		if err := pool.QueryRow(t.Context(), `INSERT INTO tenants (name, slug) VALUES ('Other', 'other') RETURNING id`).Scan(&otherTenantID); err != nil {
			t.Fatalf("seed other tenant: %v", err)
		}
		var otherConfigID string
		if err := pool.QueryRow(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret) VALUES ($1,'https://other-idp.example.com','c1','s1') RETURNING id`,
			otherTenantID,
		).Scan(&otherConfigID); err != nil {
			t.Fatalf("seed other config: %v", err)
		}

		defaultTok := tenantAdminToken(t, "default")

		// GET returns 404 for a tenant with no config of its own — it must
		// never see the other tenant's row.
		req := httptest.NewRequest(http.MethodGet, "/api/sso/config", nil)
		req.Header.Set("Authorization", "Bearer "+defaultTok)
		req = withClaims(t, req, testJWTSecret)
		rec := httptest.NewRecorder()
		h.GetSSOConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GetSSOConfig cross-tenant status = %d, want 404", rec.Code)
		}

		// DELETE by the other tenant's config ID must not succeed from the
		// "default" tenant's admin token.
		req = httptest.NewRequest(http.MethodDelete, "/api/sso/config/"+otherConfigID, nil)
		req.Header.Set("Authorization", "Bearer "+defaultTok)
		req = withURLParam(req, "id", otherConfigID)
		req = withClaims(t, req, testJWTSecret)
		rec = httptest.NewRecorder()
		h.DeleteSSOConfig(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("DeleteSSOConfig cross-tenant status = %d, want 404", rec.Code)
		}
		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM sso_configs WHERE id=$1`, otherConfigID).Scan(&n)
		if n != 1 {
			t.Errorf("other tenant's config was deleted cross-tenant — isolation failed")
		}
	})
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... -run TestSSOConfig -v`
Expected: FAIL to build — `undefined: SSOConfig`, `h.CreateSSOConfig undefined`, etc.

- [ ] **Step 4: Implement the SSO config CRUD handlers**

Create `orchestrator/internal/api/sso_handlers.go`:

```go
package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/oidcauth"
)

// SSOConfig is one row from sso_configs, with client_secret masked — it is
// never returned in cleartext once saved.
type SSOConfig struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenantId"`
	IssuerURL   string `json:"issuerUrl"`
	ClientID    string `json:"clientId"`
	DefaultRole string `json:"defaultRole"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"createdAt"`
}

var validSSORoles = map[string]bool{"viewer": true, "analyst": true, "admin": true}

// effectiveSSOTenantID resolves which tenant's SSO config the caller may
// act on: a tenant user always acts on their own tenant; a platform-admin
// (who belongs to no tenant) must specify one explicitly via ?tenantId=.
func (h *Handler) effectiveSSOTenantID(r *http.Request) (string, bool) {
	claims, ok := auth.ClaimsFrom(r.Context())
	if !ok {
		return "", false
	}
	if claims.IsPlatformAdmin {
		tid := r.URL.Query().Get("tenantId")
		return tid, tid != ""
	}
	if claims.TenantID == nil {
		return "", false
	}
	return *claims.TenantID, true
}

// GetSSOConfig returns the caller's tenant's SSO config (secret masked).
// GET /api/sso/config
func (h *Handler) GetSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveSSOTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	var cfg SSOConfig
	err := h.db.QueryRow(r.Context(),
		`SELECT id, tenant_id, issuer_url, client_id, default_role, enabled,
		        to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		   FROM sso_configs WHERE tenant_id = $1`, tenantID,
	).Scan(&cfg.ID, &cfg.TenantID, &cfg.IssuerURL, &cfg.ClientID, &cfg.DefaultRole, &cfg.Enabled, &cfg.CreatedAt)
	if err != nil {
		jsonError(w, "no SSO config for this tenant", http.StatusNotFound)
		return
	}
	respond(w, cfg)
}

// CreateSSOConfig creates the caller's tenant's SSO config.
// POST /api/sso/config
func (h *Handler) CreateSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveSSOTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	var req struct {
		IssuerURL    string `json:"issuerUrl"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		DefaultRole  string `json:"defaultRole"`
		Enabled      bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IssuerURL == "" || req.ClientID == "" || req.ClientSecret == "" {
		jsonError(w, "issuerUrl, clientId and clientSecret are required", http.StatusBadRequest)
		return
	}
	if req.DefaultRole == "" {
		req.DefaultRole = "viewer"
	}
	if !validSSORoles[req.DefaultRole] {
		jsonError(w, "defaultRole must be viewer, analyst, or admin", http.StatusBadRequest)
		return
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret, default_role, enabled)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		tenantID, req.IssuerURL, req.ClientID, req.ClientSecret, req.DefaultRole, req.Enabled,
	).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique") {
			jsonError(w, "this tenant already has an SSO config", http.StatusConflict)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "sso.config_created", id, map[string]any{"tenantId": tenantID, "issuerUrl": req.IssuerURL}, "ok")
	respond(w, map[string]any{"id": id})
}

// UpdateSSOConfig updates the caller's tenant's SSO config. A "***"
// clientSecret preserves the existing value.
// PUT /api/sso/config/{id}
func (h *Handler) UpdateSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveSSOTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		IssuerURL    string `json:"issuerUrl"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
		DefaultRole  string `json:"defaultRole"`
		Enabled      bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid body", http.StatusBadRequest)
		return
	}
	if req.ClientSecret == "***" {
		var existing string
		h.db.QueryRow(r.Context(), `SELECT client_secret FROM sso_configs WHERE id=$1 AND tenant_id=$2`, id, tenantID).Scan(&existing)
		req.ClientSecret = existing
	}
	if req.DefaultRole != "" && !validSSORoles[req.DefaultRole] {
		jsonError(w, "defaultRole must be viewer, analyst, or admin", http.StatusBadRequest)
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE sso_configs SET issuer_url=$1, client_id=$2, client_secret=$3, default_role=$4, enabled=$5, updated_at=NOW()
		  WHERE id=$6 AND tenant_id=$7`,
		req.IssuerURL, req.ClientID, req.ClientSecret, req.DefaultRole, req.Enabled, id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SSO config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "sso.config_updated", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// DeleteSSOConfig deletes the caller's tenant's SSO config. Existing
// SSO-provisioned users are unaffected — their auth_source='sso' blocks
// password login regardless of whether a config still exists; deleting the
// config just stops new SSO logins.
// DELETE /api/sso/config/{id}
func (h *Handler) DeleteSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveSSOTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	ct, err := h.db.Exec(r.Context(), `DELETE FROM sso_configs WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "SSO config not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "sso.config_deleted", id, nil, "ok")
	respond(w, map[string]any{"status": "ok"})
}

// TestSSOConfig round-trips OIDC discovery against the configured issuer,
// without performing a full login.
// POST /api/sso/config/{id}/test
func (h *Handler) TestSSOConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.effectiveSSOTenantID(r)
	if !ok {
		jsonError(w, "no tenant context", http.StatusForbidden)
		return
	}
	id := chi.URLParam(r, "id")
	var issuerURL, clientID, clientSecret string
	err := h.db.QueryRow(r.Context(),
		`SELECT issuer_url, client_id, client_secret FROM sso_configs WHERE id=$1 AND tenant_id=$2`, id, tenantID,
	).Scan(&issuerURL, &clientID, &clientSecret)
	if err != nil {
		jsonError(w, "SSO config not found", http.StatusNotFound)
		return
	}
	if _, err := oidcauth.NewProvider(r.Context(), issuerURL, clientID, clientSecret, ""); err != nil {
		respond(w, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	respond(w, map[string]any{"ok": true})
}

// randomSSOPlaceholder returns a cryptographically random string, used as
// the throwaway password_hash input for a JIT-provisioned SSO user (never
// actually used for verification — auth_source='sso' blocks password login
// outright, this is belt-and-suspenders for the NOT NULL column).
func randomSSOPlaceholder() string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}
```

- [ ] **Step 5: Wire the CRUD routes**

In `orchestrator/internal/api/routes.go`, immediately after the line found in Step 1 (`r.With(auth.RequirePermission(auth.CanReviewThreatIntel)).Post("/api/relationships/{id}/status", h.SetRelationshipStatus)`), add:

```go

		// SSO (OIDC) config — tenant-scoped CRUD. See
		// docs/superpowers/specs/2026-07-19-phase7-sso-oidc-design.md.
		r.With(auth.RequirePermission(auth.CanViewSSOConfig)).Get("/api/sso/config", h.GetSSOConfig)
		r.With(auth.RequirePermission(auth.CanManageSSOConfig)).Post("/api/sso/config", h.CreateSSOConfig)
		r.With(auth.RequirePermission(auth.CanManageSSOConfig)).Put("/api/sso/config/{id}", h.UpdateSSOConfig)
		r.With(auth.RequirePermission(auth.CanManageSSOConfig)).Delete("/api/sso/config/{id}", h.DeleteSSOConfig)
		r.With(auth.RequirePermission(auth.CanManageSSOConfig)).Post("/api/sso/config/{id}/test", h.TestSSOConfig)
```

- [ ] **Step 6: Add the 5 new routes to the RBAC drift matrix**

In `orchestrator/internal/api/rbac_matrix_test.go`, in the `// ── fine-grained permission gates ──` section of `routeMatrix` (immediately after the existing `{http.MethodPost, "/api/relationships/{id}/status", tierPermission, auth.CanReviewThreatIntel},` line), add:

```go
	{http.MethodGet, "/api/sso/config", tierPermission, auth.CanViewSSOConfig},
	{http.MethodPost, "/api/sso/config", tierPermission, auth.CanManageSSOConfig},
	{http.MethodPut, "/api/sso/config/{id}", tierPermission, auth.CanManageSSOConfig},
	{http.MethodDelete, "/api/sso/config/{id}", tierPermission, auth.CanManageSSOConfig},
	{http.MethodPost, "/api/sso/config/{id}/test", tierPermission, auth.CanManageSSOConfig},
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/api/... -run TestSSOConfig -v`
Expected: all 5 PASS.

**Note:** `TestRBACMatrix_AuthorizationBoundary` will fail for the 5 new routes at this point (nil-tenant matrix tokens can't clear `effectiveSSOTenantID`'s gate) — this is expected and fixed in Task 6, not here. Do not attempt to fix it in this task.

- [ ] **Step 8: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/sso_handlers.go internal/api/sso_config_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(sso): add tenant-scoped SSO config CRUD API

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 5: `internal/api` — login flow (initiate + callback)

**Files:**
- Create: `orchestrator/internal/api/sso_login_handlers.go`
- Create: `orchestrator/internal/api/sso_login_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `auth.GenerateSSOState`/`auth.ValidateSSOState` (Task 2), `oidcauth.NewProvider`/`oidcauth.GeneratePKCE` (Task 3), `randomSSOPlaceholder` (Task 4).
- Produces: `h.InitiateSSOLogin`, `h.SSOCallback`.

- [ ] **Step 1: Write the failing login-flow tests**

Create `orchestrator/internal/api/sso_login_test.go`:

```go
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
)

func TestInitiateSSOLogin_UnknownTenantSlug404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		req := httptest.NewRequest(http.MethodGet, "/login/no-such-tenant/sso", nil)
		req = withURLParam(req, "tenantSlug", "no-such-tenant")
		rec := httptest.NewRecorder()
		h.InitiateSSOLogin(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
	})
}

func TestInitiateSSOLogin_DisabledConfig404(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret, enabled) VALUES ('default','https://idp.example.com','c1','s1', false)`,
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/login/default/sso", nil)
		req = withURLParam(req, "tenantSlug", "default")
		rec := httptest.NewRecorder()
		h.InitiateSSOLogin(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (config disabled)", rec.Code)
		}
	})
}

func TestSSOCallback_JITProvisionsNewUserWithTenantDefaultRole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		fake := newFakeOIDCProvider(t, "c1", "newhire@example.com")
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret, default_role, enabled) VALUES ('default',$1,'c1','s1','analyst',true)`,
			fake.server.URL,
		); err != nil {
			t.Fatalf("seed: %v", err)
		}
		h := ssoHandler(t, pool)

		verifier := "test-verifier"
		state, err := auth.GenerateSSOState("default", verifier, testJWTSecret, 10*time.Minute)
		if err != nil {
			t.Fatalf("GenerateSSOState: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/callback?state="+state+"&code=any-code", nil)
		rec := httptest.NewRecorder()
		h.SSOCallback(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("SSOCallback status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var role, authSource string
		var tenantID *string
		err = pool.QueryRow(t.Context(), `SELECT role, auth_source, tenant_id FROM users WHERE username = 'newhire@example.com'`).
			Scan(&role, &authSource, &tenantID)
		if err != nil {
			t.Fatalf("JIT-provisioned user not found: %v", err)
		}
		if role != "analyst" || authSource != "sso" || tenantID == nil || *tenantID != "default" {
			t.Errorf("role=%q authSource=%q tenantID=%v, want analyst/sso/default", role, authSource, tenantID)
		}

		var cookieSet bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == "bas_token" && c.Value != "" {
				cookieSet = true
			}
		}
		if !cookieSet {
			t.Error("bas_token cookie was not set on successful SSO login")
		}
	})
}

func TestSSOCallback_LinksExistingUserByEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		fake := newFakeOIDCProvider(t, "c1", "existing@example.com")
		if _, err := pool.Exec(t.Context(),
			`INSERT INTO sso_configs (tenant_id, issuer_url, client_id, client_secret, default_role, enabled) VALUES ('default',$1,'c1','s1','viewer',true)`,
			fake.server.URL,
		); err != nil {
			t.Fatalf("seed config: %v", err)
		}
		existingID := seedUser(t, pool, "existing@example.com", "some-local-password", "admin", true)
		h := ssoHandler(t, pool)

		verifier := "test-verifier"
		state, err := auth.GenerateSSOState("default", verifier, testJWTSecret, 10*time.Minute)
		if err != nil {
			t.Fatalf("GenerateSSOState: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/callback?state="+state+"&code=any-code", nil)
		rec := httptest.NewRecorder()
		h.SSOCallback(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("SSOCallback status = %d, body=%s", rec.Code, rec.Body.String())
		}

		var n int
		pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM users WHERE username = 'existing@example.com'`).Scan(&n)
		if n != 1 {
			t.Fatalf("expected exactly 1 user row (linked, not duplicated), got %d", n)
		}
		var role string
		pool.QueryRow(t.Context(), `SELECT role FROM users WHERE id = $1`, existingID).Scan(&role)
		if role != "admin" {
			t.Errorf("linked user's role changed to %q, want unchanged admin", role)
		}
	})
}

func TestSSOCallback_WrongOrExpiredStateRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ssoHandler(t, pool)
		expired, err := auth.GenerateSSOState("default", "v", testJWTSecret, -time.Minute)
		if err != nil {
			t.Fatalf("GenerateSSOState: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/auth/sso/callback?state="+expired+"&code=any-code", nil)
		rec := httptest.NewRecorder()
		h.SSOCallback(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expired-state status = %d, want 400", rec.Code)
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... -run 'TestInitiateSSOLogin|TestSSOCallback' -v`
Expected: FAIL to build — `h.InitiateSSOLogin undefined`, `h.SSOCallback undefined`.

- [ ] **Step 3: Implement the login-flow handlers**

Create `orchestrator/internal/api/sso_login_handlers.go`:

```go
package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/oidcauth"
)

// ssoRedirectURL derives this server's externally-reachable callback URL
// from the incoming request — no separate config surface needed. Honors
// X-Forwarded-Proto for deployments behind a reverse proxy.
func ssoRedirectURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/auth/sso/callback"
}

// InitiateSSOLogin redirects the browser to the tenant's IdP to start an
// OIDC Authorization Code + PKCE flow.
// GET /login/{tenantSlug}/sso
func (h *Handler) InitiateSSOLogin(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "tenantSlug")
	var tenantID, issuerURL, clientID, clientSecret string
	var enabled bool
	err := h.db.QueryRow(r.Context(),
		`SELECT t.id, c.issuer_url, c.client_id, c.client_secret, c.enabled
		   FROM tenants t JOIN sso_configs c ON c.tenant_id = t.id
		  WHERE t.slug = $1`, slug,
	).Scan(&tenantID, &issuerURL, &clientID, &clientSecret, &enabled)
	if err != nil || !enabled {
		jsonError(w, "SSO is not configured for this organization", http.StatusNotFound)
		return
	}
	provider, err := oidcauth.NewProvider(r.Context(), issuerURL, clientID, clientSecret, ssoRedirectURL(r))
	if err != nil {
		jsonError(w, "SSO provider unavailable", http.StatusServiceUnavailable)
		return
	}
	verifier, challenge, err := oidcauth.GeneratePKCE()
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	state, err := auth.GenerateSSOState(tenantID, verifier, h.secret, 10*time.Minute)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, provider.AuthCodeURL(state, challenge), http.StatusFound)
}

// SSOCallback completes the OIDC Authorization Code flow: validates state,
// exchanges the code, resolves or JIT-provisions the user, and mints the
// same tenant-aware JWT Login does.
// GET /api/auth/sso/callback
func (h *Handler) SSOCallback(w http.ResponseWriter, r *http.Request) {
	stateTok := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if stateTok == "" || code == "" {
		jsonError(w, "missing state or code", http.StatusBadRequest)
		return
	}
	state, err := auth.ValidateSSOState(stateTok, h.secret)
	if err != nil {
		jsonError(w, "invalid or expired login attempt", http.StatusBadRequest)
		return
	}

	var issuerURL, clientID, clientSecret, defaultRole string
	var enabled bool
	err = h.db.QueryRow(r.Context(),
		`SELECT issuer_url, client_id, client_secret, default_role, enabled
		   FROM sso_configs WHERE tenant_id = $1`, state.TenantID,
	).Scan(&issuerURL, &clientID, &clientSecret, &defaultRole, &enabled)
	if err != nil || !enabled {
		jsonError(w, "SSO is not configured for this organization", http.StatusNotFound)
		return
	}

	provider, err := oidcauth.NewProvider(r.Context(), issuerURL, clientID, clientSecret, ssoRedirectURL(r))
	if err != nil {
		jsonError(w, "SSO provider unavailable", http.StatusServiceUnavailable)
		return
	}
	email, err := provider.Exchange(r.Context(), code, state.CodeVerifier)
	if err != nil {
		h.auditLogAs(r, "", "user.sso_login", "", map[string]any{"tenantId": state.TenantID, "reason": "token exchange failed"}, "fail")
		jsonError(w, "SSO login failed", http.StatusUnauthorized)
		return
	}

	var userID, role string
	var isActive bool
	err = h.db.QueryRow(r.Context(),
		`SELECT id, role, is_active FROM users WHERE username = $1 AND tenant_id = $2`,
		email, state.TenantID,
	).Scan(&userID, &role, &isActive)
	if err != nil {
		placeholder, hErr := auth.HashPassword(randomSSOPlaceholder())
		if hErr != nil {
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		role = defaultRole
		isActive = true
		insErr := h.db.QueryRow(r.Context(),
			`INSERT INTO users (username, password_hash, role, tenant_id, auth_source)
			 VALUES ($1,$2,$3,$4,'sso') RETURNING id`,
			email, placeholder, role, state.TenantID,
		).Scan(&userID)
		if insErr != nil {
			jsonError(w, insErr.Error(), http.StatusInternalServerError)
			return
		}
		h.auditLogAs(r, userID, "user.sso_provisioned", userID, map[string]any{"username": email, "tenantId": state.TenantID, "role": role}, "ok")
	}
	if !isActive {
		h.auditLogAs(r, userID, "user.login", userID, map[string]any{"username": email, "reason": "account disabled"}, "fail")
		jsonError(w, "account is disabled — contact your administrator", http.StatusForbidden)
		return
	}

	tenantID := state.TenantID
	token, err := auth.GenerateTenantToken(userID, auth.Role(role), &tenantID, false, h.secret, 24*time.Hour)
	if err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	_, _ = h.db.Exec(r.Context(), `UPDATE users SET last_login = NOW() WHERE id = $1`, userID)

	http.SetCookie(w, &http.Cookie{
		Name:     "bas_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookies(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400,
	})
	h.auditLogAs(r, userID, "user.sso_login", userID, map[string]any{"username": email}, "ok")
	http.Redirect(w, r, "/", http.StatusFound)
}
```

- [ ] **Step 4: Wire the public login-flow routes**

In `orchestrator/internal/api/routes.go`, immediately after `r.Post("/api/auth/setup", h.Setup) // first-run admin provisioning (installer)`, add:

```go
	r.Get("/login/{tenantSlug}/sso", h.InitiateSSOLogin)
	r.Get("/api/auth/sso/callback", h.SSOCallback)
```

- [ ] **Step 5: Add the 2 new public routes to the drift-guard's exclusion list**

In `orchestrator/internal/api/rbac_matrix_test.go`, in the `publicRoutes` map, immediately after `"POST /api/auth/setup": true,`, add:

```go
	"GET /login/{tenantSlug}/sso":   true,
	"GET /api/auth/sso/callback":    true,
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go test ./internal/api/... -run 'TestInitiateSSOLogin|TestSSOCallback' -v`
Expected: all 5 PASS.

- [ ] **Step 7: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/sso_login_handlers.go internal/api/sso_login_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(sso): add SSO login flow — initiate + callback, JIT provisioning

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 6: Fix the RBAC boundary test's token fixture, verify no drift

**Files:**
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:** none new — this task only changes test fixtures.

**Why this task exists (grounding correction, not part of the original spec):** `TestRBACMatrix_AuthorizationBoundary` mints every non-anonymous identity's token via `auth.GenerateToken` (legacy, nil `TenantID`). This was invisible for all 90 routes migrated so far because none of them do anything with tenant context beyond the generic `RequirePermission` role check (Multi-Tenancy's own documented gap: no production handler filters by tenant). Task 4's `effectiveSSOTenantID` is the **first** helper that genuinely requires a non-nil `TenantID` to succeed — with the current fixture, a nil-tenant "admin" token correctly gets 403 "no tenant context" from the SSO handlers, which the boundary test misreads as an authz-gate failure. Verified safe to fix broadly: every other `tierPermission` route either ignores tenant entirely (the documented gap) or is itself blocked earlier by request-body decoding on a nil test body (e.g. `CreateUser`), so switching the fixture to a real tenant changes no other route's expected outcome.

- [ ] **Step 1: Ground the current token-minting line**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && grep -n 'tok, err := auth.GenerateToken("matrix-"+id.name' internal/api/rbac_matrix_test.go`
Expected: one match, inside `TestRBACMatrix_AuthorizationBoundary`.

- [ ] **Step 2: Switch to a tenant-aware token**

Using Edit, replace:

```go
					tok, err := auth.GenerateToken("matrix-"+id.name, id.role, testJWTSecret, time.Hour)
```

with:

```go
					tenantID := "default"
					tok, err := auth.GenerateTenantToken("matrix-"+id.name, id.role, &tenantID, false, testJWTSecret, time.Hour)
```

- [ ] **Step 3: Run the full RBAC matrix suite**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./internal/api/... -run 'TestRBACMatrix|TestPlatformAdminRoutes_Gating' -v`
Expected: `TestRBACMatrix_AuthorizationBoundary`, `TestRBACMatrix_NoDrift`, `TestRBACMatrix_MethodConfusion`, `TestPlatformAdminRoutes_Gating` all PASS — including the 5 new SSO-config routes and the 2 new public SSO routes from Tasks 4-5.

- [ ] **Step 4: Commit**

```bash
cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator
git add internal/api/rbac_matrix_test.go
git commit -m "fix(rbac): mint tenant-aware tokens in the RBAC boundary test fixture

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push
```

---

### Task 7: Full regression + capture

**Files:** none (verification + vault/memory).

- [ ] **Step 1: Full repo test suite**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go test ./...`
Expected: PASS across every package.

- [ ] **Step 2: Whole-build + vet + gofmt**

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && go build ./... && go vet ./...`
Expected: clean.

Run: `cd /c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator && gofmt -l internal/db/postgres.go internal/api/detectverify_handlers.go internal/auth/sso_state.go internal/auth/sso_state_test.go internal/auth/permissions.go internal/auth/permissions_test.go internal/oidcauth/ internal/api/sso_handlers.go internal/api/sso_config_test.go internal/api/sso_login_handlers.go internal/api/sso_login_test.go internal/api/routes.go internal/api/rbac_matrix_test.go`
Expected: no output. If anything is listed, `gofmt -w` it and commit as a dedicated `style:` commit.

- [ ] **Step 3: Update the vault (outside the git repo)**

The vault at `C:\Users\Administrator\Audspect-Vault` is NOT in the repo — update it directly, do not `git add` it.
- Create `04 Features/SSO (OIDC).md` (feature note: architecture, JIT provisioning, tenant-slug discovery, the tenant-isolation decision, the `detection_connectors` side-fix, the RBAC boundary-test grounding correction).
- Edit `11 Roadmaps/Roadmap.md`: mark Identity & Access's SSO piece done; SCIM remains the only unstarted piece of that sub-project.
- Append to the current daily note: this session's work, the side-fix discovery, and the RBAC boundary-test correction.

- [ ] **Step 4: Update Claude memory**

Edit `C:\Users\Administrator\.claude\projects\C--Users-Administrator-Downloads-Audspect-Cloud\memory\project_platform_roadmap_2026h2.md`: mark Identity & Access's SSO piece done under the Phase 7 section; note SCIM as the last remaining piece. Update the `MEMORY.md` index line.

- [ ] **Step 5: Report completion**

Announce the feature is done, list the commits, and state plainly: this closes the SSO piece of Identity & Access. SCIM provisioning — the third and last piece — is still fully unstarted and needs its own brainstorm cycle. Note explicitly that no IdP-group-to-role claim mapping exists (flat per-tenant default role only) and no SLO/IdP-initiated-login support exists — both explicit non-goals from the spec, not gaps to be silently discovered later.

---

## Self-Review

**Spec coverage:**
- OIDC only, `internal/oidcauth` wrapping `go-oidc`/`x/oauth2` → Task 3. ✓
- Per-tenant config, `sso_configs` table, `UNIQUE(tenant_id)`, masked secret → Tasks 1, 4. ✓
- JIT provisioning, per-tenant configurable default role, linking-by-email → Task 5. ✓
- Tenant-slug URL discovery (`/login/{tenantSlug}/sso`) → Task 5. ✓
- Real tenant-scoped query enforcement on `sso_configs` → Task 4 (`effectiveSSOTenantID`, every query filtered), proven by `TestSSOConfig_CrossTenantIsolation`. ✓
- `detection_connectors` side-fix → Task 1. ✓
- 2 new permissions, RBAC-matrix coverage → Tasks 2, 4, 5. ✓
- Testing strategy (fake OIDC provider, Docker-backed handler tests, RBAC-matrix drift) → Tasks 3, 4, 5, 6. ✓
- Out-of-scope items (SAML, claim mapping, SLO, IdP-initiated login, email-domain discovery, multi-IdP-per-tenant, SCIM) → none touched by any task, restated in Task 7 Step 5's completion report. ✓

**Grounding corrections made while writing this plan (same discipline as every prior slice this session):**
1. The spec's Login Flow section said the signed `state` value encodes a "codeVerifierHash" — corrected to the raw `code_verifier` itself (Task 2). PKCE's token-exchange step must present the verifier in cleartext to the IdP; only the *derived* `code_challenge` (a hash) is sent in the initial authorization request. A hash alone in `state` would make the verifier unrecoverable at callback time. Carrying the raw verifier inside the signed (HMAC) state token is safe — state's threat model is tamper-evidence via the browser round-trip, not confidentiality from the browser completing its own login.
2. The spec's Testing section said tests would use "`go-oidc`'s local fake-provider test helper" — no such helper is confirmed to exist in the library's public API. Task 3 instead builds a hand-rolled `httptest.Server` serving discovery + JWKS + token endpoints with a locally generated RSA key, which is verifiably correct and doesn't depend on an unverified library feature.
3. Discovered mid-plan (not part of the spec): `TestRBACMatrix_AuthorizationBoundary`'s shared token fixture (`auth.GenerateToken`, nil tenant) can't clear the new SSO handlers' tenant-context gate. Traced to a latent gap that every prior `tierPermission` route happened not to expose (Task 6), fixed by switching the fixture to a real tenant — verified safe against all 90 pre-existing routes' expected behavior before applying.

**Placeholder scan:** no TBD/TODO; every code step shows complete code; every command has an expected result.

**Type consistency:** `oidcauth.Provider`/`NewProvider`/`GeneratePKCE`/`AuthCodeURL`/`Exchange` signatures (Task 3) are used identically in Tasks 4 (`TestSSOConfig`) and 5 (`InitiateSSOLogin`/`SSOCallback`). `auth.SSOStateClaims{TenantID, CodeVerifier}` (Task 2) fields are read identically in Task 5's `SSOCallback`. `randomSSOPlaceholder` (Task 4) is consumed by Task 5 without re-declaration — same package, no import needed. `SSOConfig` struct (Task 4) fields match its `json.Unmarshal` target in `sso_config_test.go` exactly.
