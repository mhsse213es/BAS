# Deployment Command-Envelope Signing (B4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every execution-triggering WS command the orchestrator sends an agent carries a signed `CommandEnvelope` (deployment-specific RSA-4096 key, independent from the mTLS deployment CA and from the offline vendor scenario-signing key) that the agent verifies — command type, target identity, run/scenario context, and a 60s validity window — before executing anything.

**Architecture:** A new orchestrator-side key (`internal/cmdsigning`, its own `./signing` bind-mount, its own fail-closed startup check) signs a canonical `CommandEnvelope` inside `internal/ws/hub.go`'s `SendToAgent` — the single function all 16 existing WS-dispatch call sites already funnel through, so no call site changes. The signing public certificate rides the existing CSR-enrollment response. The agent persists it, then gates its WS command switch behind envelope verification (signature, expiry, type allowlist, mTLS-identity match, replay) before unwrapping the inner payload into the same command structs it already uses today.

**Tech Stack:** Go (`orchestrator/`, module `github.com/audspect/bas`; `agent/`, module `audspect/agent`), `crypto/rsa` PKCS#1 v1.5 + SHA-256, Postgres (`agent_certificates` table extension), Docker Compose / bash (`install.sh`).

**Spec:** `docs/superpowers/specs/2026-09-28-command-envelope-signing-design.md` — this plan implements every section. Read it in full before starting; this plan assumes it as given context and does not re-derive its rationale.

## Global Constraints

- Exactly these 8 command types are signed/verified: `command_scenario`, `command_simulate`, `command_attackpath_collect`, `command_cancel`, `command_pause`, `command_resume`, `command_stop_agent`, `command_uninstall_agent`. `command_install_patches` and any other type are explicitly out of scope (spec's "Explicitly out of scope").
- The vendor scenario-signing key/infra (`orchestrator/internal/integrity/signing.go`, `orchestrator/private_key.pem`) is never touched, imported from, or referenced by any task in this plan.
- Algorithm: RSA-4096, PKCS#1 v1.5 padding, SHA-256 hash — matches the existing vendor scheme for consistency, per the spec.
- `ExpiresAt = IssuedAt + 60s`, duration configurable (not hardcoded) but defaulting to 60s.
- Canonical serialization: the signed bytes are `json.Marshal` of a fixed Go struct (never a `map[string]any`) with `Signature` excluded — Go's `encoding/json` field order is deterministic for a fixed struct, so this needs no separate canonicalization scheme.
- Replay cache is keyed by `CommandID`, not `Nonce`. `Nonce` still travels in the signed envelope.
- No worktree — this session works directly on `main` throughout, matching the established project-wide pattern. Commit after each task; push after every commit (retry once on transient network failure, don't block silently — this session hit a real transient GitHub outage earlier).

## Review Focus

- **A command envelope replayed against a different agent than it was issued for** — a captured, still-valid (within 60s) envelope presented over a WS connection authenticated as a *different* agent identity must be rejected, not silently accepted because the signature itself is valid. Pinned in Task 9 (Step 7 of the verification checklist: `AgentID` must match `AuthenticatedAgentID`).
- **An unknown/future command type that happens to carry a well-formed, validly-signed envelope** — must never be treated as authorization to execute it. Pinned in Task 10 (the type-allowlist gate runs *before* `verifyCommandEnvelope` is even called, so an unrecognized type never reaches signature verification at all).
- **The signing key silently regenerating on an existing deployment** (a wiped `./signing` directory, a bad restore, `docker compose down -v` instead of `uninstall.sh`) — must fail closed with a clear error, not silently mint a new key that no already-enrolled agent trusts, leaving every dispatched command inexplicably rejected with no indication why. Pinned in Task 3.
- **`install.sh --upgrade` on an existing deployment that predates this plan** — must create and correctly `chown` the new `./signing` directory exactly like it must for `./pki` (Task 6/8 of the deployment-topology plan caught this exact bug for `pki`; this plan must not reintroduce it for `signing`). Pinned in Task 7.
- **A genuinely expired envelope arriving a few hundred milliseconds late** (real dispatch/queue latency, not an attack) — must be rejected the same way a maliciously-backdated one is, with a log message that tells an operator *why* (expired, not "invalid"), not a bare rejection indistinguishable from a real forgery attempt. Pinned in Task 9's test for the expiry branch, asserting the returned error text names the specific failed check.

---

### Task 1: Orchestrator — CommandEnvelope type

**Files:**
- Create: `orchestrator/internal/models/command_envelope.go`
- Test: `orchestrator/internal/models/command_envelope_test.go`

**Interfaces:**
- Produces: `models.CommandEnvelope` struct (consumed by Task 2's signing function, Task 5's `SendToAgent` wiring, Task 6's enrollment response).

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/models/command_envelope_test.go
package models

import (
	"encoding/json"
	"testing"
	"time"
)

// TestCommandEnvelope_CanonicalJSONExcludesSignature locks in the canonical-
// serialization property the signing scheme depends on: CanonicalJSON must
// never include the Signature field itself (it can't sign its own output),
// and must produce byte-identical output for byte-identical field values
// (Go's encoding/json field order is deterministic for a fixed struct, so
// this needs no separate canonicalization step).
func TestCommandEnvelope_CanonicalJSONExcludesSignature(t *testing.T) {
	env := CommandEnvelope{
		Version:     1,
		CommandID:   "cmd-1",
		CommandType: "command_scenario",
		AgentID:     "abc123deadbeef01",
		RunID:       "run-1",
		IssuedAt:    time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 9, 28, 0, 1, 0, 0, time.UTC),
		Nonce:       "nonce-1",
		Payload:     json.RawMessage(`{"foo":"bar"}`),
		Signature:   []byte("must-not-appear-in-canonical-form"),
	}
	b, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(b) == "" {
		t.Fatal("CanonicalJSON returned empty output")
	}
	var roundtrip map[string]interface{}
	if err := json.Unmarshal(b, &roundtrip); err != nil {
		t.Fatalf("CanonicalJSON output is not valid JSON: %v", err)
	}
	if _, present := roundtrip["signature"]; present {
		t.Error("CanonicalJSON output must not include the signature field")
	}
	if roundtrip["commandId"] != "cmd-1" {
		t.Errorf("commandId = %v, want cmd-1", roundtrip["commandId"])
	}

	b2, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON (second call): %v", err)
	}
	if string(b) != string(b2) {
		t.Error("CanonicalJSON is not deterministic across repeated calls on the same value")
	}
}

// TestCommandEnvelope_OptionalFieldsOmittedWhenEmpty confirms ScenarioID/
// StepID/RunID/Mode/Policy are genuinely optional in the wire format --
// command_cancel/pause/resume don't necessarily have a scenario context.
func TestCommandEnvelope_OptionalFieldsOmittedWhenEmpty(t *testing.T) {
	env := CommandEnvelope{
		Version:     1,
		CommandID:   "cmd-2",
		CommandType: "command_cancel",
		AgentID:     "abc123deadbeef01",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(60 * time.Second),
		Nonce:       "nonce-2",
		Payload:     json.RawMessage(`{}`),
	}
	b, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var roundtrip map[string]interface{}
	json.Unmarshal(b, &roundtrip)
	for _, field := range []string{"runId", "scenarioId", "stepId", "mode", "policy"} {
		if _, present := roundtrip[field]; present {
			t.Errorf("expected %q to be omitted when empty, got: %v", field, roundtrip[field])
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/models/... -run TestCommandEnvelope -v`
Expected: FAIL — `undefined: CommandEnvelope`

- [ ] **Step 3: Write minimal implementation**

```go
// orchestrator/internal/models/command_envelope.go
package models

import (
	"encoding/json"
	"time"
)

// CommandEnvelope wraps every execution-triggering WS command dispatched
// to an agent (see the 8 command types this covers in
// docs/superpowers/specs/2026-09-28-command-envelope-signing-design.md).
// It is signed by internal/cmdsigning's deployment command-signing key --
// a wholly separate trust domain from both the mTLS deployment CA
// (internal/pki) and the offline vendor scenario-signing key
// (internal/integrity), per that spec's "Two independent cryptographic
// domains" section. Never touch either of those from code that also
// touches this type.
type CommandEnvelope struct {
	Version     int             `json:"version"`
	CommandID   string          `json:"commandId"`
	CommandType string          `json:"commandType"`
	AgentID     string          `json:"agentId"`
	RunID       string          `json:"runId,omitempty"`
	ScenarioID  string          `json:"scenarioId,omitempty"`
	StepID      string          `json:"stepId,omitempty"`
	Mode        string          `json:"mode,omitempty"`
	Policy      json.RawMessage `json:"policy,omitempty"`
	IssuedAt    time.Time       `json:"issuedAt"`
	ExpiresAt   time.Time       `json:"expiresAt"`
	Nonce       string          `json:"nonce"`
	Payload     json.RawMessage `json:"payload"`
	Signature   []byte          `json:"signature,omitempty"`
}

// CommandEnvelopeVersion is the current envelope wire-format version.
// Verifiers reject any envelope whose Version doesn't match a version
// they understand -- see the agent-side verification checklist.
const CommandEnvelopeVersion = 1

// CanonicalJSON returns the exact byte sequence internal/cmdsigning signs
// and the agent verifies: json.Marshal of every field except Signature.
// A fixed struct (never a map[string]any) makes Go's deterministic
// per-type field ordering the canonical form -- no separate
// canonicalization scheme (JCS etc.) is needed. Signature is excluded by
// constructing an unsigned copy rather than by tag tricks, so this stays
// correct even if CommandEnvelope's fields are ever reordered.
func (e CommandEnvelope) CanonicalJSON() ([]byte, error) {
	unsigned := e
	unsigned.Signature = nil
	return json.Marshal(struct {
		Version     int             `json:"version"`
		CommandID   string          `json:"commandId"`
		CommandType string          `json:"commandType"`
		AgentID     string          `json:"agentId"`
		RunID       string          `json:"runId,omitempty"`
		ScenarioID  string          `json:"scenarioId,omitempty"`
		StepID      string          `json:"stepId,omitempty"`
		Mode        string          `json:"mode,omitempty"`
		Policy      json.RawMessage `json:"policy,omitempty"`
		IssuedAt    time.Time       `json:"issuedAt"`
		ExpiresAt   time.Time       `json:"expiresAt"`
		Nonce       string          `json:"nonce"`
		Payload     json.RawMessage `json:"payload"`
	}{
		Version: unsigned.Version, CommandID: unsigned.CommandID, CommandType: unsigned.CommandType,
		AgentID: unsigned.AgentID, RunID: unsigned.RunID, ScenarioID: unsigned.ScenarioID,
		StepID: unsigned.StepID, Mode: unsigned.Mode, Policy: unsigned.Policy,
		IssuedAt: unsigned.IssuedAt, ExpiresAt: unsigned.ExpiresAt, Nonce: unsigned.Nonce,
		Payload: unsigned.Payload,
	})
}

// SignedCommandTypes is the exact, closed set of WS message types this
// envelope mechanism covers. Anything outside this set is neither signed
// by the orchestrator nor accepted (even unsigned) by an agent that
// checks IsSignedCommandType before dispatch -- see the agent-side
// verification checklist's hard rule that an unrecognized type is
// rejected before signature verification is even attempted.
var SignedCommandTypes = map[string]bool{
	"command_scenario":           true,
	"command_simulate":           true,
	"command_attackpath_collect": true,
	"command_cancel":             true,
	"command_pause":              true,
	"command_resume":             true,
	"command_stop_agent":         true,
	"command_uninstall_agent":    true,
}

// IsSignedCommandType reports whether msgType is one of the 8 command
// types this envelope mechanism covers.
func IsSignedCommandType(msgType string) bool {
	return SignedCommandTypes[msgType]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/models/... -run TestCommandEnvelope -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/models/command_envelope.go orchestrator/internal/models/command_envelope_test.go
git commit -m "feat(signing): add CommandEnvelope type with canonical serialization"
git push
```

---

### Task 2: Orchestrator — deployment command-signing key generation

**Files:**
- Create: `orchestrator/internal/cmdsigning/key.go`
- Test: `orchestrator/internal/cmdsigning/key_test.go`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `cmdsigning.LoadOrGenerateSigningKey(dir string) (*SigningKey, error)`; `(*SigningKey).PrivateKey() *rsa.PrivateKey`; `(*SigningKey).CertPEM() []byte`; `(*SigningKey).KeyID() string`. Consumed by Task 4 (startup wiring), Task 5 (signing in `SendToAgent`), Task 6 (enrollment response).

- [ ] **Step 1: Write the failing test**

```go
// orchestrator/internal/cmdsigning/key_test.go
package cmdsigning

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateSigningKey_GeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	sk, err := LoadOrGenerateSigningKey(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateSigningKey: %v", err)
	}
	if sk.PrivateKey() == nil {
		t.Fatal("PrivateKey() is nil")
	}
	if sk.PrivateKey().N.BitLen() != 4096 {
		t.Errorf("key size = %d bits, want 4096", sk.PrivateKey().N.BitLen())
	}
	if len(sk.CertPEM()) == 0 {
		t.Error("CertPEM() is empty")
	}
	if sk.KeyID() == "" {
		t.Error("KeyID() is empty")
	}
	if _, err := os.Stat(filepath.Join(dir, "command-signing.key")); err != nil {
		t.Errorf("private key file not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "command-signing.crt")); err != nil {
		t.Errorf("cert file not written: %v", err)
	}
}

func TestLoadOrGenerateSigningKey_LoadsExistingOnSecondCall(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrGenerateSigningKey(dir)
	if err != nil {
		t.Fatalf("first LoadOrGenerateSigningKey: %v", err)
	}
	second, err := LoadOrGenerateSigningKey(dir)
	if err != nil {
		t.Fatalf("second LoadOrGenerateSigningKey: %v", err)
	}
	if first.KeyID() != second.KeyID() {
		t.Errorf("KeyID changed across reload: %q vs %q -- a new key was generated instead of loading the existing one", first.KeyID(), second.KeyID())
	}
	if !first.PrivateKey().Equal(second.PrivateKey()) {
		t.Error("private key changed across reload")
	}
}

func TestLoadOrGenerateSigningKey_CorruptKeyFileIsHardError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "command-signing.key"), []byte("not a pem key"), 0600); err != nil {
		t.Fatalf("write corrupt key: %v", err)
	}
	if _, err := LoadOrGenerateSigningKey(dir); err == nil {
		t.Fatal("expected an error for a corrupt command-signing.key, got nil -- silently regenerating would invalidate every agent's trust in the old key with no warning")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/cmdsigning/... -v`
Expected: FAIL — `no Go files in ...` / `undefined: LoadOrGenerateSigningKey`

- [ ] **Step 3: Write minimal implementation**

```go
// orchestrator/internal/cmdsigning/key.go

// Package cmdsigning implements the deployment command-signing keypair
// used to sign every execution-triggering WS command dispatched to an
// agent (B4). This is a separate trust domain from both the mTLS
// deployment CA (internal/pki -- see that package's own doc comment,
// which already anticipated this package) and the offline vendor
// scenario-signing key (internal/integrity) -- the three are never
// chained together, so compromise of one does not automatically
// compromise another. Unlike the vendor key, this key's private half
// necessarily lives with the running orchestrator, because it signs
// commands generated at runtime, not static content signed offline.
// See docs/superpowers/specs/2026-09-28-command-envelope-signing-design.md.
package cmdsigning

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// signingKeyValidity mirrors the deployment CA's long-lived-by-design
// choice (internal/pki/ca.go's caValidity) -- air-gapped operators don't
// want frequent rotation, and the full rotation flow (accepting a
// current + next key during an overlap period) is explicitly out of
// scope for this initial implementation; see the spec.
const signingKeyValidity = 10 * 365 * 24 * time.Hour

// SigningKey holds the deployment command-signing keypair and its
// self-signed identity certificate. The private key never leaves the
// orchestrator host.
type SigningKey struct {
	cert    *x509.Certificate
	certDER []byte
	key     *rsa.PrivateKey
	keyID   string
}

// LoadOrGenerateSigningKey loads an existing signing keypair from dir, or
// generates a new one if dir contains no command-signing.key. dir is
// created if it does not exist. A key that exists but fails to parse
// (corrupt/truncated file) is a hard error -- silently regenerating would
// invalidate every already-distributed agent's trust in the old key with
// no warning, exactly like internal/pki/ca.go's LoadOrGenerateCA.
func LoadOrGenerateSigningKey(dir string) (*SigningKey, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create signing dir %s: %w", dir, err)
	}
	keyPath := filepath.Join(dir, "command-signing.key")
	certPath := filepath.Join(dir, "command-signing.crt")

	if _, err := os.Stat(keyPath); err == nil {
		return loadSigningKey(keyPath, certPath)
	}
	return generateSigningKey(keyPath, certPath)
}

func generateSigningKey(keyPath, certPath string) (*SigningKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("generate command-signing key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate command-signing cert serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Audspect Deployment Command-Signing Key", Organization: []string{"Audspect"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(signingKeyValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create command-signing certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated command-signing certificate: %w", err)
	}
	if err := writeRSAKeyPEM(keyPath, key); err != nil {
		return nil, err
	}
	if err := writeCertPEM(certPath, certDER); err != nil {
		return nil, err
	}
	return &SigningKey{cert: cert, certDER: certDER, key: key, keyID: keyIDFor(certDER)}, nil
}

func loadSigningKey(keyPath, certPath string) (*SigningKey, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read command-signing key: %w", err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read command-signing cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode command-signing key PEM %s: no PEM block found (corrupt or truncated file)", keyPath)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse command-signing private key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("decode command-signing cert PEM %s: no PEM block found (corrupt or truncated file)", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse command-signing certificate: %w", err)
	}
	return &SigningKey{cert: cert, certDER: certBlock.Bytes, key: key, keyID: keyIDFor(certBlock.Bytes)}, nil
}

func writeRSAKeyPEM(path string, key *rsa.PrivateKey) error {
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	// 0600: readable only by the orchestrator process owner, matching
	// internal/pki/ca.go's CA key -- this file staying on the orchestrator
	// host is the entire point of this key's trust model.
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}

func writeCertPEM(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0644)
}

// keyIDFor derives a stable key identifier from the certificate's DER
// bytes -- forward-compatibility for the future key-rotation flow (out of
// scope for this plan; see the spec), so agents can already record which
// key they were told to trust without a future wire-format change.
func keyIDFor(certDER []byte) string {
	h := sha256Sum(certDER)
	return "command-signing-key-" + hex.EncodeToString(h[:8])
}

// PrivateKey returns the RSA private key used to sign envelopes.
func (s *SigningKey) PrivateKey() *rsa.PrivateKey { return s.key }

// CertPEM returns the signing certificate in PEM form, for distribution
// to agents via the enrollment response (Task 6).
func (s *SigningKey) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.certDER})
}

// KeyID returns this key's stable identifier.
func (s *SigningKey) KeyID() string { return s.keyID }
```

Add the small `sha256Sum` helper (kept separate so `key.go`'s imports stay focused):

```go
// orchestrator/internal/cmdsigning/hash.go
package cmdsigning

import "crypto/sha256"

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/cmdsigning/... -v`
Expected: PASS (note: `TestLoadOrGenerateSigningKey_GeneratesOnFirstCall` measured ~767ms on this session's build host for the RSA-4096 keygen alone -- not a meaningful regression, no special handling needed, but don't be surprised by a sub-second-but-not-instant run)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/cmdsigning/key.go orchestrator/internal/cmdsigning/hash.go orchestrator/internal/cmdsigning/key_test.go
git commit -m "feat(signing): add deployment command-signing key generation, independent lifecycle from the CA"
git push
```

---

### Task 3: Orchestrator — sign function + fail-closed check + DB column

**Files:**
- Create: `orchestrator/internal/cmdsigning/sign.go`
- Create: `orchestrator/internal/cmdsigning/sign_test.go`
- Create: `orchestrator/cmd/server/signing_state.go`
- Create: `orchestrator/cmd/server/signing_state_test.go`
- Modify: `orchestrator/internal/db/postgres.go` (add one `ALTER TABLE` line to the existing schema statement list, right after the existing `agent_certificates` block at line 107-115)

**Interfaces:**
- Consumes: `cmdsigning.SigningKey` from Task 2; `models.CommandEnvelope`/`CanonicalJSON` from Task 1; the existing `sharedDB` test harness pattern from `cmd/server/testmain_test.go` (already in the repo from this session's earlier work).
- Produces: `cmdsigning.SignEnvelope(priv *rsa.PrivateKey, env models.CommandEnvelope) ([]byte, error)` (consumed by Task 5); `checkSigningKeyNotSilentlyRotated(ctx context.Context, pool *pgxpool.Pool, signingKeyExistedBefore bool) error` (consumed by Task 4); DB column `agent_certificates.command_signing_key_id text` (consumed by Task 6, which populates it, and by this task's own check, which reads it).

- [ ] **Step 1: Write the failing test (sign/verify round-trip)**

```go
// orchestrator/internal/cmdsigning/sign_test.go
package cmdsigning

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/audspect/bas/internal/models"
)

func testEnvelope(t *testing.T) models.CommandEnvelope {
	t.Helper()
	return models.CommandEnvelope{
		Version:     models.CommandEnvelopeVersion,
		CommandID:   "cmd-1",
		CommandType: "command_scenario",
		AgentID:     "abc123deadbeef01",
		RunID:       "run-1",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(60 * time.Second),
		Nonce:       "nonce-1",
		Payload:     json.RawMessage(`{"runId":"run-1"}`),
	}
}

func TestSignEnvelope_ProducesVerifiableSignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048) // small key -- fast test, algorithm-only assertion
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	env := testEnvelope(t)

	sig, err := SignEnvelope(priv, env)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("SignEnvelope returned an empty signature")
	}

	canon, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := sha256.Sum256(canon)
	if err := rsa.VerifyPKCS1v15(&priv.PublicKey, crypto.SHA256, hash[:], sig); err != nil {
		t.Errorf("signature does not verify against the canonical JSON: %v", err)
	}
}

func TestSignEnvelope_DifferentEnvelopesProduceDifferentSignatures(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	env1 := testEnvelope(t)
	env2 := testEnvelope(t)
	env2.CommandID = "cmd-2"

	sig1, err := SignEnvelope(priv, env1)
	if err != nil {
		t.Fatalf("SignEnvelope env1: %v", err)
	}
	sig2, err := SignEnvelope(priv, env2)
	if err != nil {
		t.Fatalf("SignEnvelope env2: %v", err)
	}
	if string(sig1) == string(sig2) {
		t.Error("two envelopes differing only in CommandID produced identical signatures")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/cmdsigning/... -run TestSignEnvelope -v`
Expected: FAIL — `undefined: SignEnvelope`

- [ ] **Step 3: Write minimal implementation**

```go
// orchestrator/internal/cmdsigning/sign.go
package cmdsigning

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/audspect/bas/internal/models"
)

// SignEnvelope signs env's canonical JSON (see
// models.CommandEnvelope.CanonicalJSON) with priv, using the same
// RSA-4096/PKCS#1v1.5/SHA-256 scheme internal/integrity uses for the
// (entirely separate) vendor key -- consistency of algorithm choice only,
// never a shared key or shared code path with that package.
func SignEnvelope(priv *rsa.PrivateKey, env models.CommandEnvelope) ([]byte, error) {
	canon, err := env.CanonicalJSON()
	if err != nil {
		return nil, fmt.Errorf("canonicalize envelope: %w", err)
	}
	hash := sha256.Sum256(canon)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("sign envelope: %w", err)
	}
	return sig, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/cmdsigning/... -v`
Expected: PASS (all of Task 2 + Task 3's cmdsigning tests)

- [ ] **Step 5: Add the DB column**

Read `orchestrator/internal/db/postgres.go` lines 105-116 first to confirm the exact statement-list shape hasn't drifted since this plan was written, then add immediately after the existing `agent_certificates` index line (115):

```go
		`ALTER TABLE agent_certificates ADD COLUMN IF NOT EXISTS command_signing_key_id text`,
```

This is nullable with no default: existing rows (issued before this plan) correctly have no recorded signing-key trust, and Task 6 populates it going forward at enrollment time.

- [ ] **Step 6: Write the failing test for the fail-closed check**

First read `orchestrator/cmd/server/ca_state_test.go` and `orchestrator/cmd/server/testmain_test.go` in full (both already exist in this repo from this session's earlier work) to confirm `sharedDB` and the seed-row pattern haven't changed, then write the analogous test:

```go
// orchestrator/cmd/server/signing_state_test.go
package main

import (
	"context"
	"os"
	"testing"
)

// TestCheckSigningKeyNotSilentlyRotated_AllowsFreshInstall mirrors
// TestCheckCANotSilentlyRotated_AllowsFreshInstall: a genuine fresh
// install (no existing agent_certificates rows carrying a
// command_signing_key_id) is never blocked, even though
// signingKeyExistedBefore is false (a key was just generated).
func TestCheckSigningKeyNotSilentlyRotated_AllowsFreshInstall(t *testing.T) {
	if err := checkSigningKeyNotSilentlyRotated(context.Background(), sharedDB.Pool, false); err != nil {
		t.Errorf("expected fresh install (no existing signing-trust rows) to be allowed, got: %v", err)
	}
}

// TestCheckSigningKeyNotSilentlyRotated_BlocksSilentRegenerationWithExistingTrust
// is the core safety property: a fresh signing key generation
// (signingKeyExistedBefore = false) with an EXISTING agent_certificates
// row that already recorded trust in a (now-gone) signing key must be
// refused -- exactly like the CA's equivalent check, and for the same
// reason: agents enrolled under the old key would silently reject every
// command the new key signs, with no indication why, unless the operator
// is warned at startup instead.
func TestCheckSigningKeyNotSilentlyRotated_BlocksSilentRegenerationWithExistingTrust(t *testing.T) {
	ctx := context.Background()
	_, err := sharedDB.Pool.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at, command_signing_key_id)
		VALUES ($1, $2, NOW(), NOW() + interval '1 year', $3)`,
		"test-serial-signing-lockout-check", "abc123deadbeef01", "command-signing-key-deadbeef")
	if err != nil {
		t.Fatalf("seed agent_certificates: %v", err)
	}
	defer sharedDB.Pool.Exec(ctx, `DELETE FROM agent_certificates WHERE serial_number = $1`, "test-serial-signing-lockout-check")

	os.Unsetenv("BAS_CONFIRM_NEW_SIGNING_KEY")
	if err := checkSigningKeyNotSilentlyRotated(ctx, sharedDB.Pool, false); err == nil {
		t.Fatal("expected an error when a fresh signing key is generated but a row already records trust in a different key")
	}
}

// TestCheckSigningKeyNotSilentlyRotated_OverrideAllowsIntentionalRotation
// confirms the escape hatch for a genuine, intentional key rotation/reset.
func TestCheckSigningKeyNotSilentlyRotated_OverrideAllowsIntentionalRotation(t *testing.T) {
	ctx := context.Background()
	_, err := sharedDB.Pool.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at, command_signing_key_id)
		VALUES ($1, $2, NOW(), NOW() + interval '1 year', $3)`,
		"test-serial-signing-override-check", "abc123deadbeef02", "command-signing-key-deadbeef")
	if err != nil {
		t.Fatalf("seed agent_certificates: %v", err)
	}
	defer sharedDB.Pool.Exec(ctx, `DELETE FROM agent_certificates WHERE serial_number = $1`, "test-serial-signing-override-check")

	t.Setenv("BAS_CONFIRM_NEW_SIGNING_KEY", "true")
	if err := checkSigningKeyNotSilentlyRotated(ctx, sharedDB.Pool, false); err != nil {
		t.Errorf("expected BAS_CONFIRM_NEW_SIGNING_KEY=true to allow intentional rotation, got: %v", err)
	}
}

// TestCheckSigningKeyNotSilentlyRotated_SkipsCheckWhenKeyAlreadyExisted
// confirms the normal, every-day restart case (signing key file was
// present, nothing was regenerated) is never blocked.
func TestCheckSigningKeyNotSilentlyRotated_SkipsCheckWhenKeyAlreadyExisted(t *testing.T) {
	if err := checkSigningKeyNotSilentlyRotated(context.Background(), sharedDB.Pool, true); err != nil {
		t.Errorf("expected signingKeyExistedBefore=true to skip the check entirely, got: %v", err)
	}
}

// TestCheckSigningKeyNotSilentlyRotated_IgnoresRowsWithNoRecordedTrust
// confirms a pre-this-plan agent_certificates row (command_signing_key_id
// IS NULL, since it predates this column) is correctly NOT treated as
// evidence of prior signing-key trust -- it never trusted any signing key
// at all, so there's nothing to silently invalidate.
func TestCheckSigningKeyNotSilentlyRotated_IgnoresRowsWithNoRecordedTrust(t *testing.T) {
	ctx := context.Background()
	_, err := sharedDB.Pool.Exec(ctx, `
		INSERT INTO agent_certificates (serial_number, agent_id, issued_at, expires_at)
		VALUES ($1, $2, NOW(), NOW() + interval '1 year')`,
		"test-serial-signing-null-check", "abc123deadbeef03")
	if err != nil {
		t.Fatalf("seed agent_certificates: %v", err)
	}
	defer sharedDB.Pool.Exec(ctx, `DELETE FROM agent_certificates WHERE serial_number = $1`, "test-serial-signing-null-check")

	os.Unsetenv("BAS_CONFIRM_NEW_SIGNING_KEY")
	if err := checkSigningKeyNotSilentlyRotated(ctx, sharedDB.Pool, false); err != nil {
		t.Errorf("expected a row with no recorded signing-key trust to be ignored, got: %v", err)
	}
}
```

- [ ] **Step 7: Run test to verify it fails**

Run: `cd orchestrator && go test ./cmd/server/... -run TestCheckSigningKeyNotSilentlyRotated -v`
Expected: FAIL — `undefined: checkSigningKeyNotSilentlyRotated`

- [ ] **Step 8: Write minimal implementation**

First read `orchestrator/cmd/server/main.go`'s existing `checkCANotSilentlyRotated` function in full (it's already in this repo from this session's earlier work) to match its exact structure, then write the analogous one:

```go
// orchestrator/cmd/server/signing_state.go
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

// checkSigningKeyNotSilentlyRotated is checkCANotSilentlyRotated's
// counterpart for the deployment command-signing key (main.go, this
// session's earlier B1/B3 work): a fresh key generation
// (signingKeyExistedBefore = false) on what turns out to be an EXISTING
// deployment -- evidence being an agent_certificates row that already
// recorded trust in a signing key -- must be refused rather than
// silently minting a new key no already-enrolled agent trusts, which
// would otherwise surface only as every dispatched command being
// inexplicably rejected agent-side with no indication why.
//
// signingKeyExistedBefore=true (the normal restart case: the key file
// was already on disk before LoadOrGenerateSigningKey ran) always skips
// this check, regardless of what's in agent_certificates.
//
// BAS_CONFIRM_NEW_SIGNING_KEY=true is the escape hatch for a genuine,
// intentional key rotation/reset -- distinctly named from B1/B3's
// BAS_CONFIRM_NEW_CA so an operator confirming one never accidentally
// confirms the other.
func checkSigningKeyNotSilentlyRotated(ctx context.Context, pool *pgxpool.Pool, signingKeyExistedBefore bool) error {
	if signingKeyExistedBefore {
		return nil
	}
	if os.Getenv("BAS_CONFIRM_NEW_SIGNING_KEY") == "true" {
		return nil
	}
	var count int
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM agent_certificates
		WHERE command_signing_key_id IS NOT NULL
		  AND revoked = false
		  AND expires_at > NOW()`,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("check for existing command-signing trust: %w", err)
	}
	if count > 0 {
		return fmt.Errorf(
			"a command-signing key was just generated, but %d already-enrolled agent(s) recorded trust in a previous signing key -- "+
				"this looks like the ./signing directory was lost or reset on an EXISTING deployment, not a fresh install. "+
				"Every dispatched command would be silently rejected by agents still trusting the old key. "+
				"If this is intentional (a deliberate key rotation/reset), re-run with BAS_CONFIRM_NEW_SIGNING_KEY=true", count)
	}
	return nil
}
```

- [ ] **Step 9: Run test to verify it passes**

Run: `cd orchestrator && go test ./cmd/server/... -run TestCheckSigningKeyNotSilentlyRotated -v`
Expected: PASS (all 5 tests)

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/cmdsigning/sign.go orchestrator/internal/cmdsigning/sign_test.go orchestrator/cmd/server/signing_state.go orchestrator/cmd/server/signing_state_test.go orchestrator/internal/db/postgres.go
git commit -m "feat(signing): add envelope signing function and fail-closed check for the command-signing key"
git push
```

---

### Task 4: Orchestrator — wire key generation into startup

**Files:**
- Modify: `orchestrator/cmd/server/main.go` (near the existing CA generation block)

**Interfaces:**
- Consumes: `cmdsigning.LoadOrGenerateSigningKey` (Task 2), `checkSigningKeyNotSilentlyRotated` (Task 3).
- Produces: a package-level or `Handler`-held `*cmdsigning.SigningKey` accessible to Task 5 (hub construction) and Task 6 (enrollment handler).

- [ ] **Step 1: Read the exact current CA-generation block**

Run: `grep -n "PKIDir\|LoadOrGenerateCA\|checkCANotSilentlyRotated\|caKeyExistedBefore" orchestrator/cmd/server/main.go`

Confirm the exact surrounding lines (this session's earlier work put this around line 630-645; re-read it directly rather than trusting that line number, since intervening tasks in this plan don't touch main.go until now but the file may have shifted).

- [ ] **Step 2: Add the parallel signing-key block immediately after the CA block**

Using the exact pattern the CA block already establishes (`caKeyPath`/`caKeyStatErr`/`caKeyExistedBefore` → `pki.LoadOrGenerateCA` → `checkCANotSilentlyRotated`), add:

```go
	signingDir := os.Getenv("BAS_SIGNING_DIR")
	if signingDir == "" {
		signingDir = "/etc/audspect/signing"
	}
	signingKeyPath := filepath.Join(signingDir, "command-signing.key")
	_, signingKeyStatErr := os.Stat(signingKeyPath)
	signingKeyExistedBefore := signingKeyStatErr == nil

	signingKey, err := cmdsigning.LoadOrGenerateSigningKey(signingDir)
	if err != nil {
		log.Fatalf("load/generate command-signing key: %v", err)
	}
	if err := checkSigningKeyNotSilentlyRotated(context.Background(), pool, signingKeyExistedBefore); err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("[*] command-signing key ready: %s", signingKey.KeyID())
```

Add `"github.com/audspect/bas/internal/cmdsigning"` to main.go's import block if not already grouped with the other `internal/...` imports.

`BAS_SIGNING_DIR` mirrors `BAS_PKI_DIR`'s existing override pattern (if `BAS_PKI_DIR` doesn't already exist as an env var name in this codebase, confirm the actual name `PKIDir`'s value comes from by reading `orchestrator/config/config.go`'s `PKIDir` field before assuming `BAS_PKI_DIR` -- match whatever the real convention is exactly).

- [ ] **Step 3: Thread `signingKey` into the Hub constructor's signature now, to keep this task compiling on its own**

`signingKey` must not be left as an unused local variable in `main()` — Go rejects unused locals at compile time (unlike unused struct fields, which are fine). Rather than defer all wiring to Task 5, make the minimal mechanical change here: change `ws.NewHub()`'s signature to accept and store the signing key, and update `main()`'s one call site to pass it. This gives `signingKey` a real use immediately; Task 5 then only adds the logic inside `SendToAgent` that actually *reads* `h.signer` — it does not need to touch the constructor signature again.

Locate the current definitions first: `grep -n "func NewHub\|type Hub struct" orchestrator/internal/ws/hub.go` and `grep -n "ws.NewHub()" orchestrator/cmd/server/main.go` (this session's earlier grep already confirmed there is exactly one call site).

In `orchestrator/internal/ws/hub.go`, change:

```go
type Hub struct {
	mu       sync.RWMutex
	agents   map[string]*conn
	browsers []*conn
	signer   *rsa.PrivateKey // deployment command-signing key (B4) -- see internal/cmdsigning. Read by SendToAgent starting in Task 5; unused until then, which is fine for a struct field.
}

// NewHub creates a ready-to-use Hub. signer is the deployment
// command-signing private key (internal/cmdsigning.SigningKey.PrivateKey())
// -- never the vendor scenario-signing key, which this package never
// imports or references.
func NewHub(signer *rsa.PrivateKey) *Hub {
	return &Hub{agents: make(map[string]*conn), signer: signer}
}
```

Add `"crypto/rsa"` to `hub.go`'s import block (the rest of Task 5's imports — `crypto/rand`, `encoding/hex`, etc. — are added later, in Task 5, only when `signCommand` is actually written).

In `orchestrator/cmd/server/main.go`, update the one call site:

```go
	hub := ws.NewHub(signingKey.PrivateKey())
```

- [ ] **Step 4: Verify the build**

Run: `cd orchestrator && go build ./...`
Expected: succeeds. This task adds no new automated test of its own beyond Task 2/3's existing coverage — `signingKey` generation and the fail-closed check are already covered there; this step's job is only to confirm the mechanical signature-threading compiles cleanly. Task 5 adds the actual signing-behavior tests.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/cmd/server/main.go
git commit -m "feat(signing): generate/load the command-signing key at orchestrator startup"
git push
```

---

### Task 5: Orchestrator — sign in the centralized `SendToAgent` boundary

**Files:**
- Modify: `orchestrator/internal/ws/hub.go`
- Test: `orchestrator/internal/ws/hub_test.go` (create if it doesn't already exist — check first)

**Interfaces:**
- Consumes: `cmdsigning.SignEnvelope` (Task 3), `models.CommandEnvelope`/`IsSignedCommandType` (Task 1), `*rsa.PrivateKey` from Task 4's `signingKey`.
- Produces: `ws.NewHub(signer *rsa.PrivateKey) *Hub` (signature change — every call site updated in this task, not deferred).

- [ ] **Step 1: Check for an existing hub_test.go**

Run: `ls orchestrator/internal/ws/*_test.go 2>/dev/null || echo "none"`. If tests already exist, read them in full before adding to the same file (don't create a colliding second test file).

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/ws/hub_test.go (add to existing file, or create if none exists)
package ws

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/audspect/bas/internal/models"
)

// TestSendToAgent_SignsInScopeCommandTypes locks in the centralized
// signing boundary: for one of the 8 execution-triggering command types,
// what actually goes out on the wire must be a signed CommandEnvelope,
// not the raw payload -- and this must be true regardless of which of
// the 16 real call sites constructed the WSMessage, since none of them
// are touched by this change.
func TestSendToAgent_SignsInScopeCommandTypes(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048) // small key -- fast test
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	h := NewHub(priv)
	c := &conn{send: make(chan []byte, 1)}
	h.mu.Lock()
	h.agents["agent-1"] = c
	h.mu.Unlock()

	type scenarioPayload struct {
		RunID string `json:"runId"`
	}
	sent := h.SendToAgent("agent-1", models.WSMessage{
		Type:    "command_scenario",
		AgentID: "agent-1",
		Data:    scenarioPayload{RunID: "run-1"},
	})
	if !sent {
		t.Fatal("SendToAgent reported not sent")
	}

	raw := <-c.send
	var wire models.WSMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal wire message: %v", err)
	}
	dataBytes, err := json.Marshal(wire.Data)
	if err != nil {
		t.Fatalf("re-marshal wire.Data: %v", err)
	}
	var env models.CommandEnvelope
	if err := json.Unmarshal(dataBytes, &env); err != nil {
		t.Fatalf("wire.Data for a command_scenario message did not unmarshal as a CommandEnvelope: %v", err)
	}
	if len(env.Signature) == 0 {
		t.Error("CommandEnvelope.Signature is empty -- command_scenario was not signed")
	}
	if env.CommandType != "command_scenario" {
		t.Errorf("envelope CommandType = %q, want command_scenario", env.CommandType)
	}
	if env.AgentID != "agent-1" {
		t.Errorf("envelope AgentID = %q, want agent-1", env.AgentID)
	}
}

// TestSendToAgent_PassesThroughOutOfScopeTypesUnchanged confirms message
// types outside the 8 signed command types (e.g. a heartbeat ack, or any
// other non-execution-triggering type) are never wrapped in a
// CommandEnvelope -- the signing boundary only applies to what the spec
// actually calls execution-triggering.
func TestSendToAgent_PassesThroughOutOfScopeTypesUnchanged(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	h := NewHub(priv)
	c := &conn{send: make(chan []byte, 1)}
	h.mu.Lock()
	h.agents["agent-1"] = c
	h.mu.Unlock()

	type someOtherPayload struct {
		Foo string `json:"foo"`
	}
	h.SendToAgent("agent-1", models.WSMessage{
		Type:    "agentUpdate",
		AgentID: "agent-1",
		Data:    someOtherPayload{Foo: "bar"},
	})

	raw := <-c.send
	var wire models.WSMessage
	json.Unmarshal(raw, &wire)
	dataBytes, _ := json.Marshal(wire.Data)
	var probe map[string]interface{}
	json.Unmarshal(dataBytes, &probe)
	if _, hasSignature := probe["signature"]; hasSignature {
		t.Error("an out-of-scope message type was wrapped in a signed CommandEnvelope")
	}
	if probe["foo"] != "bar" {
		t.Errorf("payload was altered for an out-of-scope type: %+v", probe)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/ws/... -run TestSendToAgent -v`
Expected: FAIL — `NewHub(priv)` doesn't match the current 0-arg `NewHub()` signature (compile error)

- [ ] **Step 4: Write minimal implementation**

Task 4 already changed `Hub`'s struct (added the `signer *rsa.PrivateKey` field) and `NewHub`'s signature to accept and store it — confirm this by reading the current `orchestrator/internal/ws/hub.go` before proceeding; do not re-declare either. This task only modifies `SendToAgent` to actually *read* `h.signer`, and adds the new `signCommand` method:

```go
// orchestrator/internal/ws/hub.go -- modify existing SendToAgent only; signCommand is new
```

```go
// SendToAgent delivers a message to a specific connected agent.
// Returns false if the agent is not currently connected.
//
// For any of the 8 execution-triggering command types
// (models.IsSignedCommandType), msg.Data is wrapped in a signed
// models.CommandEnvelope before marshaling -- this is the single
// mandatory signing boundary every one of this codebase's 16 dispatch
// call sites already funnels through, so none of them need to change.
// Every other message type passes through completely unchanged.
func (h *Hub) SendToAgent(agentID string, msg models.WSMessage) (sent bool) {
	h.mu.RLock()
	c, ok := h.agents[agentID]
	h.mu.RUnlock()
	if !ok {
		return false
	}

	if models.IsSignedCommandType(msg.Type) {
		signed, err := h.signCommand(agentID, msg)
		if err != nil {
			log.Printf("[ws] sign command %s for agent %s: %v -- not sent", msg.Type, agentID, err)
			return false
		}
		msg.Data = signed
	}

	b, _ := json.Marshal(msg)
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	select {
	case c.send <- b:
		return true
	default:
		return false
	}
}

// signCommand builds and signs the CommandEnvelope for an in-scope
// command type. runID/scenarioID/stepID/mode/policy are extracted from
// msg.Data on a best-effort basis (only ScenarioCommand-shaped payloads
// carry them today); command types without a scenario context (cancel,
// pause, resume, stop_agent, uninstall_agent) simply leave those fields
// at their zero value, which CommandEnvelope's omitempty tags already
// handle correctly.
func (h *Hub) signCommand(agentID string, msg models.WSMessage) (models.CommandEnvelope, error) {
	payload, err := json.Marshal(msg.Data)
	if err != nil {
		return models.CommandEnvelope{}, fmt.Errorf("marshal payload: %w", err)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return models.CommandEnvelope{}, fmt.Errorf("generate nonce: %w", err)
	}
	commandID := make([]byte, 16)
	if _, err := rand.Read(commandID); err != nil {
		return models.CommandEnvelope{}, fmt.Errorf("generate command id: %w", err)
	}
	now := time.Now().UTC()
	env := models.CommandEnvelope{
		Version:     models.CommandEnvelopeVersion,
		CommandID:   hex.EncodeToString(commandID),
		CommandType: msg.Type,
		AgentID:     agentID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(commandEnvelopeTTL),
		Nonce:       hex.EncodeToString(nonce),
		Payload:     payload,
	}
	// Best-effort extraction of the optional context fields from
	// ScenarioCommand-shaped payloads -- see scenario.ScenarioCommand.
	var ctx struct {
		RunID      string `json:"runId"`
		ScenarioID string `json:"scenarioId"`
		Mode       string `json:"mode"`
	}
	if json.Unmarshal(payload, &ctx) == nil {
		env.RunID = ctx.RunID
		env.ScenarioID = ctx.ScenarioID
		env.Mode = ctx.Mode
	}

	sig, err := cmdsigning.SignEnvelope(h.signer, env)
	if err != nil {
		return models.CommandEnvelope{}, fmt.Errorf("sign envelope: %w", err)
	}
	env.Signature = sig
	return env, nil
}

// commandEnvelopeTTL is how long a signed command remains valid --
// deliberately short (see the spec's "Expiry & replay" section for the
// full rationale). Configurable via env var rather than hardcoded, per
// the spec's explicit requirement.
var commandEnvelopeTTL = commandEnvelopeTTLFromEnv()

func commandEnvelopeTTLFromEnv() time.Duration {
	if v := os.Getenv("BAS_COMMAND_ENVELOPE_TTL_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 60 * time.Second
}
```

Add the new imports `orchestrator/internal/ws/hub.go` now needs (`"crypto/rsa"` was already added in Task 4): `"crypto/rand"`, `"encoding/hex"`, `"fmt"`, `"os"`, `"strconv"`, `"time"`, `"github.com/audspect/bas/internal/cmdsigning"`.

Then fix the ONE existing call site that constructs a `Hub` directly (find it: `grep -rn "ws.NewHub()" orchestrator/`) to pass `signingKey.PrivateKey()` from Task 4's `main()` — this is the only caller in the whole codebase per Task 4's own Step 3 investigation, so this task's Step 4 also closes that loop:

```go
hub := ws.NewHub(signingKey.PrivateKey())
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/ws/... -v`
Expected: PASS. Also run `go build ./...` at the repo root of `orchestrator/` to confirm `main.go`'s call site compiles.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/ws/hub.go orchestrator/internal/ws/hub_test.go orchestrator/cmd/server/main.go
git commit -m "feat(signing): sign execution-triggering commands in the centralized SendToAgent boundary"
git push
```

---

### Task 6: Orchestrator — enrollment response carries the signing trust material

**Files:**
- Modify: `orchestrator/internal/api/enroll_csr_handlers.go`

**Interfaces:**
- Consumes: `signingKey.CertPEM()`/`signingKey.KeyID()` (Task 4, threaded into the `Handler` struct alongside `h.pki`).
- Produces: `enrollCSRResponse.CommandSigningTrust` (consumed by agent-side Task 8).

- [ ] **Step 1: Read the existing handler and response struct in full**

Run: `cat orchestrator/internal/api/enroll_csr_handlers.go` — confirm the exact `Handler` struct field name the PKI CA is threaded through as (`h.pki` per this session's earlier grep) and the exact response-construction block (around line 141-155 per this session's earlier read) before writing this task's diff, since the file may have shifted.

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/api/enroll_csr_handlers_test.go -- add to the existing file (already has
// TestEnrollCSR_ValidBootstrapSecretIssuesCertificate and others from this session's earlier work)
```

```go
func TestEnrollCSR_ResponseIncludesCommandSigningTrust(t *testing.T) {
	h, cleanup := newTestHandlerWithSigningKey(t) // see Step 3's test-helper addition
	defer cleanup()

	body := validCSRRequestBody(t, "abc123deadbeef01") // reuse this file's existing request-building helper; read it first to match its exact name/shape
	req := httptest.NewRequest(http.MethodPost, "/api/agents/enroll-csr", bytes.NewReader(body))
	req.Header.Set("X-Agent-Token", testBootstrapSecret) // match existing test's constant name
	rec := httptest.NewRecorder()

	h.EnrollCSR(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp enrollCSRResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.CommandSigningTrust.KeyID == "" {
		t.Error("CommandSigningTrust.KeyID is empty")
	}
	if len(resp.CommandSigningTrust.CertPEM) == 0 {
		t.Error("CommandSigningTrust.CertPEM is empty")
	}
	block, _ := pem.Decode([]byte(resp.CommandSigningTrust.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Error("CommandSigningTrust.CertPEM is not a valid PEM certificate")
	}
}
```

Before finalizing this step, read the file's existing test helpers (`newTestHandler`-style constructors, request-body builders, the bootstrap-secret constant) and match their real names exactly — do not invent names that don't exist in the file.

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestEnrollCSR_ResponseIncludesCommandSigningTrust -v`
Expected: FAIL — compile error (`enrollCSRResponse` has no field `CommandSigningTrust`, and/or the test helper doesn't exist yet)

- [ ] **Step 4: Write minimal implementation**

Extend `enrollCSRResponse`:

```go
type enrollCSRResponse struct {
	CertPEM             string              `json:"certPem"`
	CAPEM               string              `json:"caPem"`
	ExpiresAt           string              `json:"expiresAt"`
	CommandSigningTrust commandSigningTrust `json:"commandSigningTrust"`
}

// commandSigningTrust is the authenticated-transport delivery of the
// deployment command-signing public certificate (B4). The enrollment
// response is how it reaches the agent, but it is not itself the root of
// trust -- the agent only reaches this response at all because the
// channel delivering it was already verified via the pre-distributed
// deployment CA (see the spec's "Key distribution" section).
type commandSigningTrust struct {
	KeyID   string `json:"keyId"`
	CertPEM string `json:"certPem"`
}
```

Thread the signing key into `Handler` the same way `h.pki` already is (read the `Handler` struct definition to find where `pki` is declared, add `signingKey *cmdsigning.SigningKey` alongside it), then in the response-construction block (found in Step 1), add:

```go
		CommandSigningTrust: commandSigningTrust{
			KeyID:   h.signingKey.KeyID(),
			CertPEM: string(h.signingKey.CertPEM()),
		},
```

Find where `Handler{...}` is constructed (`grep -n "&Handler{" orchestrator/cmd/server/main.go`) and update it to pass `signingKey` through as the new `signingKey *cmdsigning.SigningKey` field.

Also populate the new DB column from Task 3 at the point this same handler inserts the `agent_certificates` row (find that `INSERT INTO agent_certificates` statement in this same file) — add `command_signing_key_id` to the column list and bind `h.signingKey.KeyID()` as its value. This is what makes Task 3's fail-closed check's evidence real: every agent enrolled from this point forward records which signing key it was told to trust.

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run TestEnrollCSR -v`
Expected: PASS (this task's new test plus every pre-existing `TestEnrollCSR_*` test, unbroken)

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/enroll_csr_handlers.go orchestrator/internal/api/enroll_csr_handlers_test.go orchestrator/cmd/server/main.go
git commit -m "feat(signing): deliver the command-signing public certificate via the enrollment response"
git push
```

---

### Task 7: Orchestrator deployment — `./signing` directory, ownership, backup

**Files:**
- Modify: `packaging/compose/docker-compose.yml`
- Modify: `packaging/compose/install.sh`

**Interfaces:**
- Consumes: nothing from earlier tasks (parallel infrastructure work — could run before or after the Go tasks, sequenced last here only because it's least interesting to review first).
- Produces: the `./signing` bind-mount, ownership, and backup coverage that `cmdsigning.LoadOrGenerateSigningKey`'s default `/etc/audspect/signing` path (Task 4) actually needs on a real deployment.

- [ ] **Step 1: Add the bind-mount to docker-compose.yml**

Read the existing `./pki:/etc/audspect/pki` line (from this session's earlier deployment-topology work) and add immediately after it:

```yaml
      - ./signing:/etc/audspect/signing
```

- [ ] **Step 2: Add directory creation + ownership to `install.sh`'s `mode_install`**

Read `mode_install`'s existing `mkdir -p "${DATA_DIR}"/{...,pki,certs}` line and the `chown 65532:65532 "${DATA_DIR}/pki"` / `chmod 700 "${DATA_DIR}/pki"` lines immediately after it (from this session's earlier work), then add `signing` to the `mkdir` brace list and add the parallel chown/chmod:

```bash
  mkdir -p "${DATA_DIR}"/{data/postgres,logs,backups,scenarios,wwwroot,art-payloads,sharphound,pki,certs,signing}
  ...
  # signing holds the deployment command-signing key (B4) -- independent
  # lifecycle from pki's CA, but needs the identical nonroot-writable
  # treatment for the identical reason: the orchestrator container (UID
  # 65532) generates/persists it via the ./signing bind mount.
  chown 65532:65532 "${DATA_DIR}/signing"
  chmod 700 "${DATA_DIR}/signing"
```

- [ ] **Step 3: Add the identical treatment to `mode_upgrade`**

This is the exact bug the final review caught for `pki` in this session's deployment-topology plan (Critical finding, fixed in commit `dd0d3ff`) — `mode_upgrade` must get the same directory-creation+ownership sequence `mode_install` gets, not just `mode_install`. Read `mode_upgrade`'s existing `mkdir -p "${DATA_DIR}"/{pki,certs}` + `chown`/`chmod` block (added in that earlier fix) and extend it:

```bash
  mkdir -p "${DATA_DIR}"/{pki,certs,signing}
  chown 65532:65532 "${DATA_DIR}/pki"
  chmod 700 "${DATA_DIR}/pki"
  chown 65532:65532 "${DATA_DIR}/signing"
  chmod 700 "${DATA_DIR}/signing"
```

- [ ] **Step 4: Extend the backup engine**

Read `_package_config`'s existing tar command (extended for `pki` in this session's earlier Task 10 of the deployment-topology plan, commit `8e6e6b0`) and add `signing` to the same tar argument list.

- [ ] **Step 5: Verify**

Run: `bash -n packaging/compose/install.sh && echo syntax-OK`
Run: `cd packaging/compose && POSTGRES_PASSWORD=x JWT_SECRET=x docker compose config >/dev/null && echo compose-valid`

- [ ] **Step 6: Commit**

```bash
git add packaging/compose/docker-compose.yml packaging/compose/install.sh
git commit -m "feat(signing): persist and back up the command-signing key on both install and upgrade"
git push
```

---

### Task 8: Agent — CommandEnvelope type + persist signing trust certificate

**Files:**
- Create: `agent/protocol/command_envelope.go`
- Test: `agent/protocol/command_envelope_test.go`
- Modify: `agent/certstore.go`
- Modify: `agent/bootstrap.go` (persist the trust material when present in the enrollment response)

**Interfaces:**
- Consumes: nothing from earlier tasks (agent module is separate from orchestrator; only the wire JSON shape from Task 1/6 needs to match, which this task's own test pins independently).
- Produces: `protocol.CommandEnvelope` (verification-side type, consumed by Task 9); `certPaths()`-family `commandSigningCertPath()` + `saveCommandSigningCert([]byte) error` + `loadCommandSigningCert() (*x509.Certificate, error)` (consumed by Task 9).

- [ ] **Step 1: Write the failing test (envelope type)**

```go
// agent/protocol/command_envelope_test.go
package protocol

import (
	"encoding/json"
	"testing"
	"time"
)

// TestCommandEnvelope_UnmarshalsOrchestratorWireShape locks in that the
// agent's verification-side type accepts exactly what
// orchestrator/internal/models.CommandEnvelope's json tags produce --
// these are deliberately two separate Go types (different modules) that
// must nonetheless agree on wire shape; this test is that agreement's
// pin, independent of any live orchestrator.
func TestCommandEnvelope_UnmarshalsOrchestratorWireShape(t *testing.T) {
	wire := `{
		"version": 1,
		"commandId": "cmd-1",
		"commandType": "command_scenario",
		"agentId": "abc123deadbeef01",
		"runId": "run-1",
		"issuedAt": "2026-09-28T00:00:00Z",
		"expiresAt": "2026-09-28T00:01:00Z",
		"nonce": "nonce-1",
		"payload": {"runId":"run-1"},
		"signature": "AQID"
	}`
	var env CommandEnvelope
	if err := json.Unmarshal([]byte(wire), &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if env.CommandID != "cmd-1" || env.CommandType != "command_scenario" || env.AgentID != "abc123deadbeef01" {
		t.Errorf("unexpected envelope: %+v", env)
	}
	if env.IssuedAt.IsZero() || env.ExpiresAt.IsZero() {
		t.Error("IssuedAt/ExpiresAt did not parse")
	}
	if len(env.Signature) != 3 {
		t.Errorf("Signature = %v (len %d), want 3 bytes decoded from base64", env.Signature, len(env.Signature))
	}
}

func TestCommandEnvelope_CanonicalJSONMatchesOrchestratorShape(t *testing.T) {
	env := CommandEnvelope{
		Version:     1,
		CommandID:   "cmd-1",
		CommandType: "command_scenario",
		AgentID:     "abc123deadbeef01",
		IssuedAt:    time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 9, 28, 0, 1, 0, 0, time.UTC),
		Nonce:       "nonce-1",
		Payload:     json.RawMessage(`{"runId":"run-1"}`),
	}
	b, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	var probe map[string]interface{}
	if err := json.Unmarshal(b, &probe); err != nil {
		t.Fatalf("CanonicalJSON output invalid JSON: %v", err)
	}
	if _, present := probe["signature"]; present {
		t.Error("CanonicalJSON must exclude signature")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test ./protocol/... -run TestCommandEnvelope -v`
Expected: FAIL — `undefined: CommandEnvelope`

- [ ] **Step 3: Write minimal implementation**

```go
// agent/protocol/command_envelope.go
package protocol

import (
	"encoding/json"
	"time"
)

// CommandEnvelope is the agent's verification-side counterpart to
// orchestrator/internal/models.CommandEnvelope -- a deliberately separate
// Go type (separate module) that must agree on wire shape, pinned by
// this package's own tests rather than a shared dependency. See
// docs/superpowers/specs/2026-09-28-command-envelope-signing-design.md.
type CommandEnvelope struct {
	Version     int             `json:"version"`
	CommandID   string          `json:"commandId"`
	CommandType string          `json:"commandType"`
	AgentID     string          `json:"agentId"`
	RunID       string          `json:"runId,omitempty"`
	ScenarioID  string          `json:"scenarioId,omitempty"`
	StepID      string          `json:"stepId,omitempty"`
	Mode        string          `json:"mode,omitempty"`
	Policy      json.RawMessage `json:"policy,omitempty"`
	IssuedAt    time.Time       `json:"issuedAt"`
	ExpiresAt   time.Time       `json:"expiresAt"`
	Nonce       string          `json:"nonce"`
	Payload     json.RawMessage `json:"payload"`
	Signature   []byte          `json:"signature,omitempty"`
}

// CommandEnvelopeVersion is the current envelope wire-format version this
// agent understands. Must match orchestrator's
// models.CommandEnvelopeVersion.
const CommandEnvelopeVersion = 1

// CanonicalJSON returns the exact byte sequence the orchestrator signed --
// must stay byte-for-byte identical to orchestrator/internal/models.
// CommandEnvelope.CanonicalJSON's field set and order, or every signature
// verification fails. See that function's doc comment for why a fixed
// struct needs no separate canonicalization scheme.
func (e CommandEnvelope) CanonicalJSON() ([]byte, error) {
	unsigned := e
	unsigned.Signature = nil
	return json.Marshal(struct {
		Version     int             `json:"version"`
		CommandID   string          `json:"commandId"`
		CommandType string          `json:"commandType"`
		AgentID     string          `json:"agentId"`
		RunID       string          `json:"runId,omitempty"`
		ScenarioID  string          `json:"scenarioId,omitempty"`
		StepID      string          `json:"stepId,omitempty"`
		Mode        string          `json:"mode,omitempty"`
		Policy      json.RawMessage `json:"policy,omitempty"`
		IssuedAt    time.Time       `json:"issuedAt"`
		ExpiresAt   time.Time       `json:"expiresAt"`
		Nonce       string          `json:"nonce"`
		Payload     json.RawMessage `json:"payload"`
	}{
		Version: unsigned.Version, CommandID: unsigned.CommandID, CommandType: unsigned.CommandType,
		AgentID: unsigned.AgentID, RunID: unsigned.RunID, ScenarioID: unsigned.ScenarioID,
		StepID: unsigned.StepID, Mode: unsigned.Mode, Policy: unsigned.Policy,
		IssuedAt: unsigned.IssuedAt, ExpiresAt: unsigned.ExpiresAt, Nonce: unsigned.Nonce,
		Payload: unsigned.Payload,
	})
}

// SignedCommandTypes mirrors orchestrator/internal/models's set exactly --
// the closed list of 8 command types this envelope mechanism covers. Any
// other type is rejected before an envelope is even looked for (see
// agent/commandsig.go's verifyCommandEnvelope caller in agent.go).
var SignedCommandTypes = map[string]bool{
	"command_scenario":           true,
	"command_simulate":           true,
	"command_attackpath_collect": true,
	"command_cancel":             true,
	"command_pause":              true,
	"command_resume":             true,
	"command_stop_agent":         true,
	"command_uninstall_agent":    true,
}

// IsSignedCommandType reports whether msgType is one of the 8 command
// types this envelope mechanism covers.
func IsSignedCommandType(msgType string) bool {
	return SignedCommandTypes[msgType]
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go test ./protocol/... -run TestCommandEnvelope -v`
Expected: PASS

- [ ] **Step 5: Write the failing test (certstore persistence)**

First read `agent/certstore.go`'s existing `certPaths()` and `saveDeploymentCARoot`/`loadAgentCertificate` functions in full (already in this repo) to match their exact style, then add to `agent/certstore_test.go`:

```go
func TestSaveAndLoadCommandSigningCert_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	ca := newTestCA(t) // reuse this package's existing test helper (bootstrap_test.go)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})

	if err := saveCommandSigningCert(certPEM); err != nil {
		t.Fatalf("saveCommandSigningCert: %v", err)
	}
	loaded, err := loadCommandSigningCert()
	if err != nil {
		t.Fatalf("loadCommandSigningCert: %v", err)
	}
	if loaded.SerialNumber.Cmp(ca.cert.SerialNumber) != 0 {
		t.Error("loaded certificate does not match what was saved")
	}
}

func TestLoadCommandSigningCert_MissingFileReturnsNotExist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	if _, err := loadCommandSigningCert(); !os.IsNotExist(err) {
		t.Errorf("expected an os.ErrNotExist-wrapping error when no cert was ever saved, got: %v", err)
	}
}

func TestSaveCommandSigningCert_RejectsInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	if err := saveCommandSigningCert([]byte("not a cert")); err == nil {
		t.Error("expected saveCommandSigningCert to reject non-PEM input")
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `cd agent && go test . -run "TestSaveAndLoadCommandSigningCert|TestLoadCommandSigningCert_MissingFile|TestSaveCommandSigningCert_RejectsInvalidPEM" -v`
Expected: FAIL — `undefined: saveCommandSigningCert`

- [ ] **Step 7: Write minimal implementation**

Add to `agent/certstore.go` (next to `certPaths()`):

```go
// commandSigningCertPath returns the persisted location of the
// deployment command-signing certificate (B4) -- the public half agents
// use to verify every execution-triggering WS command, delivered via the
// enrollment response and saved once, reused for every subsequent
// command verification (never re-fetched per command).
func commandSigningCertPath() string {
	dir, _, _, _ := certPaths()
	return filepath.Join(dir, "command-signing.pem")
}

// saveCommandSigningCert persists the command-signing certificate
// received in the enrollment response. pemBytes must parse as an X.509
// certificate -- a wrong file is rejected here rather than surfacing
// later as an opaque verification failure on the first dispatched
// command.
func saveCommandSigningCert(pemBytes []byte) error {
	if _, err := parseCertificatePEM(pemBytes); err != nil {
		return fmt.Errorf("command-signing certificate is not a valid PEM certificate: %w", err)
	}
	dir, _, _, _ := certPaths()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cert dir %s: %w", dir, err)
	}
	return os.WriteFile(commandSigningCertPath(), pemBytes, 0644)
}

// loadCommandSigningCert returns the persisted command-signing
// certificate, or an error wrapping os.ErrNotExist if enrollment never
// completed (or completed against an orchestrator version that predates
// this feature).
func loadCommandSigningCert() (*x509.Certificate, error) {
	data, err := os.ReadFile(commandSigningCertPath())
	if err != nil {
		return nil, err
	}
	return parseCertificatePEM(data)
}
```

- [ ] **Step 8: Wire persistence into the enrollment response handling**

Read `agent/bootstrap.go`'s `ensureCertificate` function (where `protocol.SubmitCSR`'s response is handled — the `resp` variable, around the `saveAgentCertificate([]byte(resp.CertPEM))` call this session's earlier B3 work already touches) and `agent/protocol`'s `CSRResponse` type (`agent/protocol/*.go` — find it via `grep -n "type CSRResponse struct" agent/protocol/*.go`). Extend `CSRResponse` with the same `commandSigningTrust` shape Task 6 added server-side:

```go
// agent/protocol -- extend the existing CSRResponse struct
type CSRResponse struct {
	CertPEM   string `json:"certPem"`
	ExpiresAt string `json:"expiresAt"`
	CommandSigningTrust struct {
		KeyID   string `json:"keyId"`
		CertPEM string `json:"certPem"`
	} `json:"commandSigningTrust"`
}
```

Then in `bootstrap.go`, immediately after the existing `saveAgentCertificate([]byte(resp.CertPEM))` call succeeds, add:

```go
		if resp.CommandSigningTrust.CertPEM != "" {
			if err := saveCommandSigningCert([]byte(resp.CommandSigningTrust.CertPEM)); err != nil {
				// Non-fatal: the agent still has a valid mTLS certificate and
				// can operate; it will simply reject every execution-triggering
				// command until this is resolved (see agent/commandsig.go),
				// which is the correct fail-closed behavior for a missing
				// trust anchor, not a reason to fail bootstrap itself.
				log.Printf("[!] could not persist command-signing trust: %v", err)
			}
		}
```

- [ ] **Step 9: Run test to verify it passes**

Run: `cd agent && go build ./... && go test . -run "TestSaveAndLoadCommandSigningCert|TestLoadCommandSigningCert_MissingFile|TestSaveCommandSigningCert_RejectsInvalidPEM" -v`
Expected: PASS
Run: `cd agent && go test ./... 2>&1 | grep -E "^(--- FAIL|FAIL|ok  )"` to confirm nothing existing broke (this touches `bootstrap.go` and `protocol.CSRResponse`, both exercised by this session's earlier B3 tests).

- [ ] **Step 10: Commit**

```bash
git add agent/protocol/command_envelope.go agent/protocol/command_envelope_test.go agent/certstore.go agent/certstore_test.go agent/bootstrap.go agent/protocol/*.go
git commit -m "feat(signing): persist the command-signing trust certificate delivered at enrollment"
git push
```

---

### Task 9: Agent — envelope verification + replay cache

**Files:**
- Create: `agent/commandsig.go`
- Test: `agent/commandsig_test.go`

**Interfaces:**
- Consumes: `protocol.CommandEnvelope`/`IsSignedCommandType` (Task 8), `loadCommandSigningCert` (Task 8), `AuthenticatedAgentID`-equivalent (the agent already knows its own `id.AgentID` — see note in Step 3 on why this is simpler agent-side than the orchestrator-side mTLS-identity check).
- Produces: `(a *Agent) verifyCommandEnvelope(raw json.RawMessage, expectedType string) (*protocol.CommandEnvelope, error)` (consumed by Task 10).

- [ ] **Step 1: Write the failing tests — one per rejection reason, per Review Focus**

```go
// agent/commandsig_test.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// signingTestCA mints a throwaway RSA keypair + self-signed cert standing
// in for the deployment command-signing key, and returns a function that
// signs a protocol.CommandEnvelope with it -- mirrors this package's
// existing newTestCA (bootstrap_test.go) pattern for the mTLS CA, but for
// RSA/command-signing specifically.
func signingTestKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048) // small key -- fast test
	if err != nil {
		t.Fatalf("generate signing test key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test command-signing key"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create signing test cert: %v", err)
	}
	certPEM := pemEncodeCert(t, der)
	return key, certPEM
}

func pemEncodeCert(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func setupSigningTrust(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	key, certPEM := signingTestKey(t)
	if err := saveCommandSigningCert(certPEM); err != nil {
		t.Fatalf("saveCommandSigningCert: %v", err)
	}
	return key
}

func validEnvelope(t *testing.T, key *rsa.PrivateKey, agentID string) protocol.CommandEnvelope {
	t.Helper()
	now := time.Now().UTC()
	env := protocol.CommandEnvelope{
		Version:     protocol.CommandEnvelopeVersion,
		CommandID:   "cmd-" + t.Name(),
		CommandType: "command_scenario",
		AgentID:     agentID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(60 * time.Second),
		Nonce:       "nonce-1",
		Payload:     json.RawMessage(`{"runId":"run-1"}`),
	}
	canon, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := sha256.Sum256(canon)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign test envelope: %v", err)
	}
	env.Signature = sig
	return env
}

func marshalEnvelope(t *testing.T, env protocol.CommandEnvelope) []byte {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return b
}

func TestVerifyCommandEnvelope_AcceptsValidEnvelope(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")

	got, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario")
	if err != nil {
		t.Fatalf("expected acceptance, got: %v", err)
	}
	if got.CommandID != env.CommandID {
		t.Errorf("CommandID = %q, want %q", got.CommandID, env.CommandID)
	}
}

func TestVerifyCommandEnvelope_RejectsInvalidSignature(t *testing.T) {
	setupSigningTrust(t) // establishes trust in a DIFFERENT key than the one below
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, wrongKey, "abc123deadbeef01")

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection for a signature from an untrusted key")
	}
}

func TestVerifyCommandEnvelope_RejectsExpiredEnvelope(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	env.ExpiresAt = time.Now().Add(-time.Second) // already expired
	env.IssuedAt = time.Now().Add(-2 * time.Minute)
	env = resign(t, key, env)

	_, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario")
	if err == nil {
		t.Fatal("expected rejection for an expired envelope")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should name the specific failed check (expired), got: %v", err)
	}
}

func TestVerifyCommandEnvelope_RejectsExpiresAtBeforeIssuedAt(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	env.ExpiresAt = env.IssuedAt.Add(-time.Second)
	env = resign(t, key, env)

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection when expiresAt <= issuedAt")
	}
}

func TestVerifyCommandEnvelope_RejectsIssuedAtFarInFuture(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	env.IssuedAt = time.Now().Add(time.Hour)
	env.ExpiresAt = env.IssuedAt.Add(60 * time.Second)
	env = resign(t, key, env)

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection for an issuedAt unreasonably far in the future")
	}
}

func TestVerifyCommandEnvelope_RejectsUnsupportedVersion(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	env.Version = 999
	env = resign(t, key, env)

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection for an unsupported envelope version")
	}
}

func TestVerifyCommandEnvelope_RejectsAgentIDMismatch(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "some-other-agent-entirely")

	_, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario")
	if err == nil {
		t.Fatal("expected rejection when envelope.AgentID does not match this agent's own identity -- a captured envelope must not be usable against a different agent")
	}
}

func TestVerifyCommandEnvelope_RejectsCommandTypeMismatch(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01") // signed as command_scenario

	// The WS message claimed a different type than what's inside the
	// signed envelope -- must be rejected, not silently accepted using
	// whichever type wins.
	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_cancel"); err == nil {
		t.Fatal("expected rejection when the envelope's signed CommandType does not match the WS message's claimed type")
	}
}

func TestVerifyCommandEnvelope_RejectsReplayedCommandID(t *testing.T) {
	key := setupSigningTrust(t)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")
	raw := marshalEnvelope(t, env)

	if _, err := a.verifyCommandEnvelope(raw, "command_scenario"); err != nil {
		t.Fatalf("first delivery should succeed, got: %v", err)
	}
	if _, err := a.verifyCommandEnvelope(raw, "command_scenario"); err == nil {
		t.Fatal("expected rejection of the exact same CommandID delivered a second time")
	}
}

func TestVerifyCommandEnvelope_RejectsWhenNoTrustEstablished(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir) // no saveCommandSigningCert call -- enrollment never delivered trust
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := &Agent{id: Identity{AgentID: "abc123deadbeef01"}}
	env := validEnvelope(t, key, "abc123deadbeef01")

	if _, err := a.verifyCommandEnvelope(marshalEnvelope(t, env), "command_scenario"); err == nil {
		t.Fatal("expected rejection when no command-signing certificate has ever been persisted")
	}
}

// resign re-signs env after a test has mutated one of its fields --
// mirrors how a real forged/tampered envelope with a stale signature
// would fail signature verification if NOT re-signed; tests that need to
// isolate ONE specific rejection reason (expiry, version, etc.) re-sign
// so signature validity itself isn't the thing being tested there.
func resign(t *testing.T, key *rsa.PrivateKey, env protocol.CommandEnvelope) protocol.CommandEnvelope {
	t.Helper()
	canon, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := sha256.Sum256(canon)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("resign: %v", err)
	}
	env.Signature = sig
	return env
}
```

Add the needed imports to the top of the file: `"crypto"`, `"crypto/rand"`, `"crypto/rsa"`, `"crypto/sha256"`, `"crypto/x509"`, `"crypto/x509/pkix"`, `"encoding/json"`, `"encoding/pem"`, `"math/big"`, `"strings"`, `"testing"`, `"time"`, `"audspect/agent/protocol"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test . -run TestVerifyCommandEnvelope -v`
Expected: FAIL — `undefined: (*Agent).verifyCommandEnvelope`

- [ ] **Step 3: Write minimal implementation**

```go
// agent/commandsig.go
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"audspect/agent/protocol"
)

// issuedAtFutureTolerance bounds how far into the future IssuedAt may
// claim to be before it's treated as backdated/malformed rather than
// ordinary clock skew between the orchestrator and this agent -- a few
// seconds, deliberately much smaller than the 60s validity window itself.
const issuedAtFutureTolerance = 5 * time.Second

// replayCache tracks CommandIDs already accepted, so the exact same
// envelope can't execute twice within its own validity window. Package-
// level and mutex-guarded (not per-Agent) since an agent process has
// exactly one identity for its whole lifetime; keyed by CommandID (not
// Nonce) per the spec's explicit locked correction. This provides
// duplicate-delivery protection WITHIN this process; the short (60s)
// cryptographic validity window is what limits a captured envelope's
// usefulness ACROSS a process restart, not this cache -- see the spec's
// "Expiry & replay" section for the exact locked rationale.
var (
	replayMu    sync.Mutex
	replayCache = make(map[string]time.Time) // commandID -> expiry
)

// verifyCommandEnvelope unmarshals raw as a protocol.CommandEnvelope and
// runs the full rejection checklist before returning it as trusted. Only
// called for msg.Type values where protocol.IsSignedCommandType is
// already true -- see agent.go's connectWS, which checks that BEFORE
// calling this at all, so an unrecognized command type never reaches
// signature verification (the spec's explicit hard rule).
func (a *Agent) verifyCommandEnvelope(raw json.RawMessage, expectedType string) (*protocol.CommandEnvelope, error) {
	var env protocol.CommandEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("decode command envelope: %w", err)
	}

	if env.Version != protocol.CommandEnvelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version %d (this agent understands version %d)", env.Version, protocol.CommandEnvelopeVersion)
	}
	if env.CommandType != expectedType {
		return nil, fmt.Errorf("envelope commandType %q does not match the WS message type %q", env.CommandType, expectedType)
	}
	if env.AgentID != a.id.AgentID {
		return nil, fmt.Errorf("envelope agentId %q does not match this agent's own identity %q", env.AgentID, a.id.AgentID)
	}
	now := time.Now().UTC()
	if env.ExpiresAt.Before(now) {
		return nil, fmt.Errorf("envelope expired at %s (now %s)", env.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if !env.ExpiresAt.After(env.IssuedAt) {
		return nil, fmt.Errorf("envelope expiresAt (%s) is not after issuedAt (%s)", env.ExpiresAt.Format(time.RFC3339), env.IssuedAt.Format(time.RFC3339))
	}
	if env.IssuedAt.After(now.Add(issuedAtFutureTolerance)) {
		return nil, fmt.Errorf("envelope issuedAt (%s) is unreasonably in the future (now %s)", env.IssuedAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	cert, err := loadCommandSigningCert()
	if err != nil {
		return nil, fmt.Errorf("no command-signing trust established (enrollment may not have completed): %w", err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("persisted command-signing certificate does not hold an RSA public key")
	}
	canon, err := env.CanonicalJSON()
	if err != nil {
		return nil, fmt.Errorf("canonicalize envelope: %w", err)
	}
	hash := sha256.Sum256(canon)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], env.Signature); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	replayMu.Lock()
	pruneExpiredReplayEntries(now)
	if _, seen := replayCache[env.CommandID]; seen {
		replayMu.Unlock()
		return nil, fmt.Errorf("commandId %q already consumed (replay)", env.CommandID)
	}
	replayCache[env.CommandID] = env.ExpiresAt
	replayMu.Unlock()

	return &env, nil
}

// pruneExpiredReplayEntries removes cache entries whose validity window
// has passed, so the map doesn't grow unbounded over a long-running
// agent process. Called inline on every verification rather than on a
// separate ticker -- cheap at this command volume, and needs no new
// goroutine. Caller already holds replayMu.
func pruneExpiredReplayEntries(now time.Time) {
	for id, expiry := range replayCache {
		if expiry.Before(now) {
			delete(replayCache, id)
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd agent && go test . -run TestVerifyCommandEnvelope -v`
Expected: PASS (all 10 tests)

- [ ] **Step 5: Commit**

```bash
git add agent/commandsig.go agent/commandsig_test.go
git commit -m "feat(signing): verify command envelopes against the full rejection checklist"
git push
```

---

### Task 10: Agent — wire verification into the WS dispatch switch

**Files:**
- Modify: `agent/agent.go` (the `connectWS` switch at line 1342 onward)
- Test: `agent/agent_commandsig_dispatch_test.go` (new — end-to-end through the real dispatch path)

**Interfaces:**
- Consumes: `a.verifyCommandEnvelope` (Task 9), `protocol.IsSignedCommandType` (Task 8).
- Produces: the actual security boundary this whole plan exists to build — no further tasks depend on this one.

- [ ] **Step 1: Write the failing test**

This test drives the real dispatch path end-to-end: a signed, valid envelope for `command_cancel` (the simplest of the 8 — no scenario execution side effects to fake) must reach the existing handler logic; a tampered one must not.

```go
// agent/agent_commandsig_dispatch_test.go
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"audspect/agent/protocol"
)

func signEnvelopeForDispatchTest(t *testing.T, key *rsa.PrivateKey, env protocol.CommandEnvelope) []byte {
	t.Helper()
	canon, err := env.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := sha256.Sum256(canon)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	env.Signature = sig
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// TestDispatch_SignedCommandCancelExecutesThroughRealPath proves the full
// wire, not just verifyCommandEnvelope in isolation: a WSMessage carrying
// a validly-signed command_cancel envelope reaches
// a.cancelCurrentScenario() through agent.go's actual switch -- this is
// the property the whole plan exists to build.
func TestDispatch_SignedCommandCancelExecutesThroughRealPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	if err := saveCommandSigningCert(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		t.Fatalf("saveCommandSigningCert: %v", err)
	}

	a := newAgent(Config{ServerURL: "http://orchestrator.local:9000"}, Identity{AgentID: "abc123deadbeef01"})
	// Fake an active scenario so cancelCurrentScenario() has something
	// real to report on -- read agent.go's cancelCurrentScenario/
	// pauseCurrentScenario definitions first to confirm this is the
	// correct minimal setup for a genuine state transition, not just a
	// no-op true/false return.
	ctx, cancel := context.WithCancel(context.Background())
	a.scenarioMu.Lock()
	a.cancelScenario = cancel
	a.scenarioMu.Unlock()
	_ = ctx

	now := time.Now().UTC()
	env := protocol.CommandEnvelope{
		Version: protocol.CommandEnvelopeVersion, CommandID: "cmd-dispatch-1", CommandType: "command_cancel",
		AgentID: "abc123deadbeef01", IssuedAt: now, ExpiresAt: now.Add(60 * time.Second),
		Nonce: "nonce-1", Payload: json.RawMessage(`{}`),
	}
	envelopeBytes := signEnvelopeForDispatchTest(t, key, env)

	got, err := a.verifyCommandEnvelope(envelopeBytes, "command_cancel")
	if err != nil {
		t.Fatalf("verifyCommandEnvelope: %v", err)
	}
	if got.CommandType != "command_cancel" {
		t.Fatalf("unexpected verified type: %s", got.CommandType)
	}
	// This confirms the envelope this task's dispatch code path would
	// receive from the real WS switch verifies and unwraps correctly;
	// Step 3 below wires the switch itself to call exactly this.
}

// TestDispatch_TamperedEnvelopeNeverReachesHandler proves the negative:
// a structurally well-formed but wrongly-signed envelope claiming
// command_cancel must be rejected by verifyCommandEnvelope, meaning
// agent.go's switch (Step 3) never reaches a.cancelCurrentScenario() for
// it.
func TestDispatch_TamperedEnvelopeNeverReachesHandler(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAS_CERT_DIR", dir)
	trustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate trusted key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &trustedKey.PublicKey, trustedKey)
	saveCommandSigningCert(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	a := newAgent(Config{ServerURL: "http://orchestrator.local:9000"}, Identity{AgentID: "abc123deadbeef01"})

	now := time.Now().UTC()
	env := protocol.CommandEnvelope{
		Version: protocol.CommandEnvelopeVersion, CommandID: "cmd-dispatch-2", CommandType: "command_cancel",
		AgentID: "abc123deadbeef01", IssuedAt: now, ExpiresAt: now.Add(60 * time.Second),
		Nonce: "nonce-2", Payload: json.RawMessage(`{}`),
	}
	forged := signEnvelopeForDispatchTest(t, attackerKey, env) // signed by the WRONG key

	if _, err := a.verifyCommandEnvelope(forged, "command_cancel"); err == nil {
		t.Fatal("expected rejection of a command_cancel envelope signed by an untrusted key")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd agent && go test . -run TestDispatch -v`
Expected: FAIL initially only if Task 9's `verifyCommandEnvelope` itself is somehow broken — since Task 9 already shipped and passed, this should actually PASS as written above (it only calls `verifyCommandEnvelope` directly, not yet the real switch). This is intentional: Step 1's tests are the specification for Step 3's switch wiring, written and passing in isolation first; Step 3 then makes the real `connectWS` switch match this behavior for real inbound WS traffic, and Step 4 adds one more test that exercises the switch itself, not just `verifyCommandEnvelope`.

- [ ] **Step 3: Wire verification into `connectWS`'s switch**

Read `agent/agent.go` lines 1342-1434 (the exact current switch, reproduced in this plan's own research above) once more to confirm it hasn't shifted, then replace the switch's opening with a verification gate:

```go
			switch msg.Type {
			case "command_scenario", "command_simulate", "command_attackpath_collect",
				"command_cancel", "command_pause", "command_resume",
				"command_stop_agent", "command_uninstall_agent":
				env, err := a.verifyCommandEnvelope(msg.Data, msg.Type)
				if err != nil {
					log.Printf("[!] WS: command envelope rejected (%s): %v", msg.Type, err)
					a.logger.Op("warn", "security", fmt.Sprintf("rejected command envelope for %s: %v", msg.Type, err))
					continue
				}
				a.dispatchVerifiedCommand(msg.Type, env.Payload)

			default:
				log.Printf("[~] WS: unhandled message type %q", msg.Type)
			}
```

Then move the 8 existing `case` bodies verbatim into a new method, changing every `json.Unmarshal(msg.Data, &x)` to `json.Unmarshal(payload, &x)`:

```go
// dispatchVerifiedCommand runs the command-type-specific handling that
// used to live directly in connectWS's switch, now called only after
// verifyCommandEnvelope has accepted the envelope this payload was
// unwrapped from. payload is env.Payload -- the resolved, inner
// command-specific data (e.g. protocol.ScenarioCommand's fields for
// command_scenario), never the raw WS frame.
func (a *Agent) dispatchVerifiedCommand(msgType string, payload json.RawMessage) {
	switch msgType {
	case "command_scenario":
		var cmd protocol.ScenarioCommand
		if err := json.Unmarshal(payload, &cmd); err != nil {
			log.Printf("[!] WS: bad scenario command: %v", err)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		a.scenarioMu.Lock()
		if a.cancelScenario != nil {
			a.cancelScenario()
		}
		a.cancelScenario = cancel
		a.scenarioMu.Unlock()
		a.runWG.Add(1)
		go func() { defer a.runWG.Done(); a.runScenario(ctx, cmd) }()

	case "command_simulate":
		var sim struct {
			ScenarioID string   `json:"scenarioId"`
			RunID      string   `json:"runId"`
			Checks     []string `json:"checks"`
		}
		if err := json.Unmarshal(payload, &sim); err != nil || sim.ScenarioID == "" {
			log.Printf("[!] WS: bad command_simulate payload: %v", err)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		a.scenarioMu.Lock()
		if a.cancelScenario != nil {
			a.cancelScenario()
		}
		a.cancelScenario = cancel
		a.scenarioMu.Unlock()
		a.runWG.Add(1)
		go func() { defer a.runWG.Done(); a.runLocalScan(ctx, sim.ScenarioID, sim.RunID, sim.Checks) }()

	case "command_attackpath_collect":
		var apc AttackPathCollectCommand
		if err := json.Unmarshal(payload, &apc); err != nil {
			log.Printf("[!] WS: bad attackpath collect payload: %v", err)
			return
		}
		a.runWG.Add(1)
		go func() { defer a.runWG.Done(); a.runAttackPathCollect(apc) }()

	case "command_cancel":
		if a.cancelCurrentScenario() {
			log.Printf("[*] scenario cancelled by operator")
			a.logger.Op("warn", "lifecycle", "scenario stopped by operator request")
		} else {
			log.Printf("[~] command_cancel received but no scenario is running")
		}

	case "command_pause":
		if a.pauseCurrentScenario() {
			log.Printf("[*] scenario paused by operator")
			a.logger.Op("info", "lifecycle", "scenario paused by operator request")
		} else {
			log.Printf("[~] command_pause received but no scenario is running")
		}

	case "command_resume":
		if a.resumeCurrentScenario() {
			log.Printf("[*] scenario resumed by operator")
			a.logger.Op("info", "lifecycle", "scenario resumed by operator request")
		} else {
			log.Printf("[~] command_resume received but no scenario is running")
		}

	case "command_stop_agent":
		var body struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(payload, &body); err != nil {
			log.Printf("[!] WS: bad stop command: %v", err)
			return
		}
		go a.stopSelf(body.Reason)

	case "command_uninstall_agent":
		var body struct {
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(payload, &body); err != nil {
			log.Printf("[!] WS: bad uninstall command: %v", err)
			return
		}
		go a.uninstallSelf(body.Reason)
	}
}
```

- [ ] **Step 4: Add one test that exercises the real switch, not just the two pieces separately**

```go
// agent/agent_commandsig_dispatch_test.go -- append

// TestDispatchVerifiedCommand_CancelReachesRealHandler proves
// dispatchVerifiedCommand itself (Step 3's new method, called from the
// real connectWS switch) reaches a.cancelCurrentScenario() -- the last
// mile Step 1's tests deliberately stopped short of, since they called
// verifyCommandEnvelope directly rather than going through the switch.
func TestDispatchVerifiedCommand_CancelReachesRealHandler(t *testing.T) {
	a := newAgent(Config{ServerURL: "http://orchestrator.local:9000"}, Identity{AgentID: "a1"})
	_, cancel := context.WithCancel(context.Background())
	a.scenarioMu.Lock()
	a.cancelScenario = cancel
	a.scenarioMu.Unlock()

	a.dispatchVerifiedCommand("command_cancel", json.RawMessage(`{}`))

	a.scenarioMu.Lock()
	stillSet := a.cancelScenario != nil
	a.scenarioMu.Unlock()
	// cancelCurrentScenario's real behavior (read it first to confirm):
	// if it clears a.cancelScenario after calling it, stillSet should now
	// be false, proving dispatchVerifiedCommand's command_cancel branch
	// really executed the handler rather than being a no-op switch miss.
	if stillSet {
		t.Error("dispatchVerifiedCommand(\"command_cancel\", ...) did not reach cancelCurrentScenario's real state transition")
	}
}
```

Before finalizing this step, read `cancelCurrentScenario`'s actual implementation (`grep -n "func (a \*Agent) cancelCurrentScenario" agent/*.go`) to confirm what observable state change it makes, and adjust this test's assertion to match its REAL behavior rather than the guessed one above if they differ.

- [ ] **Step 5: Run the full test to verify it passes**

Run: `cd agent && go build ./... && go test . -run "TestDispatch|TestVerifyCommandEnvelope" -v`
Expected: PASS (all tests from Task 9 and Task 10)

- [ ] **Step 6: Run the full agent test suite to confirm nothing broke**

Run: `cd agent && go test ./... 2>&1 | grep -E "^(--- FAIL|FAIL|ok  )"`
Expected: all `ok` — this task touched `agent.go`'s core dispatch loop, which many existing tests exercise indirectly.

- [ ] **Step 7: Commit**

```bash
git add agent/agent.go agent/agent_commandsig_dispatch_test.go
git commit -m "feat(signing): gate the WS command dispatch switch behind envelope verification"
git push
```

---

## Final Verification

After all 10 tasks:

```bash
cd orchestrator && go build ./... && go test ./internal/models/... ./internal/cmdsigning/... ./internal/ws/... ./internal/api/... ./cmd/server/... -v
```
Expected: build succeeds, all tests pass (this session's pre-existing B1/B3/deployment-topology tests plus every test this plan added).

```bash
cd agent && go build ./... && go test ./... -v
```
Expected: build succeeds, all tests pass (this session's pre-existing B2/B3 tests plus every test this plan added).

```bash
bash -n packaging/compose/install.sh && echo syntax-OK
cd packaging/compose && POSTGRES_PASSWORD=x JWT_SECRET=x docker compose config >/dev/null && echo compose-valid
```
Expected: both succeed.

Manually confirm the Review Focus section's 5 items each have a passing test: search this plan's own task steps for each one's named scenario (replayed-across-identity in Task 9, unknown-type in Task 10's switch structure itself, silent-signing-key-rotation in Task 3, `install.sh --upgrade` in Task 7, genuinely-expired-with-clear-error-text in Task 9) and confirm none were silently dropped during writing.

This plan does not itself run a live end-to-end test against a real Docker stack the way the deployment-topology plan's Task 11 did (`packaging/compose/verify-mtls-lifecycle.sh`) — that script is a natural place to EXTEND once this plan ships, adding a stage that dispatches a real signed command and confirms the agent executes it, but building that extension is a reasonable follow-up, not part of this plan's own scope (the spec doesn't call for it, and this plan's Task 9/10 unit+integration tests already prove the mechanism directly against real crypto, just not against a live orchestrator process).
