// Package integrity — selfintegrity.go
//
// Detects post-installation tampering with the orchestrator's OWN binary,
// distinct from watcher.go's self-baseline comparison (a snapshot taken
// at this process's own startup, which can never catch a binary already
// tampered with before the process starts). This check is anchored
// instead to a signed manifest (SELFINTEGRITY.sha256 + .sig) generated at
// release-build time by packaging/windows-build.ps1's
// Update-OrchestratorAgentArtifacts, on the trusted build host — the
// Docker build itself never has access to the signing key. See
// docs/superpowers/specs/2026-10-18-orchestrator-self-integrity-design.md
// for the full design and the exact state-transition table this file
// implements.
//
// Explicit scope: this detects the on-disk binary differing from what the
// signed release manifest says it should be. It does NOT detect in-
// memory-only tampering that never touches the file on disk, and it
// cannot stop an attacker who controls the host and patches this
// detector itself — it makes tampering visible, not impossible.
package integrity

import (
	"encoding/base64"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
)

// orchestratorManifestExpected is set to "true" via -ldflags
// (-X github.com/audspect/bas/internal/integrity.orchestratorManifestExpected=true)
// ONLY by orchestrator/Dockerfile's builder stage — never by a bare `go
// build`/`go run`/`go test`. This is a build-time marker baked into the
// binary, not a runtime heuristic (path sniffing, env var) that could
// itself be spoofed by whatever placed a tampered binary.
var orchestratorManifestExpected = "false"

// SelfIntegrityExpected reports whether this exact binary was built via
// the release pipeline and must therefore have a SELFINTEGRITY.sha256
// baked in alongside it.
func SelfIntegrityExpected() bool {
	return orchestratorManifestExpected == "true"
}

// SetExpectedForTest overrides SelfIntegrityExpected's result for the
// duration of a test and returns a restore function. orchestratorManifestExpected
// is normally set once, at compile time, via -ldflags by the Docker
// build — tests in OTHER packages (e.g. internal/api's tamper_handlers
// tests) have no other way to exercise the "expected" code path through
// the real, exported CheckSelfIntegrity entry point.
func SetExpectedForTest(expected bool) (restore func()) {
	orig := orchestratorManifestExpected
	if expected {
		orchestratorManifestExpected = "true"
	} else {
		orchestratorManifestExpected = "false"
	}
	return func() { orchestratorManifestExpected = orig }
}

// SelfIntegrityComponent is the tamper_events "path" sentinel for this
// check — a fixed component name, not a filesystem path: os.Executable()'s
// real path is a container-internal detail, not useful to an admin
// reading the alert.
const SelfIntegrityComponent = "orchestrator-binary"

// selfIntegrityManifestKey is the filename SELFINTEGRITY.sha256 lists the
// orchestrator binary's hash under ("<hex sha256>  orchestrator").
const selfIntegrityManifestKey = "orchestrator"

// DefaultManifestPath is where the release build places SELFINTEGRITY.sha256
// (+ .sig) alongside the orchestrator binary in the final image (see
// orchestrator/Dockerfile). Unlike bas.lic's path, this is never
// per-deployment configurable — it is always the same fixed location the
// release pipeline writes to — so callers (main.go's startup gate,
// tamper_handlers.go's acknowledge revalidation) use this constant
// directly rather than threading a configurable path through Handler.
const DefaultManifestPath = "/SELFINTEGRITY.sha256"

// SelfIntegrityOutcome is the result of one self-integrity check.
type SelfIntegrityOutcome string

const (
	SelfIntegrityOK              SelfIntegrityOutcome = "ok"
	SelfIntegrityDisabled        SelfIntegrityOutcome = "disabled"         // not built via the release pipeline — never alerts
	SelfIntegrityCritical        SelfIntegrityOutcome = "critical"         // manifest missing/unsigned/mismatched when expected
	SelfIntegrityInspectionError SelfIntegrityOutcome = "inspection_error" // transient read error, not a verified failure
)

var (
	selfIntegrityMu           sync.Mutex
	selfIntegrityManifestPath string
	selfIntegrityRegistered   bool
)

// RegisterSelfIntegrityManifest records where SELFINTEGRITY.sha256 lives,
// enabling StartWatcher's periodic self-integrity re-check. Call once at
// startup, alongside WatchPaths.
func RegisterSelfIntegrityManifest(manifestPath string) {
	selfIntegrityMu.Lock()
	defer selfIntegrityMu.Unlock()
	selfIntegrityManifestPath = manifestPath
	selfIntegrityRegistered = true
}

// CheckSelfIntegrity hashes the running executable and verifies it
// against the signed manifest at manifestPath (+".sig") using the
// compiled-in key. Records a critical tamper event (via recordTamperDetail
// — the same persistence/broadcast/DispatchBlocked path every other
// tamper type already uses) on any verified failure. Returns
// SelfIntegrityDisabled without touching any file when this binary was
// not built via the release pipeline (SelfIntegrityExpected).
//
// Called both synchronously at startup (before the HTTP listener starts
// accepting connections) and on every StartWatcher tick thereafter.
func CheckSelfIntegrity(pool *pgxpool.Pool, broadcaster TamperBroadcaster, manifestPath string) SelfIntegrityOutcome {
	return checkSelfIntegrity(pool, broadcaster, manifestPath, SelfIntegrityExpected(), CompiledVerifier{})
}

// checkSelfIntegrity is CheckSelfIntegrity with the expected-flag and
// Verifier injectable, so tests exercise the real decision logic against
// a test keypair via Verifier (verifier_test.go's established pattern for
// this package) instead of mutating the global ScenarioPublicKeyPEM.
func checkSelfIntegrity(pool *pgxpool.Pool, broadcaster TamperBroadcaster, manifestPath string, expected bool, v Verifier) SelfIntegrityOutcome {
	exePath, err := os.Executable()
	if err != nil {
		if !expected {
			return SelfIntegrityDisabled
		}
		log.Printf("[integrity] self-integrity: os.Executable: %v", err)
		return SelfIntegrityInspectionError
	}
	return checkSelfIntegrityAgainstExecutable(pool, broadcaster, manifestPath, expected, v, exePath)
}

// checkSelfIntegrityAgainstExecutable is checkSelfIntegrity with the
// executable's path also injectable, since tests cannot make
// os.Executable() point at a fixture file — it always resolves to the
// test binary itself.
func checkSelfIntegrityAgainstExecutable(pool *pgxpool.Pool, broadcaster TamperBroadcaster, manifestPath string, expected bool, v Verifier, exePath string) SelfIntegrityOutcome {
	if !expected {
		return SelfIntegrityDisabled
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Deleting the manifest must never be a way to disable this
			// check — expected is true, so absence is critical, not benign.
			recordTamperDetail(pool, broadcaster, SelfIntegrityComponent, "remove", "critical", map[string]string{
				"outcome": "manifest_missing",
			})
			return SelfIntegrityCritical
		}
		log.Printf("[integrity] self-integrity: read manifest: %v", err)
		return SelfIntegrityInspectionError
	}

	sigRaw, err := os.ReadFile(manifestPath + ".sig")
	if err != nil {
		// Manifest present but unsigned/unreadable signature — cannot be
		// trusted, so this is treated the same as a verification failure,
		// not as "mechanism absent".
		recordTamperDetail(pool, broadcaster, SelfIntegrityComponent, "hash_mismatch", "critical", map[string]string{
			"outcome": "manifest_unsigned",
		})
		return SelfIntegrityCritical
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		recordTamperDetail(pool, broadcaster, SelfIntegrityComponent, "hash_mismatch", "critical", map[string]string{
			"outcome": "manifest_signature_malformed",
		})
		return SelfIntegrityCritical
	}

	verified, verr := v.Verify(manifestBytes, sigBytes)
	if verr != nil || !verified {
		// An unverifiable manifest is itself suspicious — someone may have
		// tampered with the manifest, not just the binary. Treated as
		// compromised, never silently ignored.
		recordTamperDetail(pool, broadcaster, SelfIntegrityComponent, "hash_mismatch", "critical", map[string]string{
			"outcome": "manifest_verification_failed",
		})
		return SelfIntegrityCritical
	}

	expectedHash, ok := parseSelfIntegrityHash(manifestBytes)
	if !ok {
		recordTamperDetail(pool, broadcaster, SelfIntegrityComponent, "remove", "critical", map[string]string{
			"outcome": "manifest_entry_missing",
		})
		return SelfIntegrityCritical
	}

	observedHash, err := hashFile(exePath)
	if err != nil {
		log.Printf("[integrity] self-integrity: hash executable: %v", err)
		return SelfIntegrityInspectionError
	}

	if observedHash != expectedHash {
		recordTamperDetail(pool, broadcaster, SelfIntegrityComponent, "hash_mismatch", "critical", map[string]string{
			"outcome":       "hash_mismatch",
			"expected_hash": expectedHash,
			"observed_hash": observedHash,
		})
		return SelfIntegrityCritical
	}

	return SelfIntegrityOK
}

// parseSelfIntegrityHash extracts the orchestrator binary's hash from a
// SELFINTEGRITY.sha256-format manifest ("<hex sha256>  orchestrator").
// Deliberately NOT built on Manifest/LoadManifest (manifest.go): that
// type's contract treats a missing *file* as "verification disabled, no
// error" for every caller, which is exactly the loophole this check must
// NOT have when expected is true. Re-parsing the already
// signature-verified bytes directly here keeps that distinction solely in
// checkSelfIntegrity.
func parseSelfIntegrityHash(content []byte) (hash string, ok bool) {
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.TrimPrefix(fields[1], "./") == selfIntegrityManifestKey {
			return strings.ToLower(fields[0]), true
		}
	}
	return "", false
}

// checkSelfIntegrityTick is StartWatcher's periodic hook — a no-op until
// RegisterSelfIntegrityManifest has been called.
func checkSelfIntegrityTick(pool *pgxpool.Pool, broadcaster TamperBroadcaster) {
	selfIntegrityMu.Lock()
	registered := selfIntegrityRegistered
	path := selfIntegrityManifestPath
	selfIntegrityMu.Unlock()
	if !registered {
		return
	}
	CheckSelfIntegrity(pool, broadcaster, path)
}
