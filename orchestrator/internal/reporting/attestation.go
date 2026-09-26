package reporting

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── Report tamper-evidence (P0-2) ────────────────────────────────────────────
//
// Reports are compliance deliverables a customer hands to an auditor or a
// regulator, so the recipient must be able to tell whether the document was
// altered after Audspect produced it. Two mechanisms cooperate:
//
//  1. A SHA-256 content digest over the report's canonical bytes. Anyone can
//     recompute it (for the audit pack, with `sha256sum -c MANIFEST.sha256`)
//     to detect casual/accidental modification of any file.
//  2. An HMAC-SHA256 signature over the digest, keyed by a per-deployment
//     secret derived from the orchestrator's JWT secret. This authenticates
//     the digest itself, so the manifest cannot be silently rewritten to match
//     tampered content by anyone without the key. The signing key never leaves
//     the server; verification is done by the platform (see Attestation.Verify)
//     or by anyone the operator shares the key with.
//
// This deliberately reuses the same HMAC-SHA256 primitive the agent-result MAC
// (integrity.VerifyResultMAC) and the exercise evidence chain already rely on,
// rather than introducing RSA signing that would require a private key on the
// server (the product's licensing/scenario RSA keys are verify-only at runtime).

// ToolVersion is the running build's version, set from main at startup so it can
// be stamped into every attestation. Left "dev" for unpackaged builds.
var ToolVersion = "dev"

var (
	_signKeyMu sync.RWMutex
	_signKey   []byte // derived HMAC key; nil ⇒ signing disabled (digests still emitted)
)

// SetSigningSecret derives the report-attestation HMAC key from a per-deployment
// secret (the orchestrator's JWT secret). Called once at startup. When the
// secret is empty, attestations still carry SHA-256 content digests but no HMAC
// signature — integrity checking still works, authentication does not.
//
// The key is derived (HMAC of a fixed label) rather than used directly so the
// report-signing key is domain-separated from token signing: leaking one does
// not reveal the other.
func SetSigningSecret(secret string) {
	_signKeyMu.Lock()
	defer _signKeyMu.Unlock()
	if strings.TrimSpace(secret) == "" {
		_signKey = nil
		return
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("audspect-report-attestation-v1"))
	_signKey = m.Sum(nil)
}

func signingKey() []byte {
	_signKeyMu.RLock()
	defer _signKeyMu.RUnlock()
	return _signKey
}

// SigningEnabled reports whether an HMAC signing key is configured.
func SigningEnabled() bool { return signingKey() != nil }

// Attestation is the tamper-evidence record stamped onto a report.
type Attestation struct {
	ToolVersion   string    `json:"toolVersion"`
	GeneratedAt   time.Time `json:"generatedAt"`
	GeneratedBy   string    `json:"generatedBy"`
	ContentSHA256 string    `json:"contentSha256"`
	Algorithm     string    `json:"algorithm"` // "HMAC-SHA256" | "SHA-256 (unsigned)"
	Signature     string    `json:"signature,omitempty"`
}

// Attest computes the SHA-256 digest of content and, when a signing key is
// configured, an HMAC-SHA256 signature binding the digest, timestamp, generator
// identity and tool version together.
func Attest(content []byte, generatedBy string) Attestation {
	sum := sha256.Sum256(content)
	a := Attestation{
		ToolVersion:   ToolVersion,
		GeneratedAt:   time.Now().UTC(),
		GeneratedBy:   generatedBy,
		ContentSHA256: hex.EncodeToString(sum[:]),
		Algorithm:     "SHA-256 (unsigned)",
	}
	if k := signingKey(); k != nil {
		a.Algorithm = "HMAC-SHA256"
		a.Signature = a.sign(k)
	}
	return a
}

// canonical is the deterministic byte string the signature covers. Field order
// and separator are load-bearing — Verify must reproduce them exactly.
func (a Attestation) canonical() string {
	return strings.Join([]string{
		"audspect-attestation-v1",
		a.ToolVersion,
		a.GeneratedAt.Format(time.RFC3339Nano),
		a.GeneratedBy,
		a.ContentSHA256,
	}, "\n")
}

func (a Attestation) sign(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(a.canonical()))
	return hex.EncodeToString(m.Sum(nil))
}

// Verify recomputes the HMAC signature with the configured key and compares it
// in constant time. Returns false with an error when signing is disabled or the
// attestation carries no signature.
func (a Attestation) Verify() (bool, error) {
	k := signingKey()
	if k == nil {
		return false, fmt.Errorf("report signing disabled (no key configured)")
	}
	if a.Signature == "" {
		return false, fmt.Errorf("attestation carries no signature")
	}
	return hmac.Equal([]byte(a.Signature), []byte(a.sign(k))), nil
}

// Short returns an abbreviated digest for compact display (first 16 hex chars).
func (a Attestation) Short() string {
	if len(a.ContentSHA256) >= 16 {
		return a.ContentSHA256[:16]
	}
	return a.ContentSHA256
}

// ── Audit-pack manifest ──────────────────────────────────────────────────────

// ManifestEntry is one file's path (relative to the pack root) and SHA-256.
type ManifestEntry struct {
	Path   string
	SHA256 string
}

// BuildManifest renders entries as a `sha256sum -c`-compatible file body:
// "<hex>␠␠<path>" per line, sorted by path for deterministic output.
func BuildManifest(entries []ManifestEntry) []byte {
	sorted := make([]ManifestEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	var b strings.Builder
	for _, e := range sorted {
		fmt.Fprintf(&b, "%s  %s\n", e.SHA256, e.Path)
	}
	return []byte(b.String())
}

// SignManifest produces the SIGNATURE.txt body: human-readable provenance, the
// SHA-256 of MANIFEST.sha256 itself, the HMAC signature over that digest (or an
// explicit "unsigned" note), and verification instructions.
func SignManifest(manifest []byte, agent, generatedBy string) []byte {
	att := Attest(manifest, generatedBy)
	var b strings.Builder
	b.WriteString("Audspect BAS — Audit Pack Signature\n")
	b.WriteString("===================================\n\n")
	fmt.Fprintf(&b, "Tool version:   %s\n", att.ToolVersion)
	fmt.Fprintf(&b, "Generated at:   %s\n", att.GeneratedAt.Format(time.RFC3339))
	if generatedBy != "" {
		fmt.Fprintf(&b, "Generated by:   %s\n", generatedBy)
	}
	if agent != "" {
		fmt.Fprintf(&b, "Subject:        %s\n", agent)
	}
	fmt.Fprintf(&b, "\nMANIFEST.sha256 digest (SHA-256):\n  %s\n", att.ContentSHA256)
	fmt.Fprintf(&b, "\nSignature algorithm: %s\n", att.Algorithm)
	if att.Signature != "" {
		fmt.Fprintf(&b, "Signature:\n  %s\n", att.Signature)
	} else {
		b.WriteString("Signature:\n  (unsigned — orchestrator report signing key not configured)\n")
	}
	b.WriteString(`
Verification
------------
1. Integrity of the files in this pack:
     cd into this folder and run:  sha256sum -c MANIFEST.sha256
   Every file must report "OK". A mismatch or missing file means the pack was
   altered after generation.

2. Authenticity of MANIFEST.sha256 itself:
   The signature above is an HMAC-SHA256 over the SHA-256 digest of
   MANIFEST.sha256, keyed by this Audspect deployment's report-signing key.
   Ask the issuing Audspect operator to verify it, or submit this pack to the
   Audspect console's report-verification endpoint. Only the issuing deployment
   can reproduce a valid signature.

Classification: CONFIDENTIAL — For authorized use only.
`)
	return []byte(b.String())
}
