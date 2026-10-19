package phishscope

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// AuditDigest is the audit-safe summary of an allowlist. It lets the audit log show
// that the allowlist changed, and which client IDs it contains, without storing
// user principal names.
type AuditDigest struct {
	// Fingerprint identifies the whole allowlist. It is stable across entry order
	// and letter case, so an unchanged configuration never looks like a change.
	Fingerprint string
	// UserHashes holds one SHA-256 per user entry, sorted. User names are never
	// stored in clear.
	UserHashes []string
	// ClientIDs holds the application IDs in clear, sorted. They identify apps.
	ClientIDs []string
}

// Digest computes the audit summary of s.
func Digest(s Scope) AuditDigest {
	userHashes := make([]string, 0, len(s.Users))
	for _, u := range s.Users {
		sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(u))))
		userHashes = append(userHashes, hex.EncodeToString(sum[:]))
	}
	sort.Strings(userHashes)

	clientIDs := make([]string, 0, len(s.ClientIDs))
	for _, c := range s.ClientIDs {
		clientIDs = append(clientIDs, strings.ToLower(strings.TrimSpace(c)))
	}
	sort.Strings(clientIDs)

	h := sha256.New()
	h.Write([]byte("users:"))
	h.Write([]byte(strings.Join(userHashes, ",")))
	h.Write([]byte("\nclients:"))
	h.Write([]byte(strings.Join(clientIDs, ",")))
	return AuditDigest{
		Fingerprint: hex.EncodeToString(h.Sum(nil)),
		UserHashes:  userHashes,
		ClientIDs:   clientIDs,
	}
}
