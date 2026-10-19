package api

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// phishingGraphPermissions is the set of Microsoft Graph application permissions
// each identity scenario is approved to request. It is documentation in code. The
// approver recorded each entry in docs/phishing-graph-permission-review.md.
//
// Declaring a permission here does not grant it, and does not enable a scenario.
// The gate in graphReviewPending keeps PH-ID-002 and PH-ID-003 unavailable until
// their target filters and live behavior are verified.
//
// PH-ID-005 declares nothing. Its $select permission is not yet verified.
var phishingGraphPermissions = map[string][]string{
	// Directory.Read.All: approved for the reviewed, read-only consent-grant list.
	// Broad. The exposure is accepted and documented in the review.
	"PH-ID-002": {"Directory.Read.All"},
	// AuditLog.Read.All: least privileged for listing sign-ins.
	// Policy.Read.ConditionalAccess: approved for the Conditional Access evidence
	// the Blocked objective needs. Missing evidence stays inconclusive.
	"PH-ID-003": {"AuditLog.Read.All", "Policy.Read.ConditionalAccess"},
	"PH-ID-005": nil,
}

// phishingGraphPermissionsFingerprint identifies the declared permission set, so a
// change to it is recorded in the same audit trail as an allowlist change.
func phishingGraphPermissionsFingerprint() string {
	ids := make([]string, 0, len(phishingGraphPermissions))
	for id := range phishingGraphPermissions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, id := range ids {
		perms := append([]string(nil), phishingGraphPermissions[id]...)
		sort.Strings(perms)
		b.WriteString(id + "=" + strings.Join(perms, ",") + ";")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
