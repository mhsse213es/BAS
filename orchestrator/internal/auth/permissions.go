package auth

import "net/http"

// Permission is a fine-grained capability, decoupled from role. The Verification
// Store (SP2) authorizes on permissions rather than raw roles so a large SOC can
// separate the analyst who verifies from the reviewer who approves, and so
// evidence deletion (accountability-sensitive) is restricted independently.
type Permission string

const (
	CanVerify         Permission = "verification:verify"          // create/update an attestation
	CanUploadEvidence Permission = "verification:evidence:upload" // attach evidence to a verification
	CanDeleteEvidence Permission = "verification:evidence:delete" // soft-delete evidence
	CanReview         Permission = "verification:review"          // approve/reject in the review pipeline
	CanExport         Permission = "verification:export"          // export verification data

	// CVE↔ATT&CK Relationship Store permissions.
	CanCurateThreatIntel Permission = "threatintel:curate" // create/edit relationships + evidence
	CanReviewThreatIntel Permission = "threatintel:review" // promote/demote effective confidence, change lifecycle status
)

// rolePermissions maps each role to the permissions it holds. Viewer is
// read-only and holds none of the verification permissions.
var rolePermissions = map[Role]map[Permission]bool{
	RoleAdmin: {
		CanVerify:            true,
		CanUploadEvidence:    true,
		CanDeleteEvidence:    true,
		CanReview:            true,
		CanExport:            true,
		CanCurateThreatIntel: true,
		CanReviewThreatIntel: true,
	},
	RoleAnalyst: {
		CanVerify:            true,
		CanUploadEvidence:    true,
		CanReview:            true,
		CanExport:            true,
		CanCurateThreatIntel: true,
		// CanDeleteEvidence and CanReviewThreatIntel intentionally withheld —
		// deletion and confidence review are admin-only so a single analyst
		// cannot quietly remove audit material or self-approve their own claim.
	},
	RoleViewer: {},
}

// HasPermission reports whether a role holds a permission.
func HasPermission(role Role, perm Permission) bool {
	return rolePermissions[role][perm]
}

// Permissions returns the full permission set granted to a role, for the client
// to enable/disable controls in the UI.
func Permissions(role Role) []Permission {
	set := rolePermissions[role]
	out := make([]Permission, 0, len(set))
	for _, p := range []Permission{CanVerify, CanUploadEvidence, CanDeleteEvidence, CanReview, CanExport,
		CanCurateThreatIntel, CanReviewThreatIntel} {
		if set[p] {
			out = append(out, p)
		}
	}
	return out
}

// RequirePermission rejects requests whose role lacks the given permission.
func RequirePermission(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFrom(r.Context())
			if !ok || !HasPermission(claims.Role, perm) {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r.WithContext(r.Context()))
		})
	}
}
