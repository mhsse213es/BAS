package phishbridge

import (
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// FromOAuthConsentGrants translates a real Graph oauth2PermissionGrants
// listing into phishval's Enforcement dimension for PH-ID-002: the
// "attack" this scenario validates is a malicious or over-permissioned
// application obtaining tenant-wide consent, so the Enforcement
// dimension answers "did such a grant exist, unblocked" --
// EnforcementAllowed when at least one grant is both tenant-wide
// (ConsentType == AllPrincipals) and carries a risky scope,
// EnforcementBlocked when none do. observedAt is the caller-supplied
// collection timestamp -- this function performs no I/O of its own and
// has no clock to read.
func FromOAuthConsentGrants(grants []phishidentity.OAuthConsentGrant, observedAt time.Time) phishval.Observation {
	outcome := phishval.EnforcementBlocked
	detail := "no tenant-wide consent grant carries a risky scope"
	for _, g := range grants {
		if g.IsTenantWideAndRisky() {
			outcome = phishval.EnforcementAllowed
			detail = "tenant-wide consent grant " + g.ID + " for application " + g.ClientID + " carries a risky scope"
			break
		}
	}
	return phishval.Observation{
		Enforcement: &phishval.EnforcementObservation{
			Outcome: outcome, ControlProduct: "entra-id-oauth-consent", Timestamp: observedAt,
			Source: "microsoft-graph-oauth2PermissionGrants", Evidence: phishval.EvidenceControlReceipt,
			Confidence: phishval.ConfidenceHigh, Detail: detail,
		},
	}
}
