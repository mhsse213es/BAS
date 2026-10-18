package phishbridge

import (
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// ContainmentVerification is whether a dispatched identity-containment
// action (RevokeSignInSessions) was independently confirmed to have
// taken effect -- mirrors internal/rwevidence.ContainmentObserver's own
// shape and reasoning exactly, one layer up for identity rather than
// endpoint isolation: "dispatching an isolate command proves only the
// vendor API accepted the request, not that containment happened." No
// real observer ships here either, for the same reason rwevidence's own
// doesn't: verifying a session is truly revoked needs a real tenant
// sign-in attempt or audit-log check this package cannot simulate.
type ContainmentVerification string

const (
	ContainmentVerificationConfirmed     ContainmentVerification = "confirmed"
	ContainmentVerificationFailed        ContainmentVerification = "failed"
	ContainmentVerificationIndeterminate ContainmentVerification = "indeterminate"
)

// FromIdentityContainment translates a RevokeSignInSessions dispatch
// outcome plus an optional independent verification into phishval's
// Response dimension for PH-IR-002. dispatchErr non-nil (Graph rejected
// or never accepted the call) grades ResponseFailed outright. A nil
// verification (dispatch succeeded, but nothing independently confirmed
// it) returns a nil Observation -- NEVER fabricated as Contained merely
// because Graph returned 2xx, the exact gap this function exists to
// close. Only an explicit ContainmentVerificationConfirmed/Failed value
// produces a graded Response.
func FromIdentityContainment(dispatchErr error, verification *ContainmentVerification, observedAt time.Time) phishval.Observation {
	if dispatchErr != nil {
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseFailed, ActionRequired: "revoke-sign-in-sessions", Timestamp: observedAt,
			Source: "entra-id", Evidence: phishval.EvidenceControlReceipt, Confidence: phishval.ConfidenceHigh,
			Detail: "dispatch rejected: " + dispatchErr.Error(),
		}}
	}
	if verification == nil {
		return phishval.Observation{}
	}
	switch *verification {
	case ContainmentVerificationConfirmed:
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseContained, ActionRequired: "revoke-sign-in-sessions", Timestamp: observedAt,
			Source: "entra-id", Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			Detail: "independently verified: session revocation took effect",
		}}
	case ContainmentVerificationFailed:
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseFailed, ActionRequired: "revoke-sign-in-sessions", Timestamp: observedAt,
			Source: "entra-id", Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			Detail: "independently verified: session revocation did NOT take effect -- blast radius unconstrained",
		}}
	default: // ContainmentVerificationIndeterminate or any unrecognized value
		return phishval.Observation{}
	}
}

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
