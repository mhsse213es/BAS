package phishbridge

import (
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// FromIdentityContainment translates a real
// phishidentity.RevocationResult -- RevokeAndVerifySignInSessions' own
// dispatch-then-independently-verify evidence (closing this bridge's
// own previously-documented gap: there used to be no real verification
// observer here, mirroring internal/rwevidence.ContainmentObserver's
// same limitation) -- into phishval's Response dimension for PH-IR-002.
//
// result.DispatchErr non-nil (Graph rejected the revoke call outright)
// grades ResponseFailed. RevocationNotVerified -- the re-read(s)
// succeeded but the marker never advanced -- is itself a confirmed
// negative finding and also grades ResponseFailed, never a softer
// verdict. RevocationUnknown with no DispatchErr (the baseline or every
// post-revocation read itself failed -- permissions, throttling, a
// transient fault) returns a nil Observation: genuinely inconclusive,
// never fabricated as either Contained or Failed. Only
// RevocationVerified grades ResponseContained -- and even then, the
// Detail text preserves the exact caveat RevocationVerified's own doc
// comment names: a verified marker advance is strong evidence the
// revocation took effect, never proof every already-issued access
// token became unusable immediately.
func FromIdentityContainment(result phishidentity.RevocationResult, observedAt time.Time) phishval.Observation {
	if result.DispatchErr != nil {
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseFailed, ActionRequired: "revoke-sign-in-sessions", Timestamp: observedAt,
			Source: "entra-id", Evidence: phishval.EvidenceControlReceipt, Confidence: phishval.ConfidenceHigh,
			Detail: "dispatch rejected: " + result.DispatchErr.Error(),
		}}
	}
	switch result.Verification {
	case phishidentity.RevocationVerified:
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseContained, ActionRequired: "revoke-sign-in-sessions", Timestamp: observedAt,
			Source: "entra-id", Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			Detail: result.Detail + " -- confirms the revocation marker changed, not that every already-issued access token is immediately unusable",
		}}
	case phishidentity.RevocationNotVerified:
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseFailed, ActionRequired: "revoke-sign-in-sessions", Timestamp: observedAt,
			Source: "entra-id", Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			Detail: result.Detail,
		}}
	default: // phishidentity.RevocationUnknown
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
