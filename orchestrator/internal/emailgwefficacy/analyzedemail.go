package emailgwefficacy

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/vendors/defender"
)

// AnalyzedEmailEvidenceProvider implements the EnforcementEvidenceFor
// half of MailEvidenceProvider against a real Microsoft 365 Defender
// for Office 365 tenant, via Microsoft Graph's
// GET /security/collaboration/analyzedEmails (v1.0, stable -- see
// docs/emailgw-mastery-qa-log.md item #1 for the full sourcing that
// reversed this phase's original PowerShell/certificate-auth
// assumption). It does not implement DetectionEvidenceFor --
// analyzedEmails does carry alertIds/threatTypes, but
// DefenderDetectionProvider already covers detection via the
// alerts_v2 query path, and adding a second, redundant detection path
// here is deferred rather than built speculatively.
type AnalyzedEmailEvidenceProvider struct {
	client *defender.Client
}

// NewAnalyzedEmailEvidenceProvider builds a provider from tenant
// credentials. Construction never fails on empty credentials --
// matching defender.New's own behavior -- the real Graph API call
// inside EnforcementEvidenceFor is where an invalid tenant/credential
// actually surfaces as an error.
func NewAnalyzedEmailEvidenceProvider(cfg defender.Config) *AnalyzedEmailEvidenceProvider {
	return NewAnalyzedEmailEvidenceProviderFromClient(defender.New(cfg))
}

// NewAnalyzedEmailEvidenceProviderFromClient takes an
// already-constructed defender.Client, so tests can inject one
// pointed at an httptest server (via Client.TokenURL()/BaseURL)
// without this package needing its own HTTP-mocking surface --
// mirrors NewDefenderDetectionProviderFromClient exactly.
func NewAnalyzedEmailEvidenceProviderFromClient(client *defender.Client) *AnalyzedEmailEvidenceProvider {
	return &AnalyzedEmailEvidenceProvider{client: client}
}

// EnforcementEvidenceFor queries analyzedEmails in window, correlated
// by msg.Recipient -- the one correlation key Microsoft's own
// documented $filter example confirms (recipientEmailAddress). It
// uses context.Background() internally for the same reason
// DefenderDetectionProvider does: MailEvidenceProvider's interface
// carries no context.Context, matching
// webgwefficacy.PolicyConfigEvidenceProvider's own precedent. A
// record whose delivery action can't be confidently mapped (§
// mapDeliveryAction) is never included -- silently guessing here
// would be the same "evidence read as something it isn't" failure
// mode emailGW.txt §3 rules out for missing evidence.
func (p *AnalyzedEmailEvidenceProvider) EnforcementEvidenceFor(msg MessageRef, window TimeWindow) ([]EnforcementEvidence, error) {
	filter := fmt.Sprintf("recipientEmailAddress eq '%s'", defender.EscapeODataString(msg.Recipient))
	emails, err := p.client.QueryAnalyzedEmails(context.Background(), window.Start, window.End, filter)
	if err != nil {
		return nil, fmt.Errorf("analyzed email enforcement evidence: %w", err)
	}

	out := make([]EnforcementEvidence, 0, len(emails))
	for _, e := range emails {
		action, ok := mapDeliveryAction(e.LatestDeliveryAction, e.LatestDeliveryLocation)
		if !ok {
			// Fall back to the original delivery verdict only when
			// the latest one carries no confident mapping -- latest
			// always wins when it does, per this package's own
			// most-recent-state discipline (providers.go's
			// latestByTimestamp applies to picking among records;
			// this is the analogous choice within one record's two
			// delivery snapshots).
			action, ok = mapDeliveryAction(e.OriginalDeliveryAction, e.OriginalDeliveryLocation)
			if !ok {
				continue
			}
		}
		out = append(out, EnforcementEvidence{
			Message:        msg,
			Action:         action,
			PolicyRule:     e.Policy,
			ControlProduct: "m365-defender-o365",
			Timestamp:      e.LoggedDateTime,
			Source:         SourceLive,
			Provenance: Provenance{
				Kind:       ProvenanceObserved,
				Confidence: ConfidenceHigh,
				Basis:      "Graph analyzedEmails delivery action/location, correlated by recipient address and time window",
			},
		})
	}
	return out, nil
}

// mapDeliveryAction maps Graph's own delivery action/location enum
// values onto emailgwefficacy's canonical ExpectedMailAction
// vocabulary. Returns ok=false for a value this package has no
// confident mapping for (unknown, unknownFutureValue, or empty) --
// the caller must treat that as "no usable evidence" rather than
// guessing, never as a literal unmapped string compared against an
// expectation.
func mapDeliveryAction(action, location string) (string, bool) {
	switch action {
	case "delivered":
		return string(ExpectedDeliver), true
	case "deliveredToJunk":
		// A soft warning action (delivered but moved/flagged), not a
		// full block -- closest fit in this package's vocabulary.
		return string(ExpectedTagWarning), true
	case "blocked":
		if location == "quarantine" {
			return string(ExpectedQuarantine), true
		}
		// Blocked but not placed in quarantine (dropped, failed,
		// others) -- the message never reached any recoverable
		// state, closest fit is reject.
		return string(ExpectedReject), true
	case "replaced":
		// Content was substituted (e.g. a malicious attachment
		// replaced) -- closest fit among this package's six actions;
		// flagged here, not silently assumed precise.
		return string(ExpectedRewrite), true
	default:
		// "unknown", "unknownFutureValue", or empty -- no confident
		// mapping.
		return "", false
	}
}
