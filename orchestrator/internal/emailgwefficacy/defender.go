package emailgwefficacy

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/vendors/defender"
)

// DefenderDetectionProvider implements the DetectionEvidenceFor half
// of MailEvidenceProvider against a real Microsoft 365 Defender for
// Office 365 tenant, via Microsoft Graph security alerts
// (internal/vendors/defender.Client.QueryMailAlerts). It does not
// implement EnforcementEvidenceFor -- Phase 3b's still-open blocker,
// docs/emailgw-mastery-qa-log.md item #1 -- so a caller needing a
// full MailEvidenceProvider must pair this with a separate
// enforcement provider (a fixture, until Phase 3b ships a real one).
type DefenderDetectionProvider struct {
	client *defender.Client
}

// NewDefenderDetectionProvider builds a provider from tenant
// credentials. Construction never fails on empty credentials --
// matching defender.New's own behavior -- the real Graph API call
// inside DetectionEvidenceFor is where an invalid tenant/credential
// actually surfaces as an error.
func NewDefenderDetectionProvider(cfg defender.Config) *DefenderDetectionProvider {
	return NewDefenderDetectionProviderFromClient(defender.New(cfg))
}

// NewDefenderDetectionProviderFromClient takes an already-constructed
// defender.Client, so tests can inject one pointed at an httptest
// server (via Client.TokenURL()/BaseURL) without this package needing
// its own HTTP-mocking surface.
func NewDefenderDetectionProviderFromClient(client *defender.Client) *DefenderDetectionProvider {
	return &DefenderDetectionProvider{client: client}
}

// DetectionEvidenceFor queries Graph security alerts in window,
// correlating by msg.Recipient via QueryMailAlerts' own documented,
// provisional substring heuristic -- MailEvidenceProvider's interface
// carries no context.Context, so this uses context.Background()
// internally, the same no-per-call-cancellation shape
// webgwefficacy.CloudflareGatewayPolicyProvider already uses for its
// own context-free PolicyConfigEvidenceProvider interface. An alert
// that exists but doesn't match msg.Recipient is never included --
// over-matching here would be the same "evidence read as something
// it isn't" failure mode emailGW.txt §3 rules out for missing
// evidence, applied to a false-positive correlation instead.
func (p *DefenderDetectionProvider) DetectionEvidenceFor(msg MessageRef, window TimeWindow) ([]DetectionEvidence, error) {
	alerts, err := p.client.QueryMailAlerts(context.Background(), window.Start, window.End, msg.Recipient)
	if err != nil {
		return nil, fmt.Errorf("defender detection evidence: %w", err)
	}
	out := make([]DetectionEvidence, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, DetectionEvidence{
			Message:        msg,
			AlertGenerated: true,
			Product:        "m365-defender-o365",
			Rule:           a.RuleName,
			CorrelationID:  a.ID,
			Timestamp:      a.Timestamp,
			Source:         SourceLive,
			Provenance: Provenance{
				Kind:       ProvenanceObserved,
				Confidence: ConfidenceMedium,
				Basis:      "correlated by a recipient substring match against the Graph alert's raw text; the real mail-evidence field shape is unverified against a live tenant (docs/emailgw-mastery-qa-log.md item #1)",
			},
		})
	}
	return out, nil
}
