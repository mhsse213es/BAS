package emailgwefficacy

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/defender"
)

// successfulInvestigationStates and failedInvestigationStates
// classify a Graph alert's investigationState (Microsoft's published
// v1.0 alert resource enum) into a definitive Response outcome, per
// explicit direction: partiallyRemediated and benign count as
// failure here, not a weaker success -- ResponseEvidence.Completed
// means the required action fully completed, and a controlled test
// fixture built to be malicious is never genuinely benign. Any state
// not listed in either set (running/pendingApproval/pendingResource/
// queued/unknown/unknownFutureValue, or no investigationState
// reported at all) is treated as not yet resolved:
// ResponseEvidenceFor emits nothing for it, which verifyResponse
// reads as Inconclusive, never a fabricated ConfirmedFailure.
var successfulInvestigationStates = map[string]bool{
	"successfullyRemediated": true,
}

var failedInvestigationStates = map[string]bool{
	"partiallyRemediated":   true,
	"benign":                true,
	"terminated":            true,
	"failed":                true,
	"terminatedByUser":      true,
	"terminatedBySystem":    true,
	"preexistingAlert":      true,
	"unsupportedOs":         true,
	"unsupportedAlertType":  true,
	"suppressedAlert":       true,
	"innerFailure":          true,
	"partiallyInvestigated": true,
}

// DefenderDetectionProvider implements the DetectionEvidenceFor and
// ResponseEvidenceFor halves of MailEvidenceProvider against a real
// Microsoft 365 Defender for Office 365 tenant, via Microsoft Graph
// security alerts (internal/vendors/defender.Client.QueryMailAlerts).
// Both read the same underlying alert set -- detection asks whether
// an alert exists at all, response asks what that alert's own
// investigationState resolved to -- so one Graph query backs both
// dimensions. It does not implement EnforcementEvidenceFor -- Phase
// 3b's still-open blocker, docs/emailgw-mastery-qa-log.md item #1 --
// so a caller needing a full MailEvidenceProvider must pair this with
// a separate enforcement provider (a fixture, until Phase 3b ships a
// real one).
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

// DefenderMailEvidenceProvider composes AnalyzedEmailEvidenceProvider
// (enforcement, via analyzedEmails) and DefenderDetectionProvider
// (detection, via alerts_v2) into one full MailEvidenceProvider backed
// entirely by real Microsoft 365 Defender for Office 365 APIs -- the
// live adapter Phase 3's own exit criteria describes, now that both
// halves exist. Both embedded providers share one underlying
// defender.Client (and therefore one token source), since both Graph
// calls use the same graph.microsoft.com/.default scope.
type DefenderMailEvidenceProvider struct {
	*AnalyzedEmailEvidenceProvider
	*DefenderDetectionProvider
}

// NewDefenderMailEvidenceProvider builds the composed provider from
// tenant credentials, same no-fail-on-empty-credentials behavior as
// defender.New.
func NewDefenderMailEvidenceProvider(cfg defender.Config) *DefenderMailEvidenceProvider {
	return NewDefenderMailEvidenceProviderFromClient(defender.New(cfg))
}

// NewDefenderMailEvidenceProviderFromClient takes an
// already-constructed defender.Client, so tests can inject one
// pointed at an httptest server.
func NewDefenderMailEvidenceProviderFromClient(client *defender.Client) *DefenderMailEvidenceProvider {
	return &DefenderMailEvidenceProvider{
		AnalyzedEmailEvidenceProvider: NewAnalyzedEmailEvidenceProviderFromClient(client),
		DefenderDetectionProvider:     NewDefenderDetectionProviderFromClient(client),
	}
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

// ResponseEvidenceFor queries the same Graph security alerts
// DetectionEvidenceFor does, mapping each alert's investigationState
// to a terminal Response outcome via successfulInvestigationStates/
// failedInvestigationStates. An alert whose investigationState is
// still in progress, unset, or unrecognized is excluded entirely --
// not mapped to a placeholder outcome -- so a remediation that
// hasn't resolved yet falls through to verifyResponse's own
// no-evidence-found Inconclusive path.
func (p *DefenderDetectionProvider) ResponseEvidenceFor(msg MessageRef, window TimeWindow) ([]ResponseEvidence, error) {
	alerts, err := p.client.QueryMailAlerts(context.Background(), window.Start, window.End, msg.Recipient)
	if err != nil {
		return nil, fmt.Errorf("defender response evidence: %w", err)
	}
	out := make([]ResponseEvidence, 0, len(alerts))
	for _, a := range alerts {
		completed := successfulInvestigationStates[a.InvestigationState]
		failed := failedInvestigationStates[a.InvestigationState]
		if !completed && !failed {
			continue
		}
		ts := a.ResolvedDateTime
		if ts.IsZero() {
			ts = a.Timestamp
		}
		var duration time.Duration
		if !a.ResolvedDateTime.IsZero() {
			duration = a.ResolvedDateTime.Sub(a.Timestamp)
		}
		out = append(out, ResponseEvidence{
			Message:            msg,
			ActionRequired:     a.InvestigationState,
			Completed:          completed,
			DurationToComplete: duration,
			Timestamp:          ts,
			Source:             SourceLive,
			Provenance: Provenance{
				Kind:       ProvenanceObserved,
				Confidence: ConfidenceMedium,
				Basis:      "correlated by a recipient substring match against the Graph alert's raw text, same provisional heuristic DetectionEvidenceFor uses (docs/emailgw-mastery-qa-log.md item #1); investigationState is read directly from the alert resource's own documented field",
			},
		})
	}
	return out, nil
}
