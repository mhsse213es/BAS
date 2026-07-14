package detectverify

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/verification"
)

// preWindow/postWindow match internal/siem/correlator.go's tuning exactly —
// no need to invent new SIEM-ingestion-lag numbers for this package.
const (
	preWindow  = 2 * time.Minute
	postWindow = 5 * time.Minute
)

// ScenarioResolver is the slice of the scenario engine VerifyRun needs to
// resolve a run's per-step detection expectations. *scenario.Engine satisfies
// it; kept as an interface so orchestration is testable without a real engine
// (mirrors reporting.ScenarioResolver).
type ScenarioResolver interface {
	Get(id string) (*scenario.Scenario, bool)
	ResolveStepExpectations(step scenario.Step) ([]scenario.ExpectedDetection, []scenario.ProfileRef)
}

// Store is the slice of the Verification Store VerifyRun writes to.
// *verification.Store satisfies it.
type Store interface {
	Attest(ctx context.Context, in verification.AttestInput) (verification.Record, error)
	AddEvidence(ctx context.Context, in verification.EvidenceInput) (verification.Evidence, error)
}

// VerifyRunParams is the input to VerifyRun. The caller (internal/api) loads
// all of this from the database — this package does no I/O beyond the
// connectors and store it is handed.
type VerifyRunParams struct {
	RunID      string
	ScenarioID string
	HostName   string
	HostIP     string
	Results    []models.SimulationResult
	Scenarios  ScenarioResolver
	Store      Store
	Connectors map[string]Connector // keyed by Provider Registry key, e.g. "microsoft_sentinel"
}

// VerifyRunSummary reports what VerifyRun did, for logging/audit.
type VerifyRunSummary struct {
	Checked  int // expectations examined
	Attested int // attestations written
	Errors   int // connector/store errors (no attestation written for that expectation)
}

// VerifyRun resolves every step's api-verified expectations for a run and
// checks each one against its provider's connector, attesting the result.
//
// An expectation is skipped (not counted in Checked) when: the step wasn't
// executed or didn't fail (Pass/Blocked technique produces no alertable
// behaviour — the same rule internal/siem/correlator.go uses), the
// expectation's resolved verification model isn't "api", or no connector is
// configured for its provider.
//
// A connector or store error leaves the expectation exactly as it was before
// — never fabricate a NotDetected verdict.
func VerifyRun(ctx context.Context, p VerifyRunParams) VerifyRunSummary {
	var summary VerifyRunSummary
	if p.Scenarios == nil || p.ScenarioID == "" {
		return summary
	}
	sc, ok := p.Scenarios.Get(p.ScenarioID)
	if !ok {
		return summary
	}

	resultByTech := map[string]models.SimulationResult{}
	for _, r := range p.Results {
		resultByTech[r.Technique.ID] = r
	}

	for _, step := range sc.Steps {
		res, ok := resultByTech[step.TechniqueID]
		if !ok || res.Result != models.ResultFail {
			continue
		}
		exps, _ := p.Scenarios.ResolveStepExpectations(step)
		for _, exp := range exps {
			if scenario.ResolveVerification(exp) != scenario.VerificationAPI {
				continue
			}
			conn, ok := p.Connectors[normalizeProvider(exp.Provider)]
			if !ok {
				continue
			}
			summary.Checked++

			req := VerifyRequest{
				RunID:          p.RunID,
				ExpectationID:  exp.ID,
				TechniqueID:    step.TechniqueID,
				HostName:       p.HostName,
				HostIP:         p.HostIP,
				StepExecutedAt: res.ExecutedAt,
				WindowStart:    res.ExecutedAt.Add(-preWindow),
				WindowEnd:      res.ExecutedAt.Add(time.Duration(res.DurationMs)*time.Millisecond + postWindow),
			}
			result, err := conn.Verify(ctx, req)
			if err != nil {
				summary.Errors++
				log.Printf("[detectverify] run %s expectation %s: %v", p.RunID, exp.ID, err)
				continue
			}

			in := verification.AttestInput{
				RunID:         p.RunID,
				ExpectationID: exp.ID,
				TechniqueID:   step.TechniqueID,
				Domain:        scenario.ResolveDomain(exp),
				Provider:      exp.Provider,
				Source:        verification.SourceAPI,
				VerifiedBy:    "connector:" + exp.Provider,
				Note:          result.InvestigationURL,
			}
			if result.Verdict == VerdictDetected {
				in.Result = verification.ResultDetected
				in.WorkflowState = verification.StateApproved
				if len(result.MatchedAlerts) > 0 {
					in.AlertID = result.MatchedAlerts[0].AlertID
				}
			} else {
				in.Result = verification.ResultNotDetected
				in.WorkflowState = verification.StateNeedsReview
			}

			rec, err := p.Store.Attest(ctx, in)
			if err != nil {
				summary.Errors++
				log.Printf("[detectverify] run %s expectation %s: attest: %v", p.RunID, exp.ID, err)
				continue
			}
			summary.Attested++

			if result.Verdict == VerdictDetected && len(result.MatchedAlerts) > 0 {
				attachMatchedAlertEvidence(ctx, p.Store, rec.ID, exp.Provider, result.MatchedAlerts)
			}
		}
	}
	return summary
}

// attachMatchedAlertEvidence records the connector's matched alerts as JSON
// evidence on the just-written attestation, via the existing SP2 evidence
// system — no schema change needed. Failure here is logged, not fatal: the
// attestation itself already succeeded.
func attachMatchedAlertEvidence(ctx context.Context, store Store, verificationID, provider string, alerts []MatchedAlert) {
	raw, err := json.Marshal(alerts)
	if err != nil {
		return
	}
	if _, err := store.AddEvidence(ctx, verification.EvidenceInput{
		VerificationID:   verificationID,
		OriginalFilename: "connector-alerts.json",
		DisplayFilename:  provider + "-matched-alerts.json",
		MIME:             "application/json",
		UploadedBy:       "connector:" + provider,
		Bytes:            raw,
	}); err != nil {
		log.Printf("[detectverify] verification %s: attach evidence: %v", verificationID, err)
	}
}

func normalizeProvider(key string) string {
	return strings.ToLower(strings.TrimSpace(key))
}
