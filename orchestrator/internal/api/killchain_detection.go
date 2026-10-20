package api

import (
	"context"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/verification"
)

// observationFromVerify reduces one vendor check to a killchain observation.
// The vendor call reports neither telemetry health nor window completeness, so
// neither is ever set here. The verdict engine therefore refuses to score a
// not-detected result until that evidence is supplied elsewhere.
func observationFromVerify(provider string, res detectverify.VerifyResult, err error) killchain.DetectionObservation {
	o := killchain.DetectionObservation{Provider: provider}
	if err != nil {
		o.Verdict = killchain.ObservationError
		return o
	}
	switch res.Verdict {
	case detectverify.VerdictDetected:
		o.Verdict = killchain.ObservationDetected
		if len(res.MatchedAlerts) > 0 {
			o.AlertID = res.MatchedAlerts[0].AlertID
		}
	case detectverify.VerdictNotDetected:
		o.Verdict = killchain.ObservationNotDetected
	default:
		o.Verdict = killchain.ObservationError
	}
	return o
}

// attestationReader is the slice of the verification store that stage
// collection reads. *verification.Store satisfies it.
type attestationReader interface {
	CurrentForRun(ctx context.Context, runID string) (map[string]verification.Record, error)
}

// detectionFromRecords turns a run's attestations into stage detection evidence.
// No attestations gives an inconclusive result, never a not-detected one.
func detectionFromRecords(recs map[string]verification.Record) killchain.DetectionEvidence {
	obs := make([]killchain.DetectionObservation, 0, len(recs))
	for _, rec := range recs {
		obs = append(obs, observationFromRecord(rec))
	}
	return killchain.AggregateDetection(obs)
}

func observationFromRecord(rec verification.Record) killchain.DetectionObservation {
	o := killchain.DetectionObservation{Provider: rec.Provider, AlertID: rec.AlertID}
	switch rec.Result {
	case verification.ResultDetected:
		o.Verdict = killchain.ObservationDetected
	case verification.ResultNotDetected:
		o.Verdict = killchain.ObservationNotDetected
	default:
		o.Verdict = killchain.ObservationError
	}
	return o
}

// groundTruthReader is the slice of the kill-chain store that stage collection
// reads for a run's independent ground truth.
type groundTruthReader interface {
	GroundTruthForRun(ctx context.Context, runID string) (db.GroundTruthRecord, bool, error)
}
