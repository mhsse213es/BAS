// Package rwprevent grades the Prevention capability from Defender Advanced
// Hunting device events. It asks whether a block action was recorded on the
// attempt's host during the attempt's window. It never runs an attempt itself.
package rwprevent

import (
	"context"
	"strings"
	"time"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/rwdetect"
	"github.com/audspect/bas/internal/rwevidence"
	"github.com/audspect/bas/internal/vendors/defender"
)

const (
	// ProviderName and SourceName identify this evidence in the verdict record.
	ProviderName = "defender-advanced-hunting"
	SourceName   = "defender:DeviceEvents"

	controlledFolderAccessBlock = "ControlledFolderAccessViolationBlocked"
)

// Block is one device event that recorded a block action.
type Block struct {
	Timestamp  time.Time
	ActionType string
}

// BlockSource returns the block events on a host within a window.
type BlockSource interface {
	FindBlocks(ctx context.Context, host string, start, end time.Time) ([]Block, error)
}

// Observer implements rwevidence.PreventionObserver over a BlockSource.
type Observer struct {
	Blocks  BlockSource
	Context rwdetect.ContextSource
	Window  rwdetect.WindowPolicy
}

// ObservePrevention resolves the attempt's host and time, queries the block
// events for that host and window, and classifies the result.
func (o Observer) ObservePrevention(ctx context.Context, key rwevidence.AttemptKey) (controlval.Observation, error) {
	ac, err := o.Context.AttemptContextFor(ctx, key)
	if err != nil {
		return controlval.Observation{}, err
	}
	ck := controlval.CorrelationKey{RunID: key.RunID, Target: ac.HostName, Action: key.Action}
	if ac.HostName == "" {
		return unknownObservation(ck, "no device host for this attempt: "+ac.HostProblem), nil
	}
	if ac.ExecutedAt.IsZero() || ac.TimeProblem != "" {
		return unknownObservation(ck, "no reliable execution time: "+ac.TimeProblem), nil
	}
	start := ac.ExecutedAt.Add(-o.Window.Before)
	end := ac.ExecutedAt.Add(o.Window.After)
	ck.Window = controlval.TimeWindow{Start: start, End: end}
	blocks, err := o.Blocks.FindBlocks(ctx, ac.HostName, start, end)
	if err != nil {
		return controlval.Observation{}, err
	}
	return Classify(ck, blocks), nil
}

// Classify is the whole Prevention rule. No block event is unknown, never
// allowed, because the absence of a block does not prove the attack ran. A
// controlled-folder-access block carries the documented name and High
// confidence. An Asr* block matches a name pattern only, so it carries Medium,
// and the High-confidence prevention expectation then skips it.
func Classify(ck controlval.CorrelationKey, blocks []Block) controlval.Observation {
	var cfa, asr *Block
	for i := range blocks {
		b := &blocks[i]
		switch {
		case b.ActionType == controlledFolderAccessBlock:
			if cfa == nil {
				cfa = b
			}
		case isASRBlock(b.ActionType):
			if asr == nil {
				asr = b
			}
		}
	}
	switch {
	case cfa != nil:
		return blockedObservation(ck, *cfa, controlval.ConfidenceHigh)
	case asr != nil:
		return blockedObservation(ck, *asr, controlval.ConfidenceMedium)
	default:
		return unknownObservation(ck, "no block event in window; absence does not prove the action was allowed")
	}
}

func isASRBlock(actionType string) bool {
	return strings.HasPrefix(actionType, "Asr") && strings.HasSuffix(actionType, "Blocked")
}

func blockedObservation(ck controlval.CorrelationKey, b Block, conf controlval.Confidence) controlval.Observation {
	return controlval.Observation{
		Key:          ck,
		Provider:     ProviderName,
		Outcome:      controlval.OutcomeBlocked,
		EvidenceKind: controlval.EvidenceObserved,
		Confidence:   conf,
		Source:       SourceName,
		ObservedAt:   b.Timestamp,
		Detail:       "block event " + b.ActionType,
	}
}

func unknownObservation(ck controlval.CorrelationKey, detail string) controlval.Observation {
	return controlval.Observation{
		Key:          ck,
		Provider:     ProviderName,
		Outcome:      controlval.OutcomeUnknown,
		EvidenceKind: controlval.EvidenceObserved,
		Confidence:   controlval.ConfidenceNone,
		Source:       SourceName,
		Detail:       detail,
	}
}

// DefenderSource adapts the Defender client to BlockSource.
type DefenderSource struct {
	Client *defender.Client
}

// FindBlocks implements BlockSource.
func (s DefenderSource) FindBlocks(ctx context.Context, host string, start, end time.Time) ([]Block, error) {
	recs, err := s.Client.FindBlockEvents(ctx, host, start, end)
	if err != nil {
		return nil, err
	}
	out := make([]Block, 0, len(recs))
	for _, r := range recs {
		out = append(out, Block{Timestamp: r.Timestamp, ActionType: r.ActionType})
	}
	return out, nil
}
