package pipelinecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// InjectionRequest is one test record to write, with the run it belongs to.
type InjectionRequest struct {
	RunID    string
	Index    string
	Document map[string]any
}

// TagDocument returns a copy of doc with the run identifier, the marker field and the marker
// tag added. The caller's document is not modified. It refuses an invalid run identifier.
func TagDocument(doc map[string]any, runID string) (map[string]any, error) {
	if !ValidTestRunID(runID) {
		return nil, fmt.Errorf("refused: test run identifier is not in the server-generated form")
	}
	out := make(map[string]any, len(doc)+2)
	for k, v := range doc {
		out[k] = v
	}
	audspect := map[string]any{}
	if existing, ok := out["audspect"].(map[string]any); ok {
		for k, v := range existing {
			audspect[k] = v
		}
	}
	audspect["test_run"] = runID
	out["audspect"] = audspect
	out["tags"] = []string{MarkerTag}
	return out, nil
}

// PayloadHash is the digest an approval binds to. It is computed over the tagged document, so
// approving a payload and sending a different one cannot match.
func PayloadHash(doc map[string]any) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// InjectionOutcome is what an injector reports. Status is EXECUTED, or NOT_TESTED with a reason.
type InjectionOutcome struct {
	Status string
	Reason string
}

// Injector writes one tagged record to one provider.
type Injector interface {
	// Supported reports whether this injector can write to its provider in this build. The gate
	// checks it before consuming an approval.
	Supported() bool
	Inject(ctx context.Context, req InjectionRequest) (InjectionOutcome, error)
}

// UnsupportedInjector stands in for a provider with no write adapter in this build. It never
// writes. Injection through it is reported as NOT_TESTED.
type UnsupportedInjector struct{ Provider string }

// Supported is always false: no write adapter exists for the provider.
func (u UnsupportedInjector) Supported() bool { return false }

// Inject reports that nothing was written.
func (u UnsupportedInjector) Inject(context.Context, InjectionRequest) (InjectionOutcome, error) {
	return InjectionOutcome{Status: "NOT_TESTED", Reason: fmt.Sprintf("no injection adapter for provider %q in this build; nothing was written", u.Provider)}, nil
}
