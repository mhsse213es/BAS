package adefficacy

import (
	"context"
	"errors"
	"testing"

	"github.com/audspect/bas/internal/controlval"
)

func TestParseDRSUAPIResult_NegativeStageRefused(t *testing.T) {
	got, ok := ParseDRSUAPIResult("EXEC T1003.006: replication request as the rights-less principal was refused (access denied), as expected of the control. [BAS-SIM-DCSYNC-NEG]")
	if !ok || got != DRSUAPIAccessDenied {
		t.Fatalf("got %q, %v; want DRSUAPIAccessDenied, true", got, ok)
	}
}

func TestParseDRSUAPIResult_NegativeStageControlFailedToRefuse(t *testing.T) {
	got, ok := ParseDRSUAPIResult("EXEC T1003.006: replication request as the rights-less principal returned account data -- the control did NOT refuse it. [BAS-SIM-DCSYNC-NEG]")
	if !ok || got != DRSUAPISucceeded {
		t.Fatalf("got %q, %v; want DRSUAPISucceeded, true", got, ok)
	}
}

func TestParseDRSUAPIResult_PositiveStageSucceeded(t *testing.T) {
	got, ok := ParseDRSUAPIResult("EXEC T1003.006: replication request as the rights-holding principal returned account data, as expected when the control correctly honours granted rights. [BAS-SIM-DCSYNC-POS]")
	if !ok || got != DRSUAPISucceeded {
		t.Fatalf("got %q, %v; want DRSUAPISucceeded, true", got, ok)
	}
}

func TestParseDRSUAPIResult_PositiveStageUnexpectedlyRefused(t *testing.T) {
	got, ok := ParseDRSUAPIResult("EXEC T1003.006: replication request as the rights-holding principal was refused despite the granted rights -- unexpected, check the grant landed. [BAS-SIM-DCSYNC-POS]")
	if !ok || got != DRSUAPIAccessDenied {
		t.Fatalf("got %q, %v; want DRSUAPIAccessDenied, true", got, ok)
	}
}

func TestParseDRSUAPIResult_InconclusiveIsIndeterminate(t *testing.T) {
	for _, s := range []string{
		"EXEC T1003.006: replication request as the rights-less principal returned no data; outcome inconclusive. [BAS-SIM-DCSYNC-NEG]",
		"EXEC T1003.006: replication request as the rights-less principal errored without a clear refusal signal (RPC server unavailable); outcome inconclusive. [BAS-SIM-DCSYNC-NEG]",
	} {
		got, ok := ParseDRSUAPIResult(s)
		if !ok || got != DRSUAPIIndeterminate {
			t.Fatalf("%q: got %q, %v; want DRSUAPIIndeterminate, true", s, got, ok)
		}
	}
}

func TestParseDRSUAPIResult_SkipIsNotFound(t *testing.T) {
	for _, s := range []string{
		"SKIP T1003.006: no local lab configuration found at C:\\ProgramData\\Audspect\\lab\\dcsync-verification.json. [BAS-SIM-DCSYNC-NEG]",
		"SKIP T1003.006: the DSInternals PowerShell module is not installed on this host. [BAS-SIM-DCSYNC-POS]",
		"",
		"some unrelated step output",
	} {
		_, ok := ParseDRSUAPIResult(s)
		if ok {
			t.Fatalf("%q: got ok=true, want false (skip/unrecognized must never be guessed into a result)", s)
		}
	}
}

type fakeStepDetailsLookup struct {
	details map[string]string // key: runID + "/" + action
}

func (f fakeStepDetailsLookup) DetailsFor(_ context.Context, runID, action string) (string, bool, error) {
	d, ok := f.details[runID+"/"+action]
	return d, ok, nil
}

func TestAgentOutputDecisionSource_Decision_NegativeRefused(t *testing.T) {
	src := &AgentOutputDecisionSource{Lookup: fakeStepDetailsLookup{details: map[string]string{
		"r1/dcsync-negative": "EXEC T1003.006: replication request as the rights-less principal was refused (access denied), as expected of the control. [BAS-SIM-DCSYNC-NEG]",
	}}}
	got, err := src.Decision(context.Background(), controlval.CorrelationKey{RunID: "r1", Action: "dcsync-negative"})
	if err != nil {
		t.Fatal(err)
	}
	if got.DRSUAPI != DRSUAPIAccessDenied || !got.Correlated {
		t.Fatalf("got %+v, want AccessDenied/correlated", got)
	}
}

func TestAgentOutputDecisionSource_Decision_NoStoredResultIsIndeterminateUncorrelated(t *testing.T) {
	src := &AgentOutputDecisionSource{Lookup: fakeStepDetailsLookup{details: map[string]string{}}}
	got, err := src.Decision(context.Background(), controlval.CorrelationKey{RunID: "r1", Action: "dcsync-positive"})
	if err != nil {
		t.Fatal(err)
	}
	if got.DRSUAPI != DRSUAPIIndeterminate || got.Correlated {
		t.Fatalf("got %+v, want Indeterminate/uncorrelated", got)
	}
}

func TestAgentOutputDecisionSource_Decision_LookupErrorPropagates(t *testing.T) {
	src := &AgentOutputDecisionSource{Lookup: erroringLookup{}}
	if _, err := src.Decision(context.Background(), controlval.CorrelationKey{RunID: "r1", Action: "dcsync-positive"}); err == nil {
		t.Fatal("expected lookup error to propagate")
	}
}

type erroringLookup struct{}

func (erroringLookup) DetailsFor(context.Context, string, string) (string, bool, error) {
	return "", false, errors.New("db down")
}
