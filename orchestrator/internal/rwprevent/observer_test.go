package rwprevent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/rwdetect"
	"github.com/audspect/bas/internal/rwevidence"
)

type fakeContext struct {
	ac  rwdetect.AttemptContext
	err error
}

func (f fakeContext) AttemptContextFor(_ context.Context, _ rwevidence.AttemptKey) (rwdetect.AttemptContext, error) {
	return f.ac, f.err
}

type fakeBlocks struct {
	blocks []Block
	err    error
	calls  int
	host   string
	start  time.Time
	end    time.Time
}

func (f *fakeBlocks) FindBlocks(_ context.Context, host string, start, end time.Time) ([]Block, error) {
	f.calls++
	f.host, f.start, f.end = host, start, end
	return f.blocks, f.err
}

var executed = time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)

func ctxFor(host string) fakeContext {
	return fakeContext{ac: rwdetect.AttemptContext{HostName: host, ExecutedAt: executed}}
}

// The observer queries exactly the window the rest of the pipeline uses for a
// step's device evidence, and nothing else.
func TestObservePrevention_QueriesHostAndDefaultWindow(t *testing.T) {
	blocks := &fakeBlocks{}
	o := Observer{Blocks: blocks, Context: ctxFor("HOST1"), Window: rwdetect.DefaultWindowPolicy}
	if _, err := o.ObservePrevention(context.Background(), rwevidence.AttemptKey{RunID: "r", TechniqueID: "T1486", Action: "a"}); err != nil {
		t.Fatal(err)
	}
	if blocks.host != "HOST1" {
		t.Fatalf("host = %q", blocks.host)
	}
	if want := executed.Add(-5 * time.Minute); !blocks.start.Equal(want) {
		t.Fatalf("start = %v, want %v", blocks.start, want)
	}
	if want := executed.Add(30 * time.Minute); !blocks.end.Equal(want) {
		t.Fatalf("end = %v, want %v", blocks.end, want)
	}
}

// No host, or no reliable execution time, means no device evidence can be
// attributed. The observer must not query at all, and must return unknown.
func TestObservePrevention_NoHostOrNoTimeIsUnknownWithoutQuerying(t *testing.T) {
	cases := map[string]fakeContext{
		"no host": {ac: rwdetect.AttemptContext{ExecutedAt: executed, HostProblem: "no registration"}},
		"no time": {ac: rwdetect.AttemptContext{HostName: "HOST1", TimeProblem: "ambiguous"}},
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			blocks := &fakeBlocks{}
			o := Observer{Blocks: blocks, Context: ctx, Window: rwdetect.DefaultWindowPolicy}
			obs, err := o.ObservePrevention(context.Background(), rwevidence.AttemptKey{RunID: "r", Action: "a"})
			if err != nil {
				t.Fatal(err)
			}
			if blocks.calls != 0 {
				t.Fatal("must not query device evidence without a host and a reliable time")
			}
			if obs.Outcome != controlval.OutcomeUnknown {
				t.Fatalf("outcome = %q, want unknown", obs.Outcome)
			}
		})
	}
}

func TestObservePrevention_SourceErrorIsReturnedNotGuessed(t *testing.T) {
	boom := errors.New("hunting down")
	o := Observer{Blocks: &fakeBlocks{err: boom}, Context: ctxFor("HOST1"), Window: rwdetect.DefaultWindowPolicy}
	if _, err := o.ObservePrevention(context.Background(), rwevidence.AttemptKey{RunID: "r", Action: "a"}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the source error", err)
	}
}

// Classify is the whole rule. No block event is unknown, never allowed: absence
// of a block does not prove the attack ran. A controlled-folder-access block is
// the documented name and carries High confidence. An Asr* block matches only a
// name pattern, so it carries Medium, and the High-confidence expectation then
// skips it.
func TestClassify(t *testing.T) {
	ck := controlval.CorrelationKey{RunID: "r", Action: "a"}
	cfa := Block{Timestamp: executed, ActionType: "ControlledFolderAccessViolationBlocked"}
	asr := Block{Timestamp: executed, ActionType: "AsrOfficeChildProcessBlocked"}
	other := Block{Timestamp: executed, ActionType: "FileCreated"}

	cases := []struct {
		name   string
		blocks []Block
		want   controlval.Outcome
		conf   controlval.Confidence
	}{
		{"no block event is unknown, not allowed", nil, controlval.OutcomeUnknown, controlval.ConfidenceNone},
		{"non-block action types never count", []Block{other}, controlval.OutcomeUnknown, controlval.ConfidenceNone},
		{"controlled folder access block is blocked with high confidence", []Block{cfa}, controlval.OutcomeBlocked, controlval.ConfidenceHigh},
		{"asr block alone is blocked with medium confidence", []Block{asr}, controlval.OutcomeBlocked, controlval.ConfidenceMedium},
		{"controlled folder access wins over asr", []Block{asr, cfa}, controlval.OutcomeBlocked, controlval.ConfidenceHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := Classify(ck, tc.blocks)
			if obs.Outcome != tc.want || obs.Confidence != tc.conf {
				t.Fatalf("outcome=%q confidence=%q, want %q %q", obs.Outcome, obs.Confidence, tc.want, tc.conf)
			}
			if obs.EvidenceKind != controlval.EvidenceObserved {
				t.Fatalf("evidence kind = %q, want observed", obs.EvidenceKind)
			}
		})
	}
}

// End to end through the shared rule: a controlled-folder-access block passes
// the prevention expectation, an asr-only block is skipped as insufficient, and
// no block is skipped as not recorded or unknown, never a fail.
func TestClassifyThroughEvaluate(t *testing.T) {
	exp := controlval.Expectation{Expected: controlval.OutcomeBlocked, MinConfidence: controlval.ConfidenceHigh}
	ck := controlval.CorrelationKey{RunID: "r", Action: "a"}
	cfa := Block{Timestamp: executed, ActionType: "ControlledFolderAccessViolationBlocked"}
	asr := Block{Timestamp: executed, ActionType: "AsrOfficeChildProcessBlocked"}

	obs := Classify(ck, []Block{cfa})
	if v := controlval.Evaluate(exp, &obs, nil); v.Verdict != controlval.VerdictPass {
		t.Fatalf("cfa block: verdict = %q, want PASS", v.Verdict)
	}
	obs = Classify(ck, []Block{asr})
	if v := controlval.Evaluate(exp, &obs, nil); v.Verdict != controlval.VerdictSkipped || v.SkipReason != controlval.SkipInsufficientEvidence {
		t.Fatalf("asr block: verdict=%q skip=%q, want SKIPPED insufficient_evidence", v.Verdict, v.SkipReason)
	}
	obs = Classify(ck, nil)
	if v := controlval.Evaluate(exp, &obs, nil); v.Verdict == controlval.VerdictFail {
		t.Fatal("no block event must never FAIL: absence is not proof the attack was allowed")
	}
}
