package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// ── signature refusals at the API ─────────────────────────────────────────────

func TestKillChainCreate_UnsignedIs403(t *testing.T) {
	testKillChainKey()
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	body := `{"definition":` + killChainTestDef + `}`
	req := httptest.NewRequest(http.MethodPost, "/api/killchain/campaigns", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.CreateKillChainCampaign(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unsigned definition: status = %d, want 403", rec.Code)
	}
}

func TestKillChainCreate_SignatureMustCoverExactBytes(t *testing.T) {
	priv := testKillChainKey()
	signedFor := strings.Replace(killChainTestDef, `"name":"API chain"`, `"name":"reviewed"`, 1)
	sig := signDefinition(priv, signedFor)
	// The body carries a different definition than the one that was signed.
	body := `{"definition":` + killChainTestDef + `,"signature":"` + sig + `"}`
	if rec := postCreate(body); rec.Code != http.StatusForbidden {
		t.Fatalf("tampered definition: status = %d, want 403", rec.Code)
	}
}

func TestKillChainCreate_WrongKeyIs403(t *testing.T) {
	testKillChainKey()
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"definition":` + killChainTestDef + `,"signature":"` + signDefinition(other, killChainTestDef) + `"}`
	if rec := postCreate(body); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong key: status = %d, want 403", rec.Code)
	}
}

func postCreate(body string) *httptest.ResponseRecorder {
	h := New(nil, ws.NewHub(), scenario.NewEngine(""), "")
	req := httptest.NewRequest(http.MethodPost, "/api/killchain/campaigns", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.CreateKillChainCampaign(rec, req)
	return rec
}

// ── dispatch through the stage executor ───────────────────────────────────────

type fakeDispatch struct {
	runID    string
	skip     string
	err      error
	calls    int
	gotMode  string
	gotAgent string
}

func (f *fakeDispatch) DispatchStage(_ context.Context, _ *scenario.Scenario, agentID string, o stageDispatchOptions) (string, string, error) {
	f.calls++
	f.gotMode = o.Mode
	f.gotAgent = agentID
	return f.runID, f.skip, f.err
}

// resolverOK says every scenario is executable. The scenario it returns is a
// bare value, which is enough for the dispatch seam.
type resolverOK struct{}

func (resolverOK) ResolveExecutable(context.Context, string) (scenario.ExecutableVersion, error) {
	return scenario.ExecutableVersion{Scenario: &scenario.Scenario{ID: "s"}}, nil
}

func dispatchStage() killchain.StageDef {
	return killchain.StageDef{Key: "identity", ScenarioID: "credential-access"}
}

func TestDispatch_StartReturnsTheRunIDAsExecutionID(t *testing.T) {
	fd := &fakeDispatch{runID: "run-42"}
	x := EngineStageExecutor{Resolver: resolverOK{}, AgentID: "agent-1", Dispatcher: fd,
		Options: stageDispatchOptions{Mode: "posture"}}
	id, err := x.Start(context.Background(), "c", dispatchStage())
	if err != nil || id != "run-42" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if fd.gotMode != "posture" || fd.gotAgent != "agent-1" {
		t.Fatalf("dispatch got mode=%q agent=%q", fd.gotMode, fd.gotAgent)
	}
}

func TestDispatch_RefusedRunIsAnErrorNotAnExecution(t *testing.T) {
	fd := &fakeDispatch{skip: "agent is busy"}
	x := EngineStageExecutor{Resolver: resolverOK{}, AgentID: "agent-1", Dispatcher: fd}
	_, err := x.Start(context.Background(), "c", dispatchStage())
	if err == nil || !strings.Contains(err.Error(), "agent is busy") {
		t.Fatalf("err = %v, want the skip reason", err)
	}
}

func TestDispatch_DispatchErrorIsReturned(t *testing.T) {
	fd := &fakeDispatch{err: errors.New("agent not connected")}
	x := EngineStageExecutor{Resolver: resolverOK{}, AgentID: "agent-1", Dispatcher: fd}
	if _, err := x.Start(context.Background(), "c", dispatchStage()); err == nil {
		t.Fatalf("a dispatch error must be returned")
	}
}

func TestDispatch_EmptyRunIDIsAnError(t *testing.T) {
	fd := &fakeDispatch{runID: ""}
	x := EngineStageExecutor{Resolver: resolverOK{}, AgentID: "agent-1", Dispatcher: fd}
	if _, err := x.Start(context.Background(), "c", dispatchStage()); err == nil {
		t.Fatalf("a run with no id cannot be collected, so it must be an error")
	}
}

func TestDispatch_NotExecutableNeverDispatches(t *testing.T) {
	fd := &fakeDispatch{runID: "run-1"}
	x := EngineStageExecutor{Resolver: &fakeResolver{}, AgentID: "agent-1", Dispatcher: fd}
	if _, err := x.Start(context.Background(), "c", dispatchStage()); err == nil {
		t.Fatalf("a refused scenario must not dispatch")
	}
	if fd.calls != 0 {
		t.Fatalf("dispatch was called %d times for a refused scenario", fd.calls)
	}
}

func TestDispatch_NoAgentNeverDispatches(t *testing.T) {
	fd := &fakeDispatch{runID: "run-1"}
	x := EngineStageExecutor{Resolver: resolverOK{}, Dispatcher: fd}
	if _, err := x.Start(context.Background(), "c", dispatchStage()); !errors.Is(err, ErrNoAgentBinding) {
		t.Fatalf("err = %v, want ErrNoAgentBinding", err)
	}
	if fd.calls != 0 {
		t.Fatalf("dispatch was called with no agent bound")
	}
}

// Full path through the orchestrator, with an in-memory store: the stage is
// dispatched, the run completes, and the stage is INCONCLUSIVE (never a pass),
// because a completed run proves only that it ran.
func TestDispatch_FullStagePathEndsInconclusiveNotPass(t *testing.T) {
	def := killchain.CampaignDef{ID: "c", Version: 1, Stages: []killchain.StageDef{
		{Key: "identity", ScenarioID: "credential-access"},
	}}
	store := newMemKillChainStore(def)
	x := EngineStageExecutor{
		Resolver:   resolverOK{},
		Runs:       fakeRuns{snap: runSnapshot{ExecutionID: "run-7", Status: "completed"}},
		AgentID:    "agent-1",
		Dispatcher: &fakeDispatch{runID: "run-7"},
		Options:    stageDispatchOptions{Mode: "posture"},
	}
	orch := killchain.Orchestrator{Store: store, Executor: x}
	if _, err := orch.Advance(context.Background(), "c"); err != nil {
		t.Fatal(err)
	}
	got := store.recs["identity"]
	if got.Verdict != killchain.VerdictInconclusive || got.ExecutionID != "run-7" {
		t.Fatalf("stage = %s exec=%q, want INCONCLUSIVE with run-7", got.Verdict, got.ExecutionID)
	}
}

// memKillChainStore is an in-memory store for one campaign.
type memKillChainStore struct {
	def  killchain.CampaignDef
	recs map[string]killchain.StageRecord
}

func newMemKillChainStore(def killchain.CampaignDef) *memKillChainStore {
	return &memKillChainStore{def: def, recs: map[string]killchain.StageRecord{}}
}

func (m *memKillChainStore) Campaign(context.Context, string) (killchain.CampaignRecord, error) {
	cp := killchain.CampaignRecord{ID: m.def.ID, Def: m.def, Stages: map[string]killchain.StageRecord{}}
	for k, v := range m.recs {
		cp.Stages[k] = v
	}
	return cp, nil
}

func (m *memKillChainStore) PutStage(_ context.Context, _ string, sr killchain.StageRecord) error {
	m.recs[sr.Key] = sr
	return nil
}
