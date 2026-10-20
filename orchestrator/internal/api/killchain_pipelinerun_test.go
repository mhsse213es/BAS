package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

// memRunStore is an in-memory pipelineRunStore. failComplete makes CompletePipelineRun fail,
// modelling a check that ran but whose result could not be written.
type memRunStore struct {
	mu           sync.Mutex
	runs         map[string]db.PipelineRun
	failComplete error
	failRead     error
}

func newMemRunStore() *memRunStore { return &memRunStore{runs: map[string]db.PipelineRun{}} }

func (m *memRunStore) BeginPipelineRun(_ context.Context, r db.PipelineRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.runs[r.ExecutionID]; !ok {
		r.State = db.PipelineRunning
		m.runs[r.ExecutionID] = r
	}
	return nil
}

func (m *memRunStore) CompletePipelineRun(_ context.Context, id string, results []byte, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failComplete != nil {
		return m.failComplete
	}
	r := m.runs[id]
	r.State, r.Results, r.CompletedAt = db.PipelineCompleted, results, at
	m.runs[id] = r
	return nil
}

func (m *memRunStore) PipelineRun(_ context.Context, id string) (db.PipelineRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRead != nil {
		return db.PipelineRun{}, m.failRead
	}
	r, ok := m.runs[id]
	if !ok {
		return db.PipelineRun{}, db.ErrPipelineRunNotFound
	}
	return r, nil
}

func elasticStage(connector string) killchain.StageDef {
	return killchain.StageDef{Key: "ingest", Pipeline: &killchain.PipelineSpec{
		ConnectorID: connector, Index: "logs-*", Field: "event.id", Identifier: "bas-probe-1", LookbackMinutes: 15,
	}}
}

func enabledLoader(baseURL string) pipelineConnectorLoader {
	return func(_ context.Context, id string) (*pipelineConnectorConfig, error) {
		return &pipelineConnectorConfig{ID: id, Provider: "elastic", Enabled: true, BaseURL: baseURL, APIToken: "k"}, nil
	}
}

// A check that completes is persisted, and collecting it reads the persisted result back.
func TestPipelineRunner_StartPersistsThenCollectReadsBack(t *testing.T) {
	es := fakeElastic(t, 200, `{"hits":{"total":{"value":1,"relation":"eq"},"hits":[{"_id":"d1","_source":{"@timestamp":"2026-10-20T09:00:00Z"}}]}}`)
	defer es.Close()
	store := newMemRunStore()
	r := newPipelineStageRunner(store, enabledLoader(es.URL), time.Now)

	execID, err := r.start(context.Background(), "c1", elasticStage("dc-1"))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	ev, done, failed, err := r.collect(context.Background(), execID)
	if err != nil || !done || failed {
		t.Fatalf("collect: done=%v failed=%v err=%v", done, failed, err)
	}
	if len(ev.Pipeline) != len(pipelinePersistStages()) {
		t.Fatalf("persisted stages = %d, want %d", len(ev.Pipeline), len(pipelinePersistStages()))
	}
}

// A completed run is never executed again: starting it again returns the stored result and
// does not touch the connector.
func TestPipelineRunner_CompletedRunIsNotReExecuted(t *testing.T) {
	store := newMemRunStore()
	r := newPipelineStageRunner(store, func(context.Context, string) (*pipelineConnectorConfig, error) {
		t.Fatal("connector loaded for an already completed run")
		return nil, nil
	}, time.Now)
	id := pipelineExecutionID("c1", "ingest")
	_ = store.BeginPipelineRun(context.Background(), db.PipelineRun{ExecutionID: id, CampaignID: "c1", StageKey: "ingest", ConnectorID: "dc-1"})
	_ = store.CompletePipelineRun(context.Background(), id, []byte(`[]`), time.Now())

	if _, err := r.start(context.Background(), "c1", elasticStage("dc-1")); err != nil {
		t.Fatalf("start: %v", err)
	}
}

// A check that ran but could not be persisted is an error, not a pass and not a silent loss.
func TestPipelineRunner_UnpersistedResultIsReportedDistinctly(t *testing.T) {
	es := fakeElastic(t, 200, `{"hits":{"total":{"value":0,"relation":"eq"},"hits":[]}}`)
	defer es.Close()
	store := newMemRunStore()
	store.failComplete = errors.New("connection reset")
	r := newPipelineStageRunner(store, enabledLoader(es.URL), time.Now)

	_, err := r.start(context.Background(), "c1", elasticStage("dc-1"))
	if err == nil || !strings.Contains(err.Error(), "could not be persisted") {
		t.Fatalf("start err = %v, want a not-persisted error", err)
	}
}

// A run that was started but never completed (the process stopped mid-check) is an unknown
// outcome, reported as not done, never as a pass.
func TestPipelineRunner_IncompleteRunIsUnknownNotPass(t *testing.T) {
	store := newMemRunStore()
	id := pipelineExecutionID("c1", "ingest")
	_ = store.BeginPipelineRun(context.Background(), db.PipelineRun{ExecutionID: id, CampaignID: "c1", StageKey: "ingest", ConnectorID: "dc-1"})
	r := newPipelineStageRunner(store, nil, time.Now)

	_, done, failed, err := r.collect(context.Background(), id)
	if err != nil || done || failed {
		t.Fatalf("collect: done=%v failed=%v err=%v, want not done and no error", done, failed, err)
	}
}

// A run with no record at all is an unknown outcome too.
func TestPipelineRunner_MissingRunIsUnknownNotPass(t *testing.T) {
	r := newPipelineStageRunner(newMemRunStore(), nil, time.Now)
	_, done, failed, err := r.collect(context.Background(), "pipeline-c9-ingest")
	if err != nil || done || failed {
		t.Fatalf("collect: done=%v failed=%v err=%v, want not done and no error", done, failed, err)
	}
}

// A read failure is returned as an error so recovery retries later. It is not turned into ERROR.
func TestPipelineRunner_ReadFailureIsRetryable(t *testing.T) {
	store := newMemRunStore()
	store.failRead = errors.New("db unavailable")
	r := newPipelineStageRunner(store, nil, time.Now)
	if _, _, _, err := r.collect(context.Background(), "pipeline-c1-ingest"); err == nil {
		t.Fatal("collect returned no error for a read failure")
	}
}

// A disabled connector is refused before any request is made, with an ERROR stage.
func TestPipelineRunner_DisabledConnectorIsError(t *testing.T) {
	store := newMemRunStore()
	hit := false
	srv := fakeElastic(t, 200, `{}`)
	defer srv.Close()
	r := newPipelineStageRunner(store, func(_ context.Context, id string) (*pipelineConnectorConfig, error) {
		return &pipelineConnectorConfig{ID: id, Provider: "elastic", Enabled: false, BaseURL: srv.URL}, nil
	}, time.Now)
	_ = hit
	execID, err := r.start(context.Background(), "c1", elasticStage("dc-off"))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	ev, _, _, _ := r.collect(context.Background(), execID)
	if got := ev.Pipeline[0]; got.Status != "ERROR" || !strings.Contains(got.Reason, "disabled") {
		t.Fatalf("connectivity = %+v, want ERROR naming the disabled connector", got)
	}
}

var _ = http.StatusOK
