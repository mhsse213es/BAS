package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/dbsim/dbjobs"
)

func TestDBSimStartStatusMapping(t *testing.T) {
	cases := []struct {
		err  error
		want int
	}{
		{dbjobs.ErrNotPermitted, http.StatusForbidden},
		{dbjobs.ErrBusy, http.StatusConflict},
		{dbjobs.ErrConfirmationRequired, http.StatusBadRequest},
		{dbjobs.ErrInvalidRequest, http.StatusBadRequest},
		{dbjobs.ErrTargetNotReady, http.StatusConflict},
		{dbjobs.ErrAgentOffline, http.StatusServiceUnavailable},
		{fmt.Errorf("something unexpected"), http.StatusInternalServerError},
	}
	for _, c := range cases {
		if got := dbsimStartStatus(c.err); got != c.want {
			t.Errorf("dbsimStartStatus(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

func TestDBSimIngestResultsDecodesProbeAndKeepsAbsentProbeNil(t *testing.T) {
	body := []byte(`{"runId":"r1","agentId":"a1","results":[
		{"taskId":"t1","exitCode":0,"dbProbe":{"rowsRead":4,"errorClass":"credential_unresolved"}},
		{"taskId":"t2","exitCode":1,"dbProbe":null}
	]}`)
	var wire dbsimResultWire
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	got, err := dbsimIngestResults(wire)
	if err != nil {
		t.Fatalf("dbsimIngestResults: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}
	if got[0].DBProbe == nil || got[0].DBProbe.RowsRead != 4 || got[0].DBProbe.ErrorClass != "credential_unresolved" {
		t.Errorf("probe 0 not decoded: %+v", got[0].DBProbe)
	}
	if got[1].DBProbe != nil {
		t.Errorf("null probe must stay nil, got %+v", got[1].DBProbe)
	}
	if got[0].TaskID != "t1" || got[1].ExitCode != 1 {
		t.Errorf("fields not copied: %+v", got)
	}
}

func TestDBSimIngestResultsRejectsMalformedProbe(t *testing.T) {
	body := []byte(`{"results":[{"taskId":"t1","dbProbe":"not an object"}]}`)
	var wire dbsimResultWire
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if _, err := dbsimIngestResults(wire); err == nil {
		t.Fatal("a probe that is not an object must be rejected, not graded as absent")
	}
}

// The offline grace timer lives in the job service, so the reaper must reuse one
// service for its whole life, not build one per tick.
func TestDBSimReaperIsOneServiceForLife(t *testing.T) {
	h := &Handler{}
	a := h.dbsimReaper()
	b := h.dbsimReaper()
	if a == nil || a != b {
		t.Fatal("dbsimReaper must return the same service on every call")
	}
}

func TestDBSimReaperStopsWhenContextIsCancelled(t *testing.T) {
	h := &Handler{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.StartDBSimReaper(ctx, time.Hour) // no tick in this test: only cancellation
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reaper did not stop after its context was cancelled")
	}
}

func TestDBSimSummaryCountsLatestPerPairAndSkipsUndecodable(t *testing.T) {
	good := []byte(`{"schema":1,"scenario":{"id":"dbsim-db01-auth-policy"}}`)
	runs := []db.DBSimRun{
		{ScenarioID: "s1", TargetID: "t1", Report: good},               // newest: counted
		{ScenarioID: "s1", TargetID: "t1", Report: good},               // older run of the same pair: not counted
		{ScenarioID: "s2", TargetID: "t1", Report: []byte(`not json`)}, // undecodable: skipped
		{ScenarioID: "s3", TargetID: "t1", Report: good},               // a second pair: counted
	}
	_, counted, skipped := dbsimSummaryFrom(runs)
	if counted != 2 {
		t.Errorf("pairsCounted = %d, want 2 (one per distinct scenario and target)", counted)
	}
	if skipped != 1 {
		t.Errorf("reportsSkipped = %d, want 1", skipped)
	}
}

type fakeActive struct {
	busy bool
	err  error
}

func (f fakeActive) ActiveForAgent(context.Context, string) (bool, error) { return f.busy, f.err }

// A dbsim job on the agent blocks a normal run; a store error must not be read
// as "not busy".
func TestDBSimAgentBusyBlocksAndFailsClosed(t *testing.T) {
	busy, err := dbsimAgentBusy(context.Background(), fakeActive{busy: true}, "a1")
	if err != nil || !busy {
		t.Errorf("busy agent: busy=%v err=%v, want busy=true err=nil", busy, err)
	}
	busy, err = dbsimAgentBusy(context.Background(), fakeActive{err: errors.New("db down")}, "a1")
	if err == nil {
		t.Errorf("store error must be returned, got busy=%v err=nil", busy)
	}
}
