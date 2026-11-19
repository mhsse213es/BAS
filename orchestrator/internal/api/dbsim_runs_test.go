package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

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
