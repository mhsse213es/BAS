package protocol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSendHeartbeat_RoundTripsJobProgress(t *testing.T) {
	var gotBody Heartbeat
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(HeartbeatResponse{State: "active"})
	}))
	defer server.Close()

	hb := Heartbeat{
		AgentID: "a1", Status: "scanning",
		CurrentJobID: "job1",
		JobProgress:  HeartbeatJobProgress{Stage: APStageProbing, TargetsCompleted: 3, TargetsTotal: 10, ProgressPercent: 30},
	}
	resp, err := SendHeartbeat(context.Background(), server.Client(), server.URL, "", hb)
	if err != nil {
		t.Fatalf("SendHeartbeat: %v", err)
	}
	if gotBody.JobProgress.Stage != APStageProbing || gotBody.JobProgress.TargetsCompleted != 3 {
		t.Errorf("server received JobProgress = %+v, want Stage=%s TargetsCompleted=3", gotBody.JobProgress, APStageProbing)
	}
	if resp.State != "active" {
		t.Errorf("resp.State = %q, want active", resp.State)
	}
}

func TestSendHeartbeat_ConnectionRefusedReturnsError(t *testing.T) {
	_, err := SendHeartbeat(context.Background(), http.DefaultClient, "http://127.0.0.1:1", "", Heartbeat{})
	if err == nil {
		t.Fatal("SendHeartbeat: want error against an unreachable host, got nil")
	}
}
