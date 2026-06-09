package models

import (
	"encoding/json"
	"testing"
)

func TestRunEventJSONContract(t *testing.T) {
	const in = `{"runId":"r1","seq":7,"type":"completed","taskId":"a1","techniqueId":"T1057","ts":"2026-06-09T16:40:12.512Z","payload":{"verdict":"pass","durationMs":532,"exitCode":0}}`
	var e RunEvent
	if err := json.Unmarshal([]byte(in), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.RunID != "r1" || e.Seq != 7 || e.Type != "completed" || e.TaskID != "a1" || e.TechniqueID != "T1057" {
		t.Fatalf("decoded wrong: %+v", e)
	}
	if v, _ := e.Payload["verdict"].(string); v != "pass" {
		t.Fatalf("payload verdict = %v", e.Payload["verdict"])
	}
}
