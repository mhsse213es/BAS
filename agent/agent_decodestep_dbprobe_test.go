package main

import (
	"testing"

	"audspect/agent/protocol"
)

func TestDecodeStepCopiesDBProbe(t *testing.T) {
	spec := &protocol.DBProbeSpec{ProbeID: "read_roles", Engine: "postgresql"}
	got := decodeStep(protocol.ScenarioStep{TaskID: "t", Executor: "dbprobe", DBProbe: spec})
	if got.DBProbe != spec {
		t.Fatalf("decodeStep dropped DBProbe: %+v", got.DBProbe)
	}
}
