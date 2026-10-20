//go:build !windows

package main

import (
	"time"

	"audspect/agent/protocol"
)

// collectHostEvents has no Security log on this platform. It returns no events with
// no error. The audit state is reported unknown, so the server does not read this
// as "auditing is off".
func collectHostEvents(from, to time.Time, maxEvents int) ([]protocol.HostEventRecord, bool, error) {
	return nil, false, nil
}

func probeAudit() protocol.AuditSnapshot {
	return protocol.AuditSnapshot{ProcessCreation: "unknown", Logon: "unknown"}
}
