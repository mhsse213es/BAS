//go:build linux || darwin

package main

import "testing"

func TestAgentLogDir_IsVarLog(t *testing.T) {
	if got := agentLogDir(); got != "/var/log/bas-agent" {
		t.Errorf("agentLogDir() = %q, want /var/log/bas-agent", got)
	}
}
