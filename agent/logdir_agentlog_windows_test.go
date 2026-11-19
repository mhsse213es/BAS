//go:build windows

package main

import "testing"

func TestAgentLogDir_IsProgramFilesAudspect(t *testing.T) {
	t.Setenv("ProgramFiles", `D:\Apps`)
	if got := agentLogDir(); got != `D:\Apps\Audspect` {
		t.Errorf("agentLogDir() = %q, want D:Apps/Audspect", got)
	}
	t.Setenv("ProgramFiles", "")
	if got := agentLogDir(); got != `C:\Program Files\Audspect` {
		t.Errorf("agentLogDir() with no ProgramFiles = %q, want C:/Program Files/Audspect", got)
	}
}
