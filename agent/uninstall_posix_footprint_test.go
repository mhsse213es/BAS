package main

import (
	"os"
	"path/filepath"
	"testing"
)

func posixFixture(t *testing.T) string {
	root := t.TempDir()
	for _, f := range []string{
		"usr/local/bin/bas-agent",
		"etc/bas-agent/config",             // holds the agent secret
		"etc/bas-agent/dbcred/pg.cred",     // stored database credentials
		"etc/audspect/certs/agent-key.pem", // client identity
		"etc/audspect/certs/agent-cert.pem",
		"etc/audspect/certs/deployment-ca.pem",
		"etc/audspect/certs.replaced-20261024T082304Z/agent-key.pem",
		"etc/audspect-agent/deployment-ca.pem",
		"var/log/bas-agent/agent.log",
		"var/lib/bas-agent/spool/q.json",
		"etc/systemd/system/bas-agent.service",
		"etc/systemd/system/bas-agent.service.d/override.conf",
		"Library/LaunchDaemons/com.audspect.bas-agent.plist",
		"tmp/BASAgent/agent.log",
		// not the agent's: must survive
		"etc/audspect/certs-old-by-an-admin/agent-key.pem",
		"etc/bas-agent-other/keep.txt",
		"var/log/other/keep.log",
		"usr/local/bin/other-tool",
	} {
		mkfile(t, filepath.Join(root, filepath.FromSlash(f)))
	}
	return root
}

func TestCleanPosixFootprint_RemovesEveryTraceAndNothingElse(t *testing.T) {
	root := posixFixture(t)
	rep := cleanPosixFootprint(root, filepath.Join(root, "tmp"), func(string, ...any) {})

	for _, gone := range []string{
		"usr/local/bin/bas-agent", "etc/bas-agent", "etc/audspect/certs", "etc/audspect/certs.replaced-20261024T082304Z",
		"etc/audspect-agent", "var/lib/bas-agent", "etc/systemd/system/bas-agent.service",
		"etc/systemd/system/bas-agent.service.d", "Library/LaunchDaemons/com.audspect.bas-agent.plist", "tmp/BASAgent",
	} {
		if exists(filepath.Join(root, filepath.FromSlash(gone))) {
			t.Errorf("%s was not removed", gone)
		}
	}
	for _, kept := range []string{
		"etc/audspect/certs-old-by-an-admin/agent-key.pem", "etc/bas-agent-other/keep.txt", "var/log/other/keep.log", "usr/local/bin/other-tool",
	} {
		if !exists(filepath.Join(root, filepath.FromSlash(kept))) {
			t.Errorf("%s belongs to someone else and must survive", kept)
		}
	}
	if len(rep.Failed) != 0 || len(rep.Removed) == 0 {
		t.Errorf("report = %+v", rep)
	}
	if rep.Clean() || len(rep.Kept) != 1 {
		t.Errorf("the /etc/audspect folder still holds an administrator's folder and must be reported as kept, not claimed clean: %+v", rep)
	}
}

func TestCleanPosixFootprint_AnEmptyAudspectFolderGoesToo(t *testing.T) {
	root := t.TempDir()
	mkfile(t, filepath.Join(root, "etc", "audspect", "certs", "agent-key.pem"))
	rep := cleanPosixFootprint(root, "", func(string, ...any) {})
	if exists(filepath.Join(root, "etc", "audspect")) || !rep.Clean() {
		t.Errorf("nothing of the agent may remain: %+v", rep)
	}
}

func TestCleanPosixFootprint_OnAMachineWithNothingInstalledIsQuiet(t *testing.T) {
	rep := cleanPosixFootprint(t.TempDir(), "", func(string, ...any) {})
	if len(rep.Removed)+len(rep.Deferred)+len(rep.Failed)+len(rep.Kept) != 0 {
		t.Errorf("report = %+v, want nothing", rep)
	}
}

// An upgrade replaces the agent but must keep its enrolment; the installer asks for that with this variable.
func TestPurgeSkippedWhenTheInstallerReplacesTheAgent(t *testing.T) {
	t.Setenv(keepDataEnv, "1")
	if !keepAgentData() {
		t.Error("BAS_UNINSTALL_KEEP_DATA=1 must make the uninstall keep the agent's data")
	}
	t.Setenv(keepDataEnv, "")
	if keepAgentData() {
		t.Error("a normal uninstall removes everything")
	}
}

func TestCleanPosixFootprint_NeverTouchesAnythingOutsideTheRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mkfile(t, filepath.Join(outside, "etc", "bas-agent", "config"))
	cleanPosixFootprint(root, "", func(string, ...any) {})
	if !exists(filepath.Join(outside, "etc", "bas-agent", "config")) {
		t.Error("a path outside the given root was removed")
	}
	_ = os.Stdout
}

// The diagnostic log is the evidence of why an install or uninstall went wrong, so a normal uninstall keeps it.
func TestCleanPosixFootprint_KeepsTheAgentLogUnlessPurgeIsAsked(t *testing.T) {
	root := posixFixture(t)
	mkfile(t, filepath.Join(root, "var", "log", "bas-agent", "agent.log.1"))
	mkfile(t, filepath.Join(root, "var", "log", "bas-agent", "op_log-2026-10-28.log"))
	cleanPosixFootprint(root, "", func(string, ...any) {})
	for _, kept := range []string{"var/log/bas-agent/agent.log", "var/log/bas-agent/agent.log.1"} {
		if !exists(filepath.Join(root, filepath.FromSlash(kept))) {
			t.Errorf("%s must survive an uninstall", kept)
		}
	}
	if exists(filepath.Join(root, "var", "log", "bas-agent", "op_log-2026-10-28.log")) {
		t.Error("the structured log is agent data and should be removed")
	}

	t.Setenv(purgeLogsEnv, "1")
	root = posixFixture(t)
	cleanPosixFootprint(root, "", func(string, ...any) {})
	if exists(filepath.Join(root, "var", "log", "bas-agent")) {
		t.Error("with BAS_UNINSTALL_PURGE_LOGS=1 the log folder must be removed too")
	}
}
