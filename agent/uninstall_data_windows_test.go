//go:build windows

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestCleanAgentFootprint_LeavesNoAgentDataAndRestoresRecordedSettings(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ProgramData", filepath.Join(root, "ProgramData"))
	t.Setenv("AppData", filepath.Join(root, "Roaming"))
	t.Setenv("TMP", filepath.Join(root, "Temp"))
	t.Setenv("TEMP", filepath.Join(root, "Temp"))
	pd := filepath.Join(root, "ProgramData")
	install := filepath.Join(root, "Program Files", "BASAgent")

	mkfile(t, filepath.Join(pd, "BASAgent", "api.token"))
	mkfile(t, filepath.Join(pd, "BASAgent", "logs", "op_log-1.log"))
	mkfile(t, filepath.Join(pd, "BASAgent", "spool", "q.json"))
	mkfile(t, filepath.Join(pd, "Audspect", "certs", "agent-key.pem"))
	mkfile(t, filepath.Join(pd, "Audspect", "certs", "agent-cert.pem"))
	mkfile(t, filepath.Join(pd, "Audspect", "certs", "enrollment-state"))
	mkfile(t, filepath.Join(pd, "Audspect", "certs.replaced-20261024T082304Z", "agent-key.pem"))
	mkfile(t, filepath.Join(install, "logs", logFileName))
	mkfile(t, filepath.Join(root, "Roaming", "BASAgent", "logs", logFileName))
	mkfile(t, filepath.Join(root, "Temp", "BASAgent", logFileName))

	// a folder an administrator made, and an unrelated "logs" folder next to a binary run from somewhere else
	mkfile(t, filepath.Join(pd, "Audspect", "certs-old-by-an-admin", "agent-key.pem"))
	downloads := filepath.Join(root, "Downloads")
	mkfile(t, filepath.Join(downloads, "logs", "mine.txt"))

	// a setting the agent changed: it did not exist before, and is recorded as such
	cleanTestKey(t)
	t.Cleanup(func() { cleanTestKey(t) })
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	e := settingEntry{Root: "HKCU", Key: testSettingsKey, Name: "DontShowUI", Kind: "dword", Owner: sid}
	k, _, _ := registry.CreateKey(registry.CURRENT_USER, testSettingsKey, registry.SET_VALUE)
	_ = k.SetDWordValue("DontShowUI", 1)
	k.Close()
	if err := saveSettingsBackup(settingsBackupPath(), []settingEntry{e}); err != nil { // Existed:false
		t.Fatal(err)
	}

	var out []string
	rep := cleanAgentFootprint([]string{install, downloads}, func(f string, a ...any) { out = append(out, f) })

	for _, gone := range []string{
		filepath.Join(pd, "BASAgent"), filepath.Join(pd, "Audspect", "certs"),
		filepath.Join(pd, "Audspect", "certs.replaced-20261024T082304Z"),
		filepath.Join(install, "logs"), filepath.Join(root, "Roaming", "BASAgent"), filepath.Join(root, "Temp", "BASAgent"),
	} {
		if exists(gone) {
			t.Errorf("%s was not removed", gone)
		}
	}
	if !exists(filepath.Join(pd, "Audspect", "certs-old-by-an-admin", "agent-key.pem")) {
		t.Error("an administrator's own folder must survive")
	}
	if !exists(filepath.Join(downloads, "logs", "mine.txt")) {
		t.Error("a logs folder that does not hold the agent's log must never be touched")
	}
	if got, _ := (registryStore{}).read(e); got.Existed {
		t.Error("the setting the agent added was not removed")
	}
	if len(rep.Removed) == 0 || len(rep.Failed) != 0 {
		t.Errorf("report = %+v", rep)
	}
	if len(rep.Kept) != 1 || !strings.HasSuffix(rep.Kept[0], "Audspect") {
		t.Errorf("Kept = %v, want the Audspect folder reported because of the administrator's folder", rep.Kept)
	}
	if rep.Clean() {
		t.Error("with a bystander folder left behind the report must not claim a clean machine")
	}
}

func TestCleanAgentFootprint_OnAMachineWithNothingToRemoveIsQuiet(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ProgramData", filepath.Join(root, "ProgramData"))
	t.Setenv("AppData", filepath.Join(root, "Roaming"))
	t.Setenv("TMP", filepath.Join(root, "Temp"))
	t.Setenv("TEMP", filepath.Join(root, "Temp"))
	rep := cleanAgentFootprint(nil, func(string, ...any) {})
	if len(rep.Removed)+len(rep.Deferred)+len(rep.Failed)+len(rep.Kept) != 0 {
		t.Errorf("report = %+v, want nothing", rep)
	}
}
