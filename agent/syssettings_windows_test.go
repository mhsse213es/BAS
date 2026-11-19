//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows/registry"
)

const testSettingsKey = `Software\AudspectUninstallTest`

func cleanTestKey(t *testing.T) {
	t.Helper()
	_ = registry.DeleteKey(registry.CURRENT_USER, testSettingsKey)
}

func TestRegistrySettings_ReadWriteRemoveRoundTrip(t *testing.T) {
	cleanTestKey(t)
	t.Cleanup(func() { cleanTestKey(t) })
	s := registryStore{}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	dw := settingEntry{Root: "HKCU", Key: testSettingsKey, Name: "D", Kind: "dword", Owner: sid}
	st := settingEntry{Root: "HKCU", Key: testSettingsKey, Name: "S", Kind: "string", Owner: sid}

	got, err := s.read(dw)
	if err != nil || got.Existed {
		t.Fatalf("absent value: existed=%v err=%v", got.Existed, err)
	}
	dw.Existed, dw.Dword = true, 7
	st.Existed, st.Str = true, "hello"
	if err := s.write(dw); err != nil {
		t.Fatal(err)
	}
	if err := s.write(st); err != nil {
		t.Fatal(err)
	}
	gd, _ := s.read(dw)
	gs, _ := s.read(st)
	if !gd.Existed || gd.Dword != 7 || !gs.Existed || gs.Str != "hello" {
		t.Fatalf("read back dword=%+v string=%+v", gd, gs)
	}
	if err := s.remove(dw); err != nil {
		t.Fatal(err)
	}
	if again, _ := s.read(dw); again.Existed {
		t.Error("the dword should be gone")
	}
	if err := s.remove(dw); err != nil {
		t.Errorf("removing what is already gone must not be an error: %v", err)
	}
}

func TestRegistrySettings_AnotherUsersHiveIsNeverTouched(t *testing.T) {
	s := registryStore{}
	e := settingEntry{Root: "HKCU", Key: testSettingsKey, Name: "D", Kind: "dword", Owner: "S-1-5-21-1-2-3-9999", Existed: true, Dword: 1}
	if err := s.write(e); err == nil {
		t.Error("a value recorded for another user profile must not be written into this one")
	}
	if err := s.remove(e); err == nil {
		t.Error("a value recorded for another user profile must not be removed from this one")
	}
}

func TestSystemSettingTargets_CoverEveryValueTheSuppressionChanges(t *testing.T) {
	want := map[string]bool{
		"DontShowUI": false, "LoggingDisabled": false, "Auto": false, "DisablePCA": false,
		"AutoEndTasks": false, "HungAppTimeout": false, "WaitToKillAppTimeout": false,
	}
	for _, e := range systemSettingTargets() {
		if _, ok := want[e.Name]; ok {
			want[e.Name] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("%s is changed by suppressSystemDialogs but is not recorded, so an uninstall could not undo it", n)
		}
	}
}
