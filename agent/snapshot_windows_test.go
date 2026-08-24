//go:build windows

package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestDiffRegistry_NewValue(t *testing.T) {
	key := `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	before := &SystemSnapshot{Files: map[string][]byte{
		"reg:" + key: []byte("    OneDrive    REG_SZ    C:\\OneDrive.exe\n"),
	}}
	after := &SystemSnapshot{Files: map[string][]byte{
		"reg:" + key: []byte("    OneDrive    REG_SZ    C:\\OneDrive.exe\n    Evil    REG_SZ    C:\\evil.exe\n"),
	}}
	want := []string{"registry:" + key + `\Evil`}
	got := diffRegistry(before, after)
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diffRegistry = %v, want %v", got, want)
	}
}

func TestDiffRegistry_KeyMissingFromBeforeSkipped(t *testing.T) {
	key := `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	before := &SystemSnapshot{Files: map[string][]byte{}}
	after := &SystemSnapshot{Files: map[string][]byte{
		"reg:" + key: []byte("    Evil    REG_SZ    C:\\evil.exe\n"),
	}}
	if got := diffRegistry(before, after); len(got) != 0 {
		t.Errorf("diffRegistry = %v, want empty (key absent from before is not a diffable pair)", got)
	}
}

func TestCaptureSnapshotLite_ExcludesFirewallAndHosts(t *testing.T) {
	lite := captureSnapshotLite("test-run")
	if _, ok := lite.Files["firewall"]; ok {
		t.Error("captureSnapshotLite must not capture the firewall dump")
	}
	hostsPath := `C:\Windows\System32\drivers\etc\hosts`
	if _, ok := lite.Files[hostsPath]; ok {
		t.Error("captureSnapshotLite must not capture the hosts file")
	}
}
