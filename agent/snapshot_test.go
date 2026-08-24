package main

import (
	"reflect"
	"sort"
	"testing"
)

func snap(lists map[string][]string, files map[string][]byte) *SystemSnapshot {
	s := newSnapshot("test-run")
	if lists != nil {
		s.Lists = lists
	}
	if files != nil {
		s.Files = files
	}
	return s
}

func sortedDiff(before, after *SystemSnapshot) []string {
	d := diffSnapshots(before, after)
	sort.Strings(d)
	return d
}

func TestDiffSnapshots_EmptyWhenUnchanged(t *testing.T) {
	before := snap(map[string][]string{"tmp_files": {"/tmp/a"}}, nil)
	after := snap(map[string][]string{"tmp_files": {"/tmp/a"}}, nil)
	if d := diffSnapshots(before, after); len(d) != 0 {
		t.Errorf("diffSnapshots = %v, want empty", d)
	}
}

func TestDiffSnapshots_NewTmpFile(t *testing.T) {
	before := snap(map[string][]string{"tmp_files": {"/tmp/a"}}, nil)
	after := snap(map[string][]string{"tmp_files": {"/tmp/a", "/tmp/evil.ps1"}}, nil)
	want := []string{"tmp:/tmp/evil.ps1"}
	if d := sortedDiff(before, after); !reflect.DeepEqual(d, want) {
		t.Errorf("diffSnapshots = %v, want %v", d, want)
	}
}

func TestDiffSnapshots_PreExistingItemsNeverFlagged(t *testing.T) {
	before := snap(map[string][]string{
		"tmp_files": {"/tmp/a", "/tmp/b"},
		"services":  {"Spooler"},
		"schtasks":  {"\\Microsoft\\Windows\\Defrag"},
		"startup":   {"C:\\Startup\\ok.lnk"},
		"cron_dirs": {"/etc/cron.d/logrotate"},
	}, nil)
	after := snap(map[string][]string{
		"tmp_files": {"/tmp/a", "/tmp/b"},
		"services":  {"Spooler"},
		"schtasks":  {"\\Microsoft\\Windows\\Defrag"},
		"startup":   {"C:\\Startup\\ok.lnk"},
		"cron_dirs": {"/etc/cron.d/logrotate"},
	}, nil)
	if d := diffSnapshots(before, after); len(d) != 0 {
		t.Errorf("diffSnapshots = %v, want empty (nothing new)", d)
	}
}

func TestDiffSnapshots_NewServiceSchtaskStartupCron(t *testing.T) {
	before := snap(map[string][]string{}, nil)
	after := snap(map[string][]string{
		"services":  {"EvilSvc"},
		"schtasks":  {"\\Evil\\Task"},
		"startup":   {"C:\\Startup\\evil.lnk"},
		"cron_dirs": {"/etc/cron.d/evil"},
	}, nil)
	want := []string{"cron:/etc/cron.d/evil", "schtask:\\Evil\\Task", "service:EvilSvc", "startup:C:\\Startup\\evil.lnk"}
	if d := sortedDiff(before, after); !reflect.DeepEqual(d, want) {
		t.Errorf("diffSnapshots = %v, want %v", d, want)
	}
}

func TestDiffSnapshots_WholeFileChanged(t *testing.T) {
	before := snap(nil, map[string][]byte{"crontab:user": []byte("0 * * * * old\n")})
	after := snap(nil, map[string][]byte{"crontab:user": []byte("0 * * * * old\n* * * * * evil\n")})
	want := []string{"crontab:user"}
	if d := diffSnapshots(before, after); !reflect.DeepEqual(d, want) {
		t.Errorf("diffSnapshots = %v, want %v", d, want)
	}
}

func TestDiffSnapshots_WholeFileUnchanged(t *testing.T) {
	before := snap(nil, map[string][]byte{"/etc/hosts": []byte("127.0.0.1 localhost\n")})
	after := snap(nil, map[string][]byte{"/etc/hosts": []byte("127.0.0.1 localhost\n")})
	if d := diffSnapshots(before, after); len(d) != 0 {
		t.Errorf("diffSnapshots = %v, want empty", d)
	}
}

func TestDiffSnapshots_UnrecognizedCategoryIgnored(t *testing.T) {
	before := snap(map[string][]string{"future_category": {}}, nil)
	after := snap(map[string][]string{"future_category": {"new-item"}}, nil)
	if d := diffSnapshots(before, after); len(d) != 0 {
		t.Errorf("diffSnapshots = %v, want empty (unrecognized category must be ignored, not panic)", d)
	}
}
