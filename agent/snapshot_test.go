package main

import (
	"io"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

// TestHelperProcess lets the test binary itself act as an external command,
// so the snapCmdRun/snapCmdRunStdin tests below don't depend on any real
// system binary being present or behaving the same across
// Windows/Linux/macOS -- the standard os/exec self-reinvocation pattern.
// A no-op during a normal `go test` run: only does anything when the guard
// env var is set, which the tests below set only on the child process they
// spawn via snapCmdRun(os.Args[0], ...).
func TestHelperProcess(t *testing.T) {
	if os.Getenv("SNAPCMD_HELPER_PROCESS") != "1" {
		return
	}
	switch os.Getenv("SNAPCMD_HELPER_MODE") {
	case "sleep":
		time.Sleep(10 * time.Second)
	case "succeed":
		// no-op, exit 0
	case "echo_stdin_check":
		data, _ := io.ReadAll(os.Stdin)
		if string(data) != "expected-payload" {
			os.Exit(1)
		}
	}
	os.Exit(0)
}

// TestSnapCmdRun_TimesOutOnHungCommand proves the timeout mechanism actually
// kills a hung child rather than merely being present in the code -- without
// it, revertFromSnapshot's mutation calls could block the scenario run from
// ever submitting its final result (see cmdTimeout's doc comment).
func TestSnapCmdRun_TimesOutOnHungCommand(t *testing.T) {
	orig := cmdTimeout
	cmdTimeout = 150 * time.Millisecond
	defer func() { cmdTimeout = orig }()

	os.Setenv("SNAPCMD_HELPER_PROCESS", "1")
	os.Setenv("SNAPCMD_HELPER_MODE", "sleep")
	defer os.Unsetenv("SNAPCMD_HELPER_PROCESS")
	defer os.Unsetenv("SNAPCMD_HELPER_MODE")

	start := time.Now()
	err := snapCmdRun(os.Args[0], "-test.run=TestHelperProcess")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("snapCmdRun() error = nil, want a timeout error for a command that outlives cmdTimeout")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("snapCmdRun() took %v, want it bounded near cmdTimeout (150ms), not the helper's full 10s sleep -- the timeout did not actually kill the child", elapsed)
	}
}

func TestSnapCmdRun_SucceedsForFastCommand(t *testing.T) {
	os.Setenv("SNAPCMD_HELPER_PROCESS", "1")
	os.Setenv("SNAPCMD_HELPER_MODE", "succeed")
	defer os.Unsetenv("SNAPCMD_HELPER_PROCESS")
	defer os.Unsetenv("SNAPCMD_HELPER_MODE")

	if err := snapCmdRun(os.Args[0], "-test.run=TestHelperProcess"); err != nil {
		t.Fatalf("snapCmdRun() error = %v, want nil for a command that exits 0 well within the timeout", err)
	}
}

func TestSnapCmdRunStdin_PassesStdinToChild(t *testing.T) {
	os.Setenv("SNAPCMD_HELPER_PROCESS", "1")
	os.Setenv("SNAPCMD_HELPER_MODE", "echo_stdin_check")
	defer os.Unsetenv("SNAPCMD_HELPER_PROCESS")
	defer os.Unsetenv("SNAPCMD_HELPER_MODE")

	if err := snapCmdRunStdin(os.Args[0], []byte("expected-payload"), "-test.run=TestHelperProcess"); err != nil {
		t.Fatalf("snapCmdRunStdin() error = %v, want nil -- helper verifies it received the exact stdin payload", err)
	}
}

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

// A file that did not exist at capture and does exist afterwards is a created
// artifact -- a dropped /etc/ld.so.preload, a planted authorized_keys, a new
// LaunchAgent plist. diffSnapshots skipped these entirely, so they never
// reached the cleanup verdict and a run that leaked one still read as clean.
func TestDiffSnapshots_NewlyCreatedFileIsReported(t *testing.T) {
	before := newSnapshot("r")
	after := newSnapshot("r")
	after.Files["/etc/ld.so.preload"] = []byte("/tmp/evil.so\n")

	diff := diffSnapshots(before, after)
	if len(diff) != 1 || diff[0] != "/etc/ld.so.preload" {
		t.Fatalf("diff = %v, want the created file reported", diff)
	}
}

// A file present before and removed afterwards must not be reported as a
// created artifact, and must not crash the diff.
func TestDiffSnapshots_RemovedFileIsNotReportedAsCreated(t *testing.T) {
	before := newSnapshot("r")
	before.Files["/etc/rc.local"] = []byte("original")
	after := newSnapshot("r")

	if diff := diffSnapshots(before, after); len(diff) != 0 {
		t.Fatalf("diff = %v, want empty: a removed file is not a created artifact", diff)
	}
}

// The POSIX persistence categories added for snapshot parity must normalize
// the same way the existing ones do, or they are captured and then silently
// dropped at diff time.
func TestDiffSnapshots_POSIXPersistenceCategories(t *testing.T) {
	before := newSnapshot("r")
	after := newSnapshot("r")
	after.Lists["launch_items"] = []string{"/Library/LaunchDaemons/com.evil.plist"}
	after.Lists["systemd_units"] = []string{"/etc/systemd/system/evil.timer"}
	after.Lists["autostart"] = []string{"/home/asha/.config/autostart/evil.desktop"}
	after.Lists["at_jobs"] = []string{"12"}

	diff := diffSnapshots(before, after)
	want := map[string]bool{
		"launch:/Library/LaunchDaemons/com.evil.plist":        true,
		"unit:/etc/systemd/system/evil.timer":                 true,
		"autostart:/home/asha/.config/autostart/evil.desktop": true,
		"atjob:12": true,
	}
	if len(diff) != len(want) {
		t.Fatalf("diff = %v, want %d entries", diff, len(want))
	}
	for _, d := range diff {
		if !want[d] {
			t.Errorf("unexpected normalized key %q", d)
		}
	}
}
