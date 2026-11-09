//go:build windows

package main

import (
	"strings"
	"testing"
)

// A service a test creates must not outlive the run. Only a user-mode service whose program is not an installed
// product or an OS component is deleted; anything else a run introduces is stopped and disabled, as before.

func TestServiceRemovable_OnlyAUserModeServiceThatIsNotAnInstalledProduct(t *testing.T) {
	qc := func(typ, path string) string {
		return "[SC] QueryServiceConfig SUCCESS\n\nSERVICE_NAME: x\n        TYPE               : " + typ + "\n        START_TYPE         : 3   DEMAND_START\n        BINARY_PATH_NAME   : " + path + "\n"
	}
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"cmd.exe service from a test", qc("10  WIN32_OWN_PROCESS", `C:\Windows\System32\cmd.exe /c calc`), true},
		{"a temp binary", qc("10  WIN32_OWN_PROCESS", `C:\Users\u\AppData\Local\Temp\x.exe`), true},
		{"a kernel driver", qc("1  KERNEL_DRIVER", `\SystemRoot\System32\drivers\x.sys`), false},
		{"a file system driver", qc("2  FILE_SYSTEM_DRIVER", `\??\C:\x.sys`), false},
		{"an installed product", qc("10  WIN32_OWN_PROCESS", `"C:\Program Files\Vendor\svc.exe"`), false},
		{"a 32-bit installed product", qc("10  WIN32_OWN_PROCESS", `"C:\Program Files (x86)\Vendor\svc.exe"`), false},
		{"an OS servicing component", qc("10  WIN32_OWN_PROCESS", `C:\Windows\WinSxS\amd64_x\svc.exe`), false},
		{"a shared svchost group", qc("20  WIN32_SHARE_PROCESS", `C:\Windows\system32\svchost.exe -k netsvcs -p`), false},
		{"unreadable config", "garbage", false},
	}
	for _, c := range cases {
		if got := serviceRemovable(c.out); got != c.want {
			t.Errorf("%s: removable = %v, want %v", c.name, got, c.want)
		}
	}
}

func scCmd(t *testing.T, args ...string) {
	t.Helper()
	if out, err := snapCmd("sc", args...); err != nil {
		t.Skipf("cannot manage services here (not elevated?): sc %v: %v %s", args, err, out)
	}
}

func serviceExists(name string) bool {
	_, err := snapCmd("sc", "query", name)
	return err == nil
}

func TestRevert_RemovesAServiceTheRunCreatedAndLeavesOnesThatWereThere(t *testing.T) {
	const before, during = "AudspectProbeBefore", "AudspectProbeDuring"
	_, _ = snapCmd("sc", "delete", before)
	_, _ = snapCmd("sc", "delete", during)
	scCmd(t, "create", before, "binPath=", `C:\Windows\System32\cmd.exe`, "start=", "demand")
	defer snapCmd("sc", "delete", before)
	defer snapCmd("sc", "delete", during)

	snap := captureSnapshot("svc-test")
	scCmd(t, "create", during, "binPath=", `C:\Windows\System32\cmd.exe /c calc`, "start=", "demand")
	reverted := revertFromSnapshot(snap)

	if serviceExists(during) {
		t.Errorf("the service created during the run is still installed; reverted = %v", reverted)
	}
	if !serviceExists(before) {
		t.Error("a service that existed before the run must not be touched")
	}
	found := false
	for _, r := range reverted {
		if r == "service removed: "+during {
			found = true
		}
	}
	if !found {
		t.Errorf("the removal must be reported, got %v", reverted)
	}
	for _, r := range reverted {
		if strings.Contains(r, before) {
			t.Errorf("nothing may be reported for a pre-existing service: %s", r)
		}
	}
}
