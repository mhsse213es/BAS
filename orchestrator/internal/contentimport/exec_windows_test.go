//go:build windows

package contentimport

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The generated commands are run for real: a command that only looks right can still fail on the host.

func runCmd(t *testing.T, line string) (string, int) {
	t.Helper()
	c := exec.Command("cmd.exe")
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: `cmd.exe /d /c ` + line}
	out, err := c.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return string(out), code
}

func TestExec_SigmaProcessStepRunsAsTheNamedImageAndCleansUp(t *testing.T) {
	res := mustGen(t, certutilRule, "")
	out, code := runCmd(t, res.Step.Command)
	if code != 0 || !strings.Contains(out, res.Step.Marker) || !strings.Contains(out, "urlcache -split") {
		t.Fatalf("code=%d out=%q\ncommand: %s", code, out, res.Step.Command)
	}
	dir := filepath.Join(os.TempDir(), "audspect-"+res.Step.Marker)
	if _, err := os.Stat(filepath.Join(dir, "certutil.exe")); err != nil {
		t.Errorf("the harmless copy should exist while the step runs: %v", err)
	}
	if _, code := runCmd(t, res.Step.Cleanup); code != 0 {
		t.Errorf("cleanup failed")
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("cleanup must remove the folder")
	}
}

func TestExec_SigmaFileStepCreatesAndRemovesTheFile(t *testing.T) {
	src := `
title: Locked files
tags: [attack.t1486]
logsource: {product: windows, category: file_event}
detection:
  selection:
    TargetFilename|contains: '\Documents\'
    TargetFilename|endswith: '.locked'
  condition: selection
`
	res := mustGen(t, src, "")
	if !res.Coverage.Emulable {
		t.Fatalf("%+v", res.Coverage)
	}
	if _, code := runCmd(t, res.Step.Command); code != 0 {
		t.Fatalf("command failed: %s", res.Step.Command)
	}
	dir := filepath.Join(os.TempDir(), "audspect-"+res.Step.Marker)
	var found string
	_ = filepath.Walk(dir, func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() && strings.HasSuffix(p, ".locked") && strings.Contains(p, `\Documents\`) {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Errorf("the file with the rule's path and extension was not created under %s", dir)
	}
	runCmd(t, res.Step.Cleanup)
	if _, err := os.Stat(dir); err == nil {
		t.Error("cleanup must remove the folder")
	}
}

func TestExec_YaraStepWritesTheFileAndReportsItPresent(t *testing.T) {
	src := "rule Harmless { meta: attack=\"T1204\" strings: $a = \"audspect-benign-test-string\" condition: $a }"
	rs := gen(t, src, "windows", "")
	st := rs[0].Step
	c := exec.Command("powershell.exe", "-NoProfile", "-Command", st.Command)
	out, err := c.CombinedOutput()
	if err != nil || !strings.Contains(string(out), st.Marker) {
		t.Fatalf("err=%v out=%q", err, out)
	}
	dir := filepath.Join(os.TempDir(), "audspect-"+st.Marker)
	b, rerr := os.ReadFile(filepath.Join(dir, "audspect-"+st.Marker+".bin"))
	if rerr != nil || !strings.Contains(string(b), "audspect-benign-test-string") {
		t.Errorf("file content wrong: %v %q", rerr, b)
	}
	if o, err := exec.Command("powershell.exe", "-NoProfile", "-Command", st.Cleanup).CombinedOutput(); err != nil {
		t.Fatalf("cleanup: %v %s", err, o)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("cleanup must remove the folder")
	}
}

func TestExec_YaraStepReportsABlockWhenTheFileDisappears(t *testing.T) {
	// simulate security software removing the file: delete it during the step's 5 s wait
	src := "rule Harmless { meta: attack=\"T1204\" strings: $a = \"audspect-benign-test-string\" condition: $a }"
	st := gen(t, src, "windows", "")[0].Step
	script := strings.Replace(st.Command, "Start-Sleep -Seconds 5", "Remove-Item $f -Force", 1)
	c := exec.Command("powershell.exe", "-NoProfile", "-Command", script)
	out, err := c.CombinedOutput()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 1 || !strings.Contains(string(out), "removed by a security control") {
		t.Errorf("a removed file must be reported as blocked (exit 1): err=%v out=%q", err, out)
	}
	exec.Command("powershell.exe", "-NoProfile", "-Command", st.Cleanup).Run()
}
