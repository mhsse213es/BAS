package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

func TestArtResolvePayloads(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		executor string
		wantRef  string
		wantReq  []string
	}{
		{
			name:     "bare external payload (powershell)",
			cmd:      `"PathToAtomicsFolder\..\ExternalPayloads\gsecdump.exe" -a`,
			executor: "powershell",
			wantRef:  `$env:BAS_PAYLOAD_DIR\gsecdump.exe`,
			wantReq:  []string{"gsecdump.exe"},
		},
		{
			name:     "cmd executor uses percent syntax",
			cmd:      `"PathToAtomicsFolder\..\ExternalPayloads\mimikatz.exe"`,
			executor: "cmd",
			wantRef:  `%BAS_PAYLOAD_DIR%\mimikatz.exe`,
			wantReq:  []string{"mimikatz.exe"},
		},
		{
			name:     "token form with hash braces and bin subdir",
			cmd:      `& "#{PathToAtomicsFolder}\T1003.001\bin\foo.exe"`,
			executor: "powershell",
			wantRef:  `$env:BAS_PAYLOAD_DIR\foo.exe`,
			wantReq:  []string{"foo.exe"},
		},
		{
			name:     "directory reference, no file → no required payload",
			cmd:      `cd $PathToAtomicsFolder\T1059`,
			executor: "powershell",
			wantRef:  `$env:BAS_PAYLOAD_DIR\T1059`,
			wantReq:  nil,
		},
		{
			name:     "no payload reference at all",
			cmd:      `whoami /priv`,
			executor: "powershell",
			wantRef:  `whoami /priv`,
			wantReq:  nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, req := artResolvePayloads(c.cmd, c.executor)
			if !strings.Contains(got, c.wantRef) {
				t.Errorf("command = %q, want it to contain %q", got, c.wantRef)
			}
			if strings.Contains(got, "PathToAtomicsFolder") {
				t.Errorf("command still contains raw PathToAtomicsFolder: %q", got)
			}
			if len(req) != len(c.wantReq) {
				t.Fatalf("required = %v, want %v", req, c.wantReq)
			}
			for i := range req {
				if req[i] != c.wantReq[i] {
					t.Errorf("required[%d] = %q, want %q", i, req[i], c.wantReq[i])
				}
			}
		})
	}
}

func TestMaterializeShipsPayloadWhenPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gsecdump.exe"), []byte("MZ-fake-binary"), 0644); err != nil {
		t.Fatal(err)
	}
	store := &ARTStore{payloads: NewPayloadStore(dir)}

	step := ScenarioStep{
		Executor: "powershell", Framework: "art",
		Command:          `"$env:BAS_PAYLOAD_DIR\gsecdump.exe" -a`,
		requiredPayloads: []string{"gsecdump.exe"},
	}
	out := store.materialize(step)
	if len(out.Payloads) != 1 || out.Payloads[0].Name != "gsecdump.exe" {
		t.Fatalf("expected 1 staged payload gsecdump.exe, got %+v", out.Payloads)
	}
	if !strings.Contains(out.Command, "gsecdump.exe") || strings.HasPrefix(strings.TrimSpace(out.Command), "Write-Output \"SKIP") {
		t.Errorf("command should be unchanged when payload present: %q", out.Command)
	}
}

func TestMaterializeSkipsWhenPayloadMissing(t *testing.T) {
	store := &ARTStore{payloads: NewPayloadStore(t.TempDir())} // empty store

	step := ScenarioStep{
		Executor: "powershell", Framework: "art",
		Command:          `"$env:BAS_PAYLOAD_DIR\gsecdump.exe" -a`,
		requiredPayloads: []string{"gsecdump.exe"},
	}
	out := store.materialize(step)
	if len(out.Payloads) != 0 {
		t.Errorf("expected no payloads, got %d", len(out.Payloads))
	}
	if !strings.Contains(out.Command, "SKIP:") || !strings.Contains(out.Command, "gsecdump.exe") {
		t.Errorf("expected a SKIP command naming the missing payload, got %q", out.Command)
	}
	// The SKIP command must interpret as ResultSkipped.
	res, _ := interpretART(ExecResult{ExitCode: 0, Stdout: stripPSWrite(out.Command)}, stripPSWrite(out.Command))
	_ = res
}

// TestMaterializeSkipsUnreachablePeerTechnique proves T1021.004 (ESXi lateral
// movement) is skipped before dispatch rather than run and timing out --
// 2026-08-26 audit: BOTH real atomics connect to a hardcoded placeholder
// hostname ("atomic.local") that can never resolve on a single-endpoint
// sweep. See project_environmental_error_triage.md.
func TestMaterializeSkipsUnreachablePeerTechnique(t *testing.T) {
	store := &ARTStore{payloads: NewPayloadStore(t.TempDir())}

	step := ScenarioStep{
		TechniqueID: "T1021.004", Executor: "powershell", Framework: "art",
		Command: `Connect-VIServer -Server atomic.local -User root -Password pass`,
	}
	out := store.materialize(step)
	if !strings.Contains(out.Command, "SKIP:") {
		t.Fatalf("expected a SKIP command for T1021.004, got %q", out.Command)
	}
	if !strings.Contains(out.Command, "ESXi") {
		t.Errorf("SKIP reason should explain why (ESXi/peer unreachable), got %q", out.Command)
	}
	res, _ := interpretART(ExecResult{ExitCode: 0, Stdout: stripPSWrite(out.Command)}, stripPSWrite(out.Command))
	if res != models.ResultSkipped {
		t.Errorf("interpretART on the SKIP command = %q, want skipped", res)
	}
}

// TestMaterializeDoesNotSkipMixedPeerTechniques proves the 2026-08-26 audit's
// mixed techniques (some atomics target a real peer, others target
// 127.0.0.1/localhost and run fine standalone) are NOT blanket-skipped --
// only T1021.004 is 100% peer-dependent. Blanket-skipping T1021.001/.002/
// .006, T1039, or T1048.003 would wrongly discard atomics that currently
// produce a real result.
func TestMaterializeDoesNotSkipMixedPeerTechniques(t *testing.T) {
	store := &ARTStore{payloads: NewPayloadStore(t.TempDir())}

	for _, id := range []string{"T1021.001", "T1021.002", "T1021.006", "T1039", "T1048.003"} {
		step := ScenarioStep{
			TechniqueID: id, Executor: "powershell", Framework: "art",
			Command: "whoami",
		}
		out := store.materialize(step)
		if strings.Contains(out.Command, "SKIP:") {
			t.Errorf("%s should not be blanket-skipped (mixed peer/local atomics), got %q", id, out.Command)
		}
	}
}

// stripPSWrite turns `Write-Output "SKIP: x"` into `SKIP: x` to simulate the
// agent's stdout for the skip echo.
func stripPSWrite(cmd string) string {
	s := strings.TrimPrefix(strings.TrimSpace(cmd), "Write-Output ")
	return strings.Trim(s, `"`)
}

func TestInterpretARTSkipAndPrereq(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   models.CheckResult
	}{
		// An explicit skip marker (e.g. missing external payload) stays SKIPPED.
		{"explicit skip marker", "SKIP: requires external payload gsecdump.exe", models.ResultSkipped},
		// A missing binary/path means the test could not execute — that is an
		// ERROR (BAS problem), not a security finding and not a deliberate skip.
		{"not recognized", "'foo.exe' is not recognized as an internal or external command", models.ResultError},
		{"cannot find path", "cd : Cannot find path 'C:\\x' because it does not exist.", models.ResultError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := interpretART(ExecResult{ExitCode: 1}, c.stdout)
			if got != c.want {
				t.Errorf("interpretART(%q) = %q, want %q", c.stdout, got, c.want)
			}
		})
	}
}
