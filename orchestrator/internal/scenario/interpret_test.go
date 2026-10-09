package scenario

import (
	"strings"
	"testing"

	"github.com/audspect/bas/internal/models"
)

// An ART step must carry framework "art" so results route through interpretART
// (block-aware), and a known technique ID must resolve its tactic — otherwise
// the result loses its metadata and falls back to the generic "custom" path.
func TestBuildStepTagsARTFramework(t *testing.T) {
	s := Step{TechniqueID: "T1003", Name: "OS Credential Dumping", Framework: "art"}
	built, err := buildStep(s, "", "", nil, "windows")
	if err != nil {
		t.Fatalf("buildStep: %v", err)
	}
	if built.Framework != "art" {
		t.Errorf("Framework = %q, want art", built.Framework)
	}

	meta := BuildStepMeta([]ScenarioStep{built}, nil, ComponentVersions{})
	m, ok := meta[built.TaskID]
	if !ok {
		t.Fatalf("BuildStepMeta missing TaskID %s", built.TaskID)
	}
	if m.Framework != "art" || m.TechniqueID != "T1003" {
		t.Errorf("StepMeta = %+v, want framework=art technique=T1003", m)
	}
}

// Reconstructing the Step from persisted StepMeta must yield a result with the
// correct framework routing and a resolved tactic (not the empty "()" fallback).
func TestInterpretFromStepMetaResolvesTactic(t *testing.T) {
	m := StepMeta{TechniqueID: "T1003", Name: "OS Credential Dumping", Framework: "art"}
	step := Step{TechniqueID: m.TechniqueID, Name: m.Name, Framework: m.Framework}
	res := Interpret(step, ExecResult{ExitCode: 0, Stdout: "lsass dumped"})

	if res.Framework != "art" {
		t.Errorf("Framework = %q, want art", res.Framework)
	}
	if res.Technique.Tactic != "credential-access" {
		t.Errorf("Tactic = %q, want credential-access", res.Technique.Tactic)
	}
	if res.Result != "fail" { // exit 0, not blocked → technique executed
		t.Errorf("Result = %q, want fail", res.Result)
	}
}

func TestInterpretCopiesCheckIDThrough(t *testing.T) {
	step := Step{TechniqueID: "T1562.004", Name: "Firewall Enabled", Framework: "custom", CheckID: "windows-firewall-enabled"}
	res := Interpret(step, ExecResult{ExitCode: 0, Stdout: "PASS: firewall enabled"})
	if res.CheckID != "windows-firewall-enabled" {
		t.Errorf("CheckID = %q, want windows-firewall-enabled", res.CheckID)
	}
}

func TestInterpretCheckIDEmptyWhenUnset(t *testing.T) {
	step := Step{TechniqueID: "T1055", Name: "ASLR Enabled", Framework: "custom"}
	res := Interpret(step, ExecResult{ExitCode: 0})
	if res.CheckID != "" {
		t.Errorf("CheckID = %q, want empty for a step with no check_id (e.g. cis-ubuntu-l1 kernel checks)", res.CheckID)
	}
}

// TestInterpretStepNamePreservesSpecificAtomicName proves StepName always
// carries the step's own specific name, even when the technique ID resolves
// to a generic ATT&CK catalog name -- previously step.Name was discarded
// whenever that lookup succeeded (the common case), so two different atomics
// under the same technique (e.g. "T1003 - Test 1" and "T1003 - Test 3", both
// T1003) were indistinguishable everywhere downstream (reports, CSV, results
// drawer) except the live run panel.
func TestInterpretStepNamePreservesSpecificAtomicName(t *testing.T) {
	step := Step{TechniqueID: "T1003", Name: "T1003 - Test 3: LSASS dump via comsvcs.dll MiniDump", Framework: "art"}
	res := Interpret(step, ExecResult{ExitCode: 0})
	if res.StepName != step.Name {
		t.Errorf("StepName = %q, want %q", res.StepName, step.Name)
	}
	// The generic catalog name must still be resolved for Technique.Name --
	// StepName is additive, not a replacement.
	if res.Technique.Name == "" || res.Technique.Name == step.Name {
		t.Errorf("Technique.Name = %q, want the resolved generic ATT&CK catalog name, distinct from the specific step name", res.Technique.Name)
	}
}

// TestInterpretStepNameEmptyWhenStepNameEmpty proves StepName isn't
// backfilled from the resolved technique name -- it's genuinely empty when
// the step itself has no name, so downstream rendering can tell "no specific
// atomic name available" apart from "name happens to equal the generic one".
func TestInterpretStepNameEmptyWhenStepNameEmpty(t *testing.T) {
	step := Step{TechniqueID: "T1003", Framework: "art"}
	res := Interpret(step, ExecResult{ExitCode: 0})
	if res.StepName != "" {
		t.Errorf("StepName = %q, want empty", res.StepName)
	}
}

func TestInterpretARTBlockDetection(t *testing.T) {
	cases := []struct {
		name   string
		r      ExecResult
		stdout string
		want   models.CheckResult
	}{
		{"plain access denied", ExecResult{ExitCode: 1}, "Access is denied.", models.ResultPass},
		{"defender quarantine", ExecResult{ExitCode: 0}, "Operation did not complete successfully because the file contains a virus", models.ResultPass},
		{"group policy block", ExecResult{ExitCode: 1}, "This program is blocked by group policy", models.ResultPass},
		{"silent access-denied exit (win32 5)", ExecResult{ExitCode: 5}, "", models.ResultPass},
		{"silent NTSTATUS access-denied (signed)", ExecResult{ExitCode: -1073741790}, "", models.ResultPass},
		{"technique ran, exit 0", ExecResult{ExitCode: 0}, "whoami\\nDESKTOP\\\\admin", models.ResultFail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := interpretART(c.r, c.stdout)
			if got != c.want {
				t.Errorf("interpretART(%q, exit=%d) = %q, want %q", c.stdout, c.r.ExitCode, got, c.want)
			}
		})
	}
}

// TestInterpret_DomainControllerInterlockAbortIsVetoedNeverFail is the
// critical regression test for a real scoring defect found 2026-10-09 while
// proving the AD Mastery E2E Directive's evidence/safety contract (increment
// 2.1): agent.go's domain-controller safety interlock (both
// BlockOnDomainController and RequireDCReachable) originally submitted
// {ExitCode:-1, Blocked:true, BlockedReason:"..."}. scenario.ExecResult (this
// package's own type) has no Blocked/BlockedReason field by deliberate design
// (see its doc comment) -- so those two fields were silently dropped at JSON
// unmarshal, Interpret() never saw any signal that the run was never
// attempted, and the result fell through to interpretCustom's final default:
// ResultFail, "Step failed (exit -1)" -- a false "attack succeeded, defenses
// did not stop it" finding for a run that never executed a single step.
//
// The fix submits {Vetoed:true, VetoedActionKey/Class/Source:...} instead --
// the SAME structured field Interpret() already special-cases before the
// framework switch for a B5 destructive-action veto, with its own scoring-
// exclusion already established. This test uses exactly the shape the agent
// now submits: TaskID is empty (the interlock fires before any step is
// chosen), so Step is the real fallback {Framework: "custom"} the server
// builds when a TaskID lookup misses -- proving the fix through the actual
// top-level Interpret() entry point, not a single framework interpreter.
func TestInterpret_DomainControllerInterlockAbortIsVetoedNeverFail(t *testing.T) {
	step := Step{Framework: "custom"} // the real fallback for an unmatched TaskID
	r := ExecResult{
		ExitCode:             -1,
		Vetoed:               true,
		VetoedActionKey:      "live_ad_execution",
		VetoedExecutionClass: "environment_safety_policy",
		VetoedBlockSource:    "domain_controller_interlock",
	}
	res := Interpret(step, r)

	if res.Result != models.ResultVetoed {
		t.Fatalf("Result = %q, want %q -- the interlock abort must never be scored as a real finding", res.Result, models.ResultVetoed)
	}
	if res.Result == models.ResultFail || res.Result == models.ResultPass || res.Result == models.ResultBlocked {
		t.Fatalf("Result = %q -- an unattempted run must never be mistaken for either an attack success (Fail) or a defensive win (Pass/Blocked)", res.Result)
	}
}

func TestInterpretART_VetoedMapsToResultVetoedNeverResultPass(t *testing.T) {
	r := ExecResult{Vetoed: true, VetoedActionKey: "vss_delete", VetoedExecutionClass: "destructive"}
	result, _ := interpretART(r, "")
	if result != models.ResultVetoed {
		t.Errorf("result = %v, want models.ResultVetoed", result)
	}
	if result == models.ResultPass || result == models.ResultBlocked {
		t.Fatal("a B5 veto must NEVER map to ResultPass or ResultBlocked -- that would falsely report a customer-defense success for a technique that was never attempted")
	}
}

// A BAS execution problem (malformed content, timeout, scheduler contention,
// missing prerequisite, DNS, interactive prompt, …) is NOT a security finding —
// it must classify as ERROR, never FAIL, so it is excluded from the score.
// Strings are taken verbatim from the Atomic Red Team selective-techniques report.
func TestInterpretARTExecutionErrors(t *testing.T) {
	cases := []struct {
		name   string
		r      ExecResult
		stdout string
	}{
		{"invalid syntax (T1112)", ExecResult{ExitCode: 1}, "ERROR: Invalid syntax."},
		{"invalid key name (T1112)", ExecResult{ExitCode: 1}, "ERROR: Invalid key name."},
		{"scheduler contention (T1082)", ExecResult{ExitCode: -1}, "schedule timeout: resource locks unavailable within 30s"},
		{"step timeout (T1059.003)", ExecResult{ExitCode: -1}, "step exceeded execute timeout of 120s"},
		{"dns failure (T1105)", ExecResult{ExitCode: 1}, "ssh: Could not resolve hostname adversary-host: No such host is known."},
		{"binary cannot execute (T1003.001)", ExecResult{ExitCode: 1}, "The system cannot execute the specified program."},
		{"prereq not found (T1105 OneDrive)", ExecResult{ExitCode: 1}, "OneDriveStandaloneUpdater.exe not found at C:\\...\\OneDrive. Test cannot continue."},
		{"interactive prompt (T1003.002 sam)", ExecResult{ExitCode: -1}, "File C:\\Windows\\TEMP\\sam already exists. Overwrite (Yes/No)?"},
		{"arch mismatch (T1082)", ExecResult{ExitCode: 1}, "Could not load file or assembly ... An attempt was made to load a program with an incorrect format."},
		{"msi invalid cmdline (T1569.002)", ExecResult{ExitCode: 1639}, "DESCRIPTION:"},
		{"curl cannot open (T1105)", ExecResult{ExitCode: 26}, "curl: cannot open 'c:\\temp\\atomictestfile.txt'"},
		{"generic nonzero, no signal", ExecResult{ExitCode: 1}, "Directory: C:\\temp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, detail := interpretART(c.r, c.stdout)
			if got != models.ResultError {
				t.Errorf("interpretART(%q, exit=%d) = %q, want error (detail=%q)", c.stdout, c.r.ExitCode, got, detail)
			}
		})
	}
}

// Custom/posture checks: a check whose own PowerShell crashed (parse error) is
// a BAS problem → ERROR, not a security FAIL. Strings are verbatim from the Full
// Security Posture Scan report. Structured PASS:/FAIL:/SKIP: verdicts and benign
// non-zero exits are unaffected.
func TestInterpretCustomClassifiesScriptCrash(t *testing.T) {
	cases := []struct {
		name   string
		r      ExecResult
		stdout string
		want   models.CheckResult
	}{
		{"missing terminator", ExecResult{ExitCode: 1}, `The string is missing the terminator: ".`, models.ResultError},
		{"stray token cmdlet", ExecResult{ExitCode: 1}, "s : The term 's' is not recognized as the name of a cmdlet, function, script file, or operable program.", models.ResultError},
		{"structured FAIL stays fail", ExecResult{ExitCode: 0}, "FAIL: UAC DISABLED — silent elevation possible", models.ResultFail},
		{"structured PASS stays pass", ExecResult{ExitCode: 0}, "PASS: WDigest disabled", models.ResultPass},
		{"benign nonzero, no parse error", ExecResult{ExitCode: 1}, "value not present", models.ResultFail},
		{"informational line before FAIL verdict", ExecResult{ExitCode: 0}, "EXEC T1558.003: found 3 kerberoastable accounts\nFAIL: enumeration ran unimpeded", models.ResultFail},
		{"informational line before PASS verdict", ExecResult{ExitCode: 0}, "EXEC T1558.004: enumerated 0 roastable accounts\nPASS: no AS-REP roastable accounts exposed", models.ResultPass},
		{"informational line before SKIP verdict", ExecResult{ExitCode: 0}, "INFO: probing domain reachability\nSKIP: host is not domain-joined", models.ResultSkipped},

		// Empty output: no verdict line, no informational text at all. Pre-existing,
		// unchanged behavior -- pinned so a future change can't silently alter it.
		{"empty output, exit 0, falls to Pass default", ExecResult{ExitCode: 0}, "", models.ResultPass},
		{"empty output, exit 1, falls to Fail default", ExecResult{ExitCode: 1}, "", models.ResultFail},

		// Malformed verdicts: close to the real prefix but not an exact match.
		// Pre-existing, unchanged behavior -- these must keep falling through to
		// the exit-code default rather than being loosely matched.
		{"malformed verdict, misspelled word", ExecResult{ExitCode: 0}, "PASSED: looks fine", models.ResultPass},      // exit-0 default, not a Pass match
		{"malformed verdict, space before colon", ExecResult{ExitCode: 1}, "FAIL : broken", models.ResultFail},        // exit-1 default, not a Fail match
		{"malformed verdict, no colon at all", ExecResult{ExitCode: 0}, "FAIL something is wrong", models.ResultPass}, // exit-0 default -- "FAIL something" never matches "fail:"

		// Conflicting verdict TYPES in the same output: never produced by any
		// committed scenario today (every step's branches are mutually
		// exclusive -- verified against scenarios/kerberoasting-ad-drill.yaml
		// and the wider corpus), but output can still be malformed or
		// hand-crafted, and this function must have one explicit, documented
		// answer rather than an accidental one. Fail-safe policy: FAIL must
		// never be silently suppressed by a PASS or SKIP line elsewhere in the
		// same output (mirrors this file's existing bias -- see Vetoed/TimedOut
		// in Interpret -- toward never overstating a defensive win when there
		// is ambiguity). Priority: FAIL > SKIP > PASS, independent of which
		// line appears first.
		{"conflicting FAIL after PASS: FAIL wins despite position", ExecResult{ExitCode: 0}, "PASS: looked clean at first\nFAIL: actually exploitable", models.ResultFail},
		{"conflicting PASS after FAIL: FAIL still wins", ExecResult{ExitCode: 0}, "FAIL: exploitable\nPASS: contradicts the above", models.ResultFail},
		{"conflicting SKIP and PASS (no FAIL): SKIP wins", ExecResult{ExitCode: 0}, "SKIP: not applicable here\nPASS: contradicts the above", models.ResultSkipped},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, detail := interpretCustom(c.r, c.stdout)
			if got != c.want {
				t.Errorf("interpretCustom(%q, exit=%d) = %q, want %q (detail=%q)", c.stdout, c.r.ExitCode, got, c.want, detail)
			}
		})
	}
}

// TestInterpretCustom_VerdictLineNotNecessarilyFirst is a dedicated regression
// test for a scoring bug found 2026-10-09 while verifying the Kerberoasting
// scenario end-to-end: interpretCustom previously only read the FIRST
// non-empty output line for a PASS:/FAIL:/SKIP: prefix. scenarios/
// kerberoasting-ad-drill.yaml (and ~37 other builtin scenarios) write an
// informational "EXEC T1558...: <finding>" line BEFORE their verdict line, so
// the first line never matched a structured prefix, fell through to the
// exit-code default (0 = Pass), and every one of those findings was scored
// Pass instead of its intended Fail -- reporting an actual Kerberoast/AS-REP
// exposure as a passing control. The verdict line can appear anywhere in the
// output; interpretCustom must find it regardless of position.
func TestInterpretCustom_VerdictLineNotNecessarilyFirst(t *testing.T) {
	// Verbatim from scenarios/kerberoasting-ad-drill.yaml Stage 2.
	stdout := "EXEC T1558.003: requested a TGS-REP service ticket for SPN 'MSSQLSvc/db01.corp.local:1433' " +
		"(hash NOT extracted or cracked). This is the exact Kerberoast request. DC Security EID 4769 expected. [BAS-SIM-KRB-S2]\n" +
		"FAIL: A service ticket was granted on demand for a service account SPN. If that account has a weak password " +
		"and RC4 is allowed, the ticket is offline-crackable. Enforce AES-only, use gMSAs / 25+ char service passwords, " +
		"and alert on EID 4769 RC4 tickets."

	got, detail := interpretCustom(ExecResult{ExitCode: 0}, stdout)
	if got != models.ResultFail {
		t.Fatalf("interpretCustom = %q, want ResultFail — the FAIL: line was not found because it isn't first (detail=%q)", got, detail)
	}
	if strings.HasPrefix(detail, "EXEC T1558.003") {
		t.Fatalf("detail should report the verdict line's own text, not the informational line ahead of it: %q", detail)
	}
}

// The Atomic Red Team selective report marked many test/atomic artifacts as FAIL
// (Technique Executed). They are NOT successful attacks — a bad path, a missing
// runtime dependency, or a resource that already existed. Critically, several of
// these surface on a ZERO exit code (PowerShell non-terminating errors), so they
// must classify as ERROR, not FAIL. Strings are verbatim from the report.
func TestInterpretARTAtomicArtifactsAreErrors(t *testing.T) {
	cases := []struct {
		name   string
		r      ExecResult
		stdout string
	}{
		{"F-02 invalid dump path (exit 0)", ExecResult{ExitCode: 0}, `The path 'C:\Windows\system32\"C:\Windows\TEMP\nanodump.dmp"' is invalid.`},
		{"F-03 IWR IE engine missing (exit 0)", ExecResult{ExitCode: 0}, "IWR : The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete."},
		{"F-06 SilentProcessExit folder invalid (exit 0)", ExecResult{ExitCode: 0}, "SilentProcessExit folder is not valid"},
		{"F-105 item already exists (exit 0)", ExecResult{ExitCode: 0}, "New-Item : The item already exists."},
		{"not a valid win32 application", ExecResult{ExitCode: 1}, "The program or feature could not be started because it is not a valid Win32 application."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, detail := interpretART(c.r, c.stdout)
			if got != models.ResultError {
				t.Errorf("interpretART(%q, exit=%d) = %q, want error (detail=%q)", c.stdout, c.r.ExitCode, got, detail)
			}
		})
	}
}

// TestInterpretARTProcessSpawnFailure_NotMislabeledAsMalformedContent is the
// regression guard for a real user-reported bug: Go's own exec.Cmd.Start()
// failure text ("fork/exec ...: The handle is invalid.") contains the
// substring "is invalid", which used to fall into the generic
// malformed-content classification -- an agent/host-level process-spawn
// failure is not a scenario content problem and must never be blamed on the
// atomic. Verbatim from the actual error text reported against an
// "Endpoint Mastery 02 - ATT&CK" run.
func TestInterpretARTProcessSpawnFailure_NotMislabeledAsMalformedContent(t *testing.T) {
	stdout := `fork/exec C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe: The handle is invalid.`
	got, detail := interpretART(ExecResult{ExitCode: -1}, stdout)
	if got != models.ResultError {
		t.Fatalf("interpretART(%q) = %q, want error", stdout, got)
	}
	if strings.Contains(detail, "malformed atomic content") {
		t.Fatalf("detail = %q, must NOT blame the atomic's content for an agent-side process-spawn failure", detail)
	}
	if !strings.Contains(detail, "agent could not launch the process") {
		t.Fatalf("detail = %q, want it to name this an agent/host problem", detail)
	}
}

// Guard against over-matching: a benign validation payload that genuinely ran
// (PowerShell/CMD executed unblocked, exit 0, no error text) is a real FAIL —
// the control did not prevent code execution. It must NOT be swept into ERROR.
// The FAIL detail must state the SECURITY meaning, not echo the raw command
// output ("Hello, from PowerShell!") as if malware succeeded.
// TestInterpretARTBenignExecutionStaysFail also proves the FAIL headline
// carries real evidence (2026-08-20 fix), not just the security-meaning
// framing on its own -- the previous version of this test asserted the
// OPPOSITE (raw output must never appear), which meant a FAIL headline was
// genuinely uninformative on its own: "Security control did not prevent
// this technique" told a reader nothing about WHAT ran. The output is now
// appended as clearly-labelled evidence ("Output: ...") specifically so it
// can't misread as if the raw text were the important part by itself --
// labelling, not omission, is what avoids that confusion.
func TestInterpretARTBenignExecutionStaysFail(t *testing.T) {
	for _, out := range []string{"Hello, from PowerShell!", "Hello, from CMD!"} {
		got, detail := interpretART(ExecResult{ExitCode: 0}, out)
		if got != models.ResultFail {
			t.Errorf("interpretART(%q, exit=0) = %q, want fail (detail=%q)", out, got, detail)
		}
		if !strings.Contains(strings.ToLower(detail), "did not prevent") {
			t.Errorf("interpretART(%q) detail = %q, want the security-outcome framing", out, detail)
		}
		if !strings.Contains(detail, "Output: "+out) {
			t.Errorf("interpretART(%q) detail = %q, want the real output included as labelled evidence", out, detail)
		}
	}
}

// A non-zero exit that still shows the technique executed (e.g. a trailing
// cleanup line failed) is a genuine FAIL, not an execution error. Also
// covers the ranToCompletion branch of the evidence fix above -- a
// distinct code path from the exit==0 branch.
func TestInterpretARTRanToCompletionIsFail(t *testing.T) {
	for _, out := range []string{"The operation completed successfully.", "technique ran to completion"} {
		got, detail := interpretART(ExecResult{ExitCode: 1}, out)
		if got != models.ResultFail {
			t.Errorf("interpretART(%q, exit=1) = %q, want fail", out, got)
		}
		if !strings.Contains(detail, "Output: "+out) {
			t.Errorf("interpretART(%q) detail = %q, want the real output included as labelled evidence", out, detail)
		}
	}
}

func TestClassifySkipReason(t *testing.T) {
	cases := []struct {
		name   string
		detail string
		want   string
	}{
		{"ART missing payload", "requires external payload(s) not available on server: gsecdump.exe — drop them in ART_PAYLOAD_DIR to enable this test", models.SkipReasonMissingContent},
		{"ART not in local store with OS", "ART technique T1003 not in local store for windows", models.SkipReasonPlatformUnavailable},
		{"ART not in local store no OS", "ART technique T1003 not in local store", models.SkipReasonPlatformUnavailable},
		{"malformed step no command", "No command defined for step 'my-step'", models.SkipReasonPlatformUnavailable},
		{"caldera not configured", "Caldera not configured — set CALDERA_URL to enable ability abc123", models.SkipReasonPlatformUnavailable},
		{"caldera ability not found", "Caldera ability abc123 not found", models.SkipReasonPlatformUnavailable},
		{"circuit breaker open", "circuit breaker open for technique:T1055, domain:registry", models.SkipReasonCircuitOpen},
		{"unrecognized text", "some future skip reason nobody has written yet", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifySkipReason(c.detail); got != c.want {
				t.Errorf("classifySkipReason(%q) = %q, want %q", c.detail, got, c.want)
			}
		})
	}
}

func TestInterpret_SetsSkipReason(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   string
	}{
		{"ART missing payload", "SKIP: requires external payload(s) not available on server: gsecdump.exe", models.SkipReasonMissingContent},
		{"ART not in local store", "SKIP: ART technique T1003 not in local store for windows", models.SkipReasonPlatformUnavailable},
		{"unmatched skip text (e.g. policy marker) leaves SkipReason empty", "SKIP: requires admin privilege, execution policy caps at user", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			step := Step{TechniqueID: "T1003", Name: "test", Framework: "art"}
			res := Interpret(step, ExecResult{ExitCode: 0, Stdout: c.stdout})
			if res.Result != models.ResultSkipped {
				t.Fatalf("Result = %q, want skipped", res.Result)
			}
			if res.SkipReason != c.want {
				t.Errorf("SkipReason = %q, want %q", res.SkipReason, c.want)
			}
		})
	}
	// A non-skip result must never carry a SkipReason.
	passRes := Interpret(Step{TechniqueID: "T1059", Framework: "art"}, ExecResult{ExitCode: 0, Stdout: "the operation completed successfully"})
	if passRes.SkipReason != "" {
		t.Errorf("non-skip SkipReason = %q, want empty", passRes.SkipReason)
	}
}

func TestInterpretUsesDefaultOutputLimitWhenUnset(t *testing.T) {
	step := Step{TechniqueID: "T1082", Name: "test", Framework: "custom"}
	longOutput := strings.Repeat("x", 4000)
	res := Interpret(step, ExecResult{ExitCode: 0, Stdout: longOutput})
	if len(res.RawOutput) > 3003 { // 3000 + the "…" truncation marker (3 UTF-8 bytes)
		t.Errorf("RawOutput len = %d, want capped near 3000 (default limit)", len(res.RawOutput))
	}
	if !res.Truncated {
		t.Error("expected Truncated=true when output exceeds the default 3000-byte limit")
	}
	if res.OriginalOutputBytes != len(longOutput) {
		t.Errorf("OriginalOutputBytes = %d, want %d", res.OriginalOutputBytes, len(longOutput))
	}
}

func TestInterpretUsesStepOverrideOutputLimit(t *testing.T) {
	step := Step{TechniqueID: "T1082", Name: "test", Framework: "custom", MaxOutputBytes: 20000}
	longOutput := strings.Repeat("x", 4000)
	res := Interpret(step, ExecResult{ExitCode: 0, Stdout: longOutput})
	if res.Truncated {
		t.Error("expected Truncated=false -- 4000 bytes is under the step's 20000-byte override")
	}
	if len(res.RawOutput) != len(longOutput) {
		t.Errorf("RawOutput len = %d, want %d (untruncated)", len(res.RawOutput), len(longOutput))
	}
}
