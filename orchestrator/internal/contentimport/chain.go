package contentimport

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"github.com/audspect/bas/internal/scenario"
)

// A chain runs several reviewed steps in order and records, per stage, whether it was allowed (exit code 0), blocked
// (non-zero) or skipped because an earlier stage's outcome did not meet its run_if. The whole chain is compiled into ONE
// self-contained step, so the agent runs it like any other step and needs no support for dependencies between steps.
//
//	run_if "always"        run regardless (the first stage is always run)
//	run_if "prev_allowed"  run only if the previous stage was allowed: an attack chain, which stops where a control stops it
//	run_if "prev_blocked"  run only if the previous stage was blocked: an alternative technique tried when the first fails
//
// The chain's own exit code is that of the last stage that ran: 0 if it was allowed, else 1.

// Stage is one link of a chain.
type Stage struct {
	Name        string
	TechniqueID string
	ActionKey   string // with TechniqueID, how the platform classifies this stage's destructiveness
	Executor    string // powershell | psh | cmd | bash
	Command     string
	Cleanup     string
	Marker      string
	RunIf       string // "", always, prev_allowed, prev_blocked
	TimeoutSec  int
	Risk        string
	Reversible  bool
	SafeForProd bool
}

const (
	RunAlways      = "always"
	RunPrevAllowed = "prev_allowed"
	RunPrevBlocked = "prev_blocked"
	maxChainStages = 8
)

var nameClean = regexp.MustCompile(`[^A-Za-z0-9 _.:-]`)

func stageFamily(executor string) string {
	switch strings.ToLower(executor) {
	case "", "powershell", "psh", "cmd":
		return "windows"
	case "bash", "sh":
		return "posix"
	}
	return ""
}

func classRank(c scenario.ExecutionClass) int {
	switch c {
	case scenario.ClassNonDestructive:
		return 0
	case scenario.ClassPotentiallyDestructive:
		return 1
	}
	return 2 // destructive, or anything the platform does not recognise
}

func riskRank(r string) int {
	switch strings.ToLower(r) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	}
	return 2 // unstated risk is not assumed to be low
}

// CompileChain turns the stages into one step.
func CompileChain(name string, stages []Stage) (*scenario.Step, error) {
	if len(stages) < 2 || len(stages) > maxChainStages {
		return nil, fmt.Errorf("a chain needs between 2 and %d stages, got %d", maxChainStages, len(stages))
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("a chain needs a name")
	}
	family := stageFamily(stages[0].Executor)
	if family == "" {
		return nil, fmt.Errorf("stage 1: executor %q cannot be chained", stages[0].Executor)
	}
	parts := []string{name}
	risk, rev, prod, timeout := 1, true, true, 30
	for i, s := range stages {
		if stageFamily(s.Executor) != family {
			return nil, fmt.Errorf("stage %d (%s) uses %q, which cannot run in the same chain as stage 1 (%s)", i+1, s.Name, s.Executor, stages[0].Executor)
		}
		if strings.TrimSpace(s.Command) == "" {
			return nil, fmt.Errorf("stage %d (%s) has no command", i+1, s.Name)
		}
		switch s.RunIf {
		case "", RunAlways, RunPrevAllowed, RunPrevBlocked:
		default:
			return nil, fmt.Errorf("stage %d: run_if %q is not one of always, prev_allowed, prev_blocked", i+1, s.RunIf)
		}
		if i == 0 && (s.RunIf == RunPrevAllowed || s.RunIf == RunPrevBlocked) {
			return nil, fmt.Errorf("stage 1 has no previous stage to depend on")
		}
		if riskRank(s.Risk) > risk {
			risk = riskRank(s.Risk)
		}
		rev = rev && s.Reversible
		prod = prod && s.SafeForProd
		t := s.TimeoutSec
		if t <= 0 {
			t = 60
		}
		timeout += t
		parts = append(parts, s.Name, s.Command, s.RunIf)
	}
	if timeout > 900 {
		timeout = 900
	}
	marker := Marker("chain", parts...)

	// The platform decides how carefully a step is gated from its technique and action key. A chain is gated like the
	// WORST thing in it: it takes the classification key of its most destructive stage (the first, when all are equal),
	// so a destructive stage cannot ride along under a harmless-looking first stage.
	worst, worstRank := 0, -1
	for i, s := range stages {
		if r := classRank(scenario.ResolveExecutionClass(s.TechniqueID, s.ActionKey).Class); r > worstRank {
			worst, worstRank = i, r
		}
	}
	st := &scenario.Step{
		Name: truncate("Chain: "+strings.TrimSpace(name), 120), TechniqueID: stages[worst].TechniqueID, ActionKey: stages[worst].ActionKey, Framework: "custom",
		TestIndex: 0, TimeoutSec: timeout, Marker: marker, Reversible: rev, ProductionSafe: prod,
		BlastRadius: fmt.Sprintf("runs %d reviewed steps in order; each stage's own blast radius applies, and a stage that is blocked can stop the rest", len(stages)),
		Detection:   []string{"attack chain: " + strings.TrimSpace(name)},
	}
	switch risk {
	case 1:
		st.Risk = "low"
	case 3:
		st.Risk = "high"
	default:
		st.Risk = "medium"
	}
	if family == "windows" {
		st.Executor = "powershell"
		st.Command, st.Cleanup = chainPowerShell(marker, stages)
	} else {
		st.Executor = "bash"
		st.Command, st.Cleanup = chainBash(marker, stages)
	}
	return st, nil
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func cleanName(s string) string { return strings.TrimSpace(nameClean.ReplaceAllString(s, "_")) }

func psCondition(runIf string, first bool) string {
	switch {
	case first || runIf == "" || runIf == RunAlways:
		return "$true"
	case runIf == RunPrevAllowed:
		return "($prev -eq 'allowed')"
	default:
		return "($prev -eq 'blocked')"
	}
}

// psRunStage emits PowerShell that writes the stage's text to a file in $dir and runs it in a child process, leaving
// the exit code in $code and its output in $dir\<file>.out.
func psRunStage(tag, executor, text string) string {
	var ext, exe, args string
	data := text
	switch strings.ToLower(executor) {
	case "cmd":
		ext, exe, args = "cmd", "cmd.exe", `'/d /c "' + $f + '"'`
	default:
		ext, exe, args = "ps1", "powershell.exe", `'-NoProfile -ExecutionPolicy Bypass -File "' + $f + '"'`
		data = string(rune(0xFEFF)) + text // a BOM so Windows PowerShell reads the file as UTF-8
	}
	return fmt.Sprintf(`$f = Join-Path $dir '%s.%s'; [IO.File]::WriteAllBytes($f,[Convert]::FromBase64String('%s')); `+
		`try { $p = Start-Process -FilePath %s -ArgumentList (%s) -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $dir '%s.out') -RedirectStandardError (Join-Path $dir '%s.err'); $code = $p.ExitCode } catch { $code = 1 }`,
		tag, ext, b64(data), psq(exe), args, tag, tag)
}

func chainPowerShell(marker string, stages []Stage) (command, cleanup string) {
	var b strings.Builder
	dir := "audspect-" + marker
	fmt.Fprintf(&b, "$ErrorActionPreference='Continue'; $dir = Join-Path $env:TEMP '%s'; New-Item -ItemType Directory -Force $dir | Out-Null; $prev = 'none'; $lastExit = 1\n", dir)
	for i, s := range stages {
		tag := fmt.Sprintf("s%d", i+1)
		fmt.Fprintf(&b, "if (%s) {\n  %s\n  $lastExit = $code; $outcome = if ($code -eq 0) { 'allowed' } else { 'blocked' }\n} else { $outcome = 'skipped' }\n",
			psCondition(s.RunIf, i == 0), psRunStage(tag, s.Executor, s.Command))
		fmt.Fprintf(&b, "Write-Output ('AUDSPECT_CHAIN stage=%d name=%s outcome=' + $outcome)\n", i+1, cleanName(s.Name))
		fmt.Fprintf(&b, "$o = Join-Path $dir '%s.out'; if (Test-Path $o) { Get-Content $o -TotalCount 20 | ForEach-Object { Write-Output ('  | ' + $_) } }\n", tag)
		b.WriteString("$prev = $outcome\n")
	}
	fmt.Fprintf(&b, "Write-Output '%s'; exit $(if ($lastExit -eq 0) { 0 } else { 1 })", marker)

	var c strings.Builder
	fmt.Fprintf(&c, "$dir = Join-Path $env:TEMP '%s'; New-Item -ItemType Directory -Force $dir | Out-Null\n", dir)
	for i := len(stages) - 1; i >= 0; i-- {
		if strings.TrimSpace(stages[i].Cleanup) == "" {
			continue
		}
		fmt.Fprintf(&c, "%s\n", psRunStage(fmt.Sprintf("c%d", i+1), stages[i].Executor, stages[i].Cleanup))
	}
	c.WriteString("Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue")
	return b.String(), c.String()
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func chainBash(marker string, stages []Stage) (command, cleanup string) {
	var b strings.Builder
	dir := "/tmp/audspect-" + marker
	fmt.Fprintf(&b, "dir=%s; mkdir -p \"$dir\"; prev=none; last=1\n", dir)
	for i, s := range stages {
		tag := fmt.Sprintf("s%d", i+1)
		cond := "true"
		switch {
		case i == 0 || s.RunIf == "" || s.RunIf == RunAlways:
		case s.RunIf == RunPrevAllowed:
			cond = `[ "$prev" = allowed ]`
		default:
			cond = `[ "$prev" = blocked ]`
		}
		fmt.Fprintf(&b, "if %s; then printf %%s %s | base64 -d > \"$dir/%s.sh\"; bash \"$dir/%s.sh\" > \"$dir/%s.out\" 2>&1; code=$?; last=$code; "+
			"if [ \"$code\" -eq 0 ]; then outcome=allowed; else outcome=blocked; fi; else outcome=skipped; fi\n",
			cond, shq(b64(s.Command)), tag, tag, tag)
		fmt.Fprintf(&b, "echo \"AUDSPECT_CHAIN stage=%d name=%s outcome=$outcome\"; [ -f \"$dir/%s.out\" ] && head -n 20 \"$dir/%s.out\" | sed 's/^/  | /'\n",
			i+1, cleanName(s.Name), tag, tag)
		b.WriteString("prev=$outcome\n")
	}
	fmt.Fprintf(&b, "echo '%s'; if [ \"$last\" -eq 0 ]; then exit 0; else exit 1; fi", marker)

	var c strings.Builder
	for i := len(stages) - 1; i >= 0; i-- {
		if strings.TrimSpace(stages[i].Cleanup) == "" {
			continue
		}
		fmt.Fprintf(&c, "printf %%s %s | base64 -d | bash || true\n", shq(b64(stages[i].Cleanup)))
	}
	fmt.Fprintf(&c, "rm -rf %s", dir)
	return b.String(), c.String()
}
