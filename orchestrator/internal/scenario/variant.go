package scenario

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Variant dimensions ────────────────────────────────────────────────────────
//
// The Variant Engine multiplies the base ART atomic test library at dispatch
// time rather than at seed time. Three orthogonal dimensions apply:
//
//   Encoding     — how the command string is represented on the wire (PS only)
//   Privilege    — which execution context the agent resolves for the step
//   ExecContext  — which Windows launch mechanism invokes the command
//
// The base test is {plain / user / direct} — no transforms.
//
// Product per step:
//   PowerShell: 3 encodings × 3 privileges × 4 contexts = 36 variants
//   CMD:        1 encoding  × 3 privileges × 4 contexts = 12 variants

// PSEncodings are the encoding transforms available for PowerShell steps.
var PSEncodings = []string{"plain", "base64", "charcode"}

// Privileges are the execution-context privilege levels available to all steps.
// The agent resolves the appropriate Windows token; "system" requires the agent
// to have elevated privileges or a SYSTEM-capable dispatch path.
var Privileges = []string{"user", "admin", "system"}

// ExecContexts are the Windows launch mechanisms available for all steps.
// Each uses a different Windows sub-system, exercising different detection surfaces.
var ExecContexts = []string{"direct", "wmi", "scheduled-task", "com"}

const psVariantsPerStep = 3 * 3 * 4  // 36
const cmdVariantsPerStep = 1 * 3 * 4 // 12

// VariantSpec selects one position in the variant space for a single step.
// The zero value is the base test (plain / user / direct) — no transforms applied.
type VariantSpec struct {
	// Encoding controls the command representation.
	//   "plain"    — command sent as-is (default)
	//   "base64"   — UTF-16LE base64 via powershell -EncodedCommand
	//   "charcode" — [char]N+[char]N via IEX(); evades keyword-match rules
	Encoding string `json:"encoding"`

	// Privilege declares the required execution context.
	//   "user"   — logged-in interactive user (default; realistic phishing model)
	//   "admin"  — local administrator
	//   "system" — NT AUTHORITY\SYSTEM (requires agent elevation)
	Privilege string `json:"privilege"`

	// ExecContext selects the Windows launch mechanism.
	//   "direct"          — executor runs the command directly (default)
	//   "wmi"             — Win32_Process.Create (T1047)
	//   "scheduled-task"  — schtasks + run (T1053.005)
	//   "com"             — WScript.Shell COM object (T1559.001)
	ExecContext string `json:"execContext"`
}

// IsBase returns true when the spec is the unmodified base test.
func (s VariantSpec) IsBase() bool {
	return norm(s.Encoding, "plain") == "plain" &&
		norm(s.Privilege, "user") == "user" &&
		norm(s.ExecContext, "direct") == "direct"
}

// Sig returns a short human-readable signature, e.g. "base64/admin/wmi".
// Returns "base" for the zero variant.
func (s VariantSpec) Sig() string {
	enc := norm(s.Encoding, "plain")
	priv := norm(s.Privilege, "user")
	ctx := norm(s.ExecContext, "direct")
	if enc == "plain" && priv == "user" && ctx == "direct" {
		return "base"
	}
	var parts []string
	if enc != "plain" {
		parts = append(parts, enc)
	}
	if priv != "user" {
		parts = append(parts, priv)
	}
	if ctx != "direct" {
		parts = append(parts, ctx)
	}
	return strings.Join(parts, "/")
}

func norm(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ── Count helpers ─────────────────────────────────────────────────────────────

// StepVariantCount returns the number of distinct executable variants available
// for a single step (including the base variant).
func StepVariantCount(executor string) int {
	switch executor {
	case "powershell":
		return psVariantsPerStep
	case "cmd":
		return cmdVariantsPerStep
	default:
		return 1
	}
}

// ComputeVariantCount sums the per-step variant counts across a step list.
func ComputeVariantCount(steps []ScenarioStep) int {
	n := 0
	for _, s := range steps {
		n += StepVariantCount(s.Executor)
	}
	return n
}

// VariantCountFromExecutorCounts computes the total available variant count
// given raw executor breakdown counts (no step list needed).
func VariantCountFromExecutorCounts(psSteps, cmdSteps int) int {
	return psSteps*psVariantsPerStep + cmdSteps*cmdVariantsPerStep
}

// QueryVariantCount queries art_atomic_tests for the executor breakdown and
// returns (psCount, cmdCount, variantTotal). Errors are non-fatal — the caller
// should degrade gracefully if the DB is unavailable.
func QueryVariantCount(ctx context.Context, pool *pgxpool.Pool) (psCount, cmdCount, total int, err error) {
	rows, err := pool.Query(ctx, `SELECT executor, COUNT(*) FROM art_atomic_tests GROUP BY executor`)
	if err != nil {
		return 0, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var exec string
		var cnt int
		if scanErr := rows.Scan(&exec, &cnt); scanErr != nil {
			return 0, 0, 0, scanErr
		}
		switch exec {
		case "powershell":
			psCount = cnt
		case "cmd":
			cmdCount = cnt
		}
	}
	if err = rows.Err(); err != nil {
		return 0, 0, 0, err
	}
	return psCount, cmdCount, VariantCountFromExecutorCounts(psCount, cmdCount), nil
}

// ── ApplyVariant ──────────────────────────────────────────────────────────────

// ApplyVariant returns a copy of step with the transforms in spec applied.
// Returns the step unchanged when spec.IsBase(). The step name and TaskID
// are updated to include the variant signature so results can be attributed
// to the correct variant without ambiguity.
func ApplyVariant(step ScenarioStep, spec VariantSpec) ScenarioStep {
	if spec.IsBase() {
		return step
	}
	v := step

	// 1. Encoding transform (PowerShell steps only)
	if step.Executor == "powershell" {
		switch spec.Encoding {
		case "base64":
			v.Command = psWrapBase64(step.Command)
		case "charcode":
			v.Command = psWrapCharcode(step.Command)
		}
	}

	// 2. Execution context wrapper — wraps the (already encoded) command
	switch spec.ExecContext {
	case "wmi":
		v.Command, v.Executor = wrapWMI(v.Command, step.Executor)
	case "scheduled-task":
		v.Command, v.Executor = wrapScheduledTask(v.Command, step.Executor)
	case "com":
		v.Command, v.Executor = wrapCOM(v.Command, step.Executor)
	}

	// 3. Privilege annotation — the agent resolves the actual Windows token
	if p := norm(spec.Privilege, "user"); p != "user" {
		v.RequiresPriv = p
	}

	// 4. Update name + TaskID with the variant signature
	sig := spec.Sig()
	v.Name = step.Name + " [" + sig + "]"
	v.TaskID = TaskID(v.TechniqueID, v.Name)
	return v
}

// ── Encoding wrappers ─────────────────────────────────────────────────────────

// psWrapBase64 encodes a PowerShell command as UTF-16LE base64 and rewrites
// it as "powershell -EncodedCommand <b64>". This bypasses simple string-match
// detection rules that scan for plaintext keywords like "Invoke-Mimikatz".
func psWrapBase64(cmd string) string {
	b64 := base64.StdEncoding.EncodeToString(utf16LEEncode(cmd))
	return "powershell -NonInteractive -NoProfile -EncodedCommand " + b64
}

// psWrapCharcode converts a PowerShell command to a [char]N+[char]N+...
// expression executed via IEX. Each character becomes an integer ordinal,
// defeating keyword-based detection without any external encoding.
func psWrapCharcode(cmd string) string {
	parts := make([]string, 0, len([]rune(cmd)))
	for _, r := range cmd {
		parts = append(parts, fmt.Sprintf("[char]%d", r))
	}
	return "IEX(" + strings.Join(parts, "+") + ")"
}

// utf16LEEncode converts a UTF-8 string to UTF-16 little-endian bytes (BMP only).
func utf16LEEncode(s string) []byte {
	var buf bytes.Buffer
	for _, r := range s {
		if r > 0xFFFF {
			r = 0xFFFD
		}
		buf.WriteByte(byte(r & 0xFF))
		buf.WriteByte(byte(r >> 8))
	}
	return buf.Bytes()
}

// ── Execution context wrappers ────────────────────────────────────────────────

// wrapWMI launches the command via Win32_Process.Create (T1047 — WMI execution).
// The child process inherits a different parent-process lineage than a direct
// powershell/cmd spawn, bypassing parent-process chain detection.
func wrapWMI(cmd, executor string) (newCmd, newExecutor string) {
	inner := shellInvocation(cmd, executor)
	escaped := strings.ReplaceAll(inner, `"`, "`\"")
	return `([wmiclass]"Win32_Process").Create("` + escaped + `")`, "powershell"
}

// wrapScheduledTask launches the command via schtasks (T1053.005 — Scheduled Task).
// The task is created, run once, and deleted in the same PS expression.
// Exercises the Task Scheduler service code path, which many EDRs monitor
// separately from direct process creation.
func wrapScheduledTask(cmd, executor string) (newCmd, newExecutor string) {
	inner := shellInvocation(cmd, executor)
	escaped := strings.ReplaceAll(inner, `"`, `\"`)
	wrapped := `$tn = "BAS-VarTask"; ` +
		`schtasks /create /f /tn $tn /tr "` + escaped + `" /sc once /st 00:00; ` +
		`Start-Sleep -Seconds 1; ` +
		`schtasks /run /tn $tn; ` +
		`Start-Sleep -Seconds 3; ` +
		`schtasks /delete /tn $tn /f`
	return wrapped, "powershell"
}

// wrapCOM launches the command via WScript.Shell (T1559.001 — Component Object Model).
// The COM object is instantiated from PowerShell, spawning the child through the
// COM infrastructure rather than CreateProcess — a common script-based LOLBin path.
func wrapCOM(cmd, executor string) (newCmd, newExecutor string) {
	inner := shellInvocation(cmd, executor)
	escaped := strings.ReplaceAll(inner, `"`, `\"`)
	return `$s = New-Object -COM WScript.Shell; $s.Run("` + escaped + `", 0, $true)`, "powershell"
}

// shellInvocation builds the full process command line for an inner command.
// Used when wrapping in WMI / schtasks / COM where a complete shell invocation
// string (not just the payload) is required.
func shellInvocation(cmd, executor string) string {
	if executor == "cmd" {
		return `cmd /c ` + cmd
	}
	return `powershell -NonInteractive -NoProfile -Command ` + cmd
}
