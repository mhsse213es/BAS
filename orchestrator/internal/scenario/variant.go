package scenario

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Variant dimensions ────────────────────────────────────────────────────────
//
// The Variant Engine multiplies the base ART atomic test library at dispatch
// time rather than at seed time. Four orthogonal dimensions apply:
//
//   Platform     — operating system target (windows default; linux supported)
//   Encoding     — how the command string is represented on the wire (PS only)
//   Privilege    — execution context the agent resolves for the step
//   ExecContext  — which Windows launch mechanism invokes the command
//
// The base test is {windows / plain / user / direct} — no transforms.
//
// Realistic per-step variant counts (after filtering via CanApply):
//   PowerShell: 33   (3 enc × 3 priv × 4 ctx − 3 system+com combos)
//   CMD:        11   (1 enc × 3 priv × 4 ctx − 1 system+com combo)
//
// Count constants are computed from CanApply at package init so they stay
// consistent with the capability rules without manual bookkeeping.

// Platforms lists the OS targets the Variant Engine supports.
// "linux" is included now so VariantSpec can carry the dimension without a
// later breaking schema change; Windows-only ART steps will CanApply=false
// for linux variants until a Linux agent path is wired.
var Platforms = []string{"windows", "linux"}

// PSEncodings are the encoding transforms available for PowerShell steps.
var PSEncodings = []string{"plain", "base64", "charcode"}

// Privileges are the execution-context privilege levels available to all steps.
var Privileges = []string{"user", "admin", "system"}

// ExecContexts are the Windows launch mechanisms available for all steps.
var ExecContexts = []string{"direct", "wmi", "scheduled-task", "com"}

// ExecContextTechnique maps each non-direct exec context to the ATT&CK technique
// it exercises as a proxy. A single run can therefore produce findings for both the
// primary technique (e.g. T1059.001) and the proxy (e.g. T1047 via WMI).
var ExecContextTechnique = map[string]string{
	"wmi":            "T1047",     // Windows Management Instrumentation
	"scheduled-task": "T1053.005", // Scheduled Task/Job: Scheduled Task
	"com":            "T1559.001", // Inter-Process Communication: Component Object Model
}

// psVariantsPerStep / cmdVariantsPerStep are computed at package init from
// CanApply so the counts are always in sync with capability rules.
var (
	psVariantsPerStep  = computeStepVariantCount("powershell")
	cmdVariantsPerStep = computeStepVariantCount("cmd")
)

// computeStepVariantCount enumerates all dimension combos for the given executor
// and counts those that pass CanApply. Called once at package init.
func computeStepVariantCount(executor string) int {
	encs := PSEncodings
	if executor == "cmd" {
		encs = []string{"plain"}
	}
	n := 0
	for _, enc := range encs {
		for _, priv := range Privileges {
			for _, ctx := range ExecContexts {
				if CanApply(VariantSpec{Platform: "windows", Encoding: enc, Privilege: priv, ExecContext: ctx}, executor) {
					n++
				}
			}
		}
	}
	return n
}

// VariantSpec selects one position in the variant space for a single step.
// The zero value is the base test (windows / plain / user / direct) — no transforms.
type VariantSpec struct {
	// Platform is the OS target.
	//   "windows" — default; the only platform ART tests run on today
	//   "linux"   — future; Linux agent path not yet wired
	Platform string `json:"platform"`

	// Encoding controls the command representation (PowerShell steps only).
	//   "plain"    — command sent as-is (default)
	//   "base64"   — UTF-16LE base64 via powershell -EncodedCommand
	//   "charcode" — [char]N+[char]N via IEX(); evades keyword-match rules
	Encoding string `json:"encoding"`

	// Privilege declares the required execution context.
	//   "user"   — logged-in interactive user (default; realistic phishing model)
	//   "admin"  — local administrator
	//   "system" — NT AUTHORITY\SYSTEM (requires agent elevation)
	//
	// This is the *requested* privilege. ExecResult.ExecutedAs carries the
	// actual privilege context the agent used — both are present in findings.
	Privilege string `json:"privilege"`

	// ExecContext selects the Windows launch mechanism.
	//   "direct"          — executor runs the command directly (default)
	//   "wmi"             — Win32_Process.Create (T1047)
	//   "scheduled-task"  — schtasks + run (T1053.005)
	//   "com"             — WScript.Shell COM object (T1559.001)
	ExecContext string `json:"execContext"`
}

// ID returns a stable 16-char hex identifier for this variant of a given technique.
// The ID is deterministic and suitable for deduplication, caching, findings
// correlation, and coverage heatmaps.
func (s VariantSpec) ID(techniqueID string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		techniqueID,
		norm(s.Platform, "windows"),
		norm(s.Encoding, "plain"),
		norm(s.Privilege, "user"),
		norm(s.ExecContext, "direct"),
	}, "|")))
	return hex.EncodeToString(h[:8])
}

// IsBase returns true when the spec is the unmodified base test
// (windows / plain / user / direct) — no transforms applied.
func (s VariantSpec) IsBase() bool {
	return norm(s.Platform, "windows") == "windows" &&
		norm(s.Encoding, "plain") == "plain" &&
		norm(s.Privilege, "user") == "user" &&
		norm(s.ExecContext, "direct") == "direct"
}

// Sig returns a short human-readable signature, e.g. "base64/admin/wmi".
// Returns "base" for the zero variant.
func (s VariantSpec) Sig() string {
	plat := norm(s.Platform, "windows")
	enc := norm(s.Encoding, "plain")
	priv := norm(s.Privilege, "user")
	ctx := norm(s.ExecContext, "direct")
	if plat == "windows" && enc == "plain" && priv == "user" && ctx == "direct" {
		return "base"
	}
	var parts []string
	if plat != "windows" {
		parts = append(parts, plat)
	}
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

// ── CanApply ─────────────────────────────────────────────────────────────────

// CanApply reports whether spec is a valid, executable combination for a step
// with the given executor. Invalid combinations are never dispatched, and are
// excluded from variant counts so "Available Variants" numbers are defensible.
//
// Known invalid combinations:
//
//	system + com       — WScript.Shell.Run does not reliably spawn as SYSTEM
//	cmd + base64       — -EncodedCommand is PowerShell-only
//	cmd + charcode     — IEX([char]…) is PowerShell-only
//	linux + wmi        — Win32_Process is Windows-only
//	linux + schtasks   — Task Scheduler is Windows-only
//	linux + com        — WScript.Shell is Windows-only
//	linux + base64     — UTF-16LE -EncodedCommand is PowerShell-for-Windows only
//	linux + charcode   — IEX syntax is Windows PowerShell-only
func CanApply(spec VariantSpec, executor string) bool {
	platform := norm(spec.Platform, "windows")
	priv := norm(spec.Privilege, "user")
	ctx := norm(spec.ExecContext, "direct")
	enc := norm(spec.Encoding, "plain")

	if platform == "linux" {
		// Linux: only direct execution with plain encoding is valid today.
		return ctx == "direct" && enc == "plain"
	}

	// Windows: SYSTEM + COM is not reliable.
	if priv == "system" && ctx == "com" {
		return false
	}

	// Encoding transforms are PowerShell-only.
	if executor == "cmd" && (enc == "base64" || enc == "charcode") {
		return false
	}

	return true
}

// ── Count helpers ─────────────────────────────────────────────────────────────

// StepVariantCount returns the number of valid executable variants for a single
// step with the given executor (including the base variant). Results are derived
// from CanApply so they stay consistent with capability rules.
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

// ComputeVariantCount sums the per-step valid variant counts across a step list.
func ComputeVariantCount(steps []ScenarioStep) int {
	n := 0
	for _, s := range steps {
		n += StepVariantCount(s.Executor)
	}
	return n
}

// VariantCountFromExecutorCounts computes the total available variant count
// given executor breakdown counts (no step list required).
func VariantCountFromExecutorCounts(psSteps, cmdSteps int) int {
	return psSteps*psVariantsPerStep + cmdSteps*cmdVariantsPerStep
}

// QueryVariantCount queries art_atomic_tests for the executor breakdown and
// returns (psCount, cmdCount, variantTotal). The variant total reflects only
// valid CanApply combinations. Errors are non-fatal — caller degrades gracefully.
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
// Returns the step unchanged when spec.IsBase() or !CanApply(spec, step.Executor).
//
// The returned step carries:
//   - Transformed Command and Executor (encoding + exec context wrappers)
//   - ProxyTechniqueID for non-direct exec contexts (T1047 / T1053.005 / T1559.001)
//   - RequiresPriv set from spec.Privilege (ExecResult.RequestedPriv mirrors it;
//     ExecResult.ExecutedAs carries the actual privilege the agent used)
//   - Updated Name and TaskID to include the variant signature
func ApplyVariant(step ScenarioStep, spec VariantSpec) ScenarioStep {
	if spec.IsBase() {
		return step
	}
	if !CanApply(spec, step.Executor) {
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

	// 3. ATT&CK proxy technique for the exec context wrapper
	if t, ok := ExecContextTechnique[norm(spec.ExecContext, "direct")]; ok {
		v.ProxyTechniqueID = t
	}

	// 4. Privilege: sets the requested privilege tier.
	//    ExecResult.RequestedPriv mirrors RequiresPriv on the result.
	//    ExecResult.ExecutedAs records what the agent actually used — callers
	//    should surface both to operators so "Blocked as User / Allowed as Admin"
	//    findings are immediately actionable.
	if p := norm(spec.Privilege, "user"); p != "user" {
		v.RequiresPriv = p
	}

	// 5. Update name + TaskID with the variant signature
	sig := spec.Sig()
	v.Name = step.Name + " [" + sig + "]"
	v.TaskID = TaskID(v.TechniqueID, v.Name)
	return v
}

// ── Encoding wrappers ─────────────────────────────────────────────────────────

// psWrapBase64 encodes a PowerShell command as UTF-16LE base64 and rewrites
// it as "powershell -EncodedCommand <b64>". Bypasses static rules that scan
// for plaintext keywords like "Invoke-Mimikatz".
func psWrapBase64(cmd string) string {
	b64 := base64.StdEncoding.EncodeToString(utf16LEEncode(cmd))
	return "powershell -NonInteractive -NoProfile -EncodedCommand " + b64
}

// psWrapCharcode converts a PowerShell command to [char]N+[char]N executed via
// IEX. Each character becomes an integer ordinal, defeating keyword-based
// detection without any external encoding step.
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

// wrapWMI launches the command via Win32_Process.Create (T1047).
// The child process has a different parent-process lineage than a direct
// powershell/cmd spawn, bypassing parent-process chain detection.
func wrapWMI(cmd, executor string) (newCmd, newExecutor string) {
	inner := shellInvocation(cmd, executor)
	escaped := strings.ReplaceAll(inner, `"`, "`\"")
	return `([wmiclass]"Win32_Process").Create("` + escaped + `")`, "powershell"
}

// wrapScheduledTask launches the command via schtasks (T1053.005).
// The task is created, run once, and deleted in the same PS expression.
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

// wrapCOM launches the command via WScript.Shell (T1559.001).
// The COM object is instantiated from PowerShell, spawning the child through
// the COM infrastructure rather than CreateProcess.
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
