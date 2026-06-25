package scenario

// VariantDepth controls how many variants are generated per step when a scenario
// is dispatched. Operators select depth at run-time; "none" is the default to
// avoid accidentally expanding a 100-step scenario 33× without intent.
//
// Depth      Extra steps / PS step   Total steps / PS step
//   none          0                       1  (base only)
//   quick         4                       5
//   standard     14                      15
//   full         32                      33  (all valid combos − base)
//
// CMD steps have fewer valid variants (no encoding transforms); CanApply
// filters the curated lists so CMD steps get ~3/8/10 extras at quick/std/full.
type VariantDepth string

const (
	VariantDepthNone     VariantDepth = "none"     // 1 per step — base test only
	VariantDepthQuick    VariantDepth = "quick"     // ~5 per PS step, ~4 per CMD step
	VariantDepthStandard VariantDepth = "standard"  // ~15 per PS step, ~9 per CMD step
	VariantDepthFull     VariantDepth = "full"       // all valid combos (33/11 per step)
)

// quickAdditional is the curated set of additional variant specs dispatched at
// Quick depth. Each spec is in priority order: encoding first (highest bypass
// signal), then privilege, then exec context, then a key cross-product combo.
// The base spec (plain/user/direct) is always the first step and is NOT listed here.
var quickAdditional = []VariantSpec{
	{Encoding: "base64",   Privilege: "user",  ExecContext: "direct"},        // -EncodedCommand bypass
	{Encoding: "charcode", Privilege: "user",  ExecContext: "direct"},        // IEX([char]N) bypass
	{Encoding: "plain",    Privilege: "admin", ExecContext: "direct"},        // admin privilege
	{Encoding: "plain",    Privilege: "user",  ExecContext: "wmi"},           // T1047 proxy
}

// standardAdditional extends quickAdditional with the remaining high-value combos
// for a ~15-variant per step budget on PS steps.
var standardAdditional = []VariantSpec{
	// ── Quick set ──────────────────────────────────────────────────────────────
	{Encoding: "base64",   Privilege: "user",   ExecContext: "direct"},
	{Encoding: "charcode", Privilege: "user",   ExecContext: "direct"},
	{Encoding: "plain",    Privilege: "admin",  ExecContext: "direct"},
	{Encoding: "plain",    Privilege: "user",   ExecContext: "wmi"},
	// ── Extend ─────────────────────────────────────────────────────────────────
	{Encoding: "plain",    Privilege: "user",   ExecContext: "scheduled-task"}, // T1053.005
	{Encoding: "plain",    Privilege: "user",   ExecContext: "com"},            // T1559.001
	{Encoding: "plain",    Privilege: "system", ExecContext: "direct"},         // SYSTEM privilege
	{Encoding: "base64",   Privilege: "admin",  ExecContext: "direct"},         // encoding + privilege
	{Encoding: "charcode", Privilege: "admin",  ExecContext: "direct"},         // stronger encoding + privilege
	{Encoding: "base64",   Privilege: "user",   ExecContext: "wmi"},            // encoding + T1047
	{Encoding: "charcode", Privilege: "user",   ExecContext: "wmi"},            // IEX + T1047
	{Encoding: "plain",    Privilege: "admin",  ExecContext: "wmi"},            // privilege + T1047
	{Encoding: "base64",   Privilege: "admin",  ExecContext: "wmi"},            // three-way combo
	{Encoding: "plain",    Privilege: "system", ExecContext: "wmi"},            // max priv + T1047
}

// allAdditionalSpecs enumerates every valid non-base variant for a given executor.
// Called for VariantDepthFull.
func allAdditionalSpecs(executor string) []VariantSpec {
	base := VariantSpec{Platform: "windows", Encoding: "plain", Privilege: "user", ExecContext: "direct"}
	encs := PSEncodings
	if executor == "cmd" {
		encs = []string{"plain"}
	}
	var out []VariantSpec
	for _, enc := range encs {
		for _, priv := range Privileges {
			for _, ctx := range ExecContexts {
				s := VariantSpec{Platform: "windows", Encoding: enc, Privilege: priv, ExecContext: ctx}
				if s == base {
					continue // base is always implicit — don't add it twice
				}
				if CanApply(s, executor) {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// SelectedSpecs returns the additional (non-base) variant specs to dispatch for
// a step with the given executor at the given depth. Returns nil for DepthNone.
// Invalid combinations are filtered by CanApply.
func SelectedSpecs(depth VariantDepth, executor string) []VariantSpec {
	switch depth {
	case VariantDepthNone, "":
		return nil
	case VariantDepthFull:
		return allAdditionalSpecs(executor)
	}

	// Quick and Standard: filter the curated lists by CanApply for this executor.
	src := quickAdditional
	if depth == VariantDepthStandard {
		src = standardAdditional
	}
	out := make([]VariantSpec, 0, len(src))
	for _, s := range src {
		if !s.IsBase() && CanApply(s, executor) {
			out = append(out, s)
		}
	}
	return out
}

// ExpandSteps returns a new step list where each base step is followed by its
// variant steps at the requested depth. The base step is always included first.
// If depth is None the original slice is returned unchanged.
//
// The variant steps carry BaseTaskID (base step's TaskID) and VariantSpecRef so
// the result processor can persist per-variant findings to scenario_variant_results.
func ExpandSteps(steps []ScenarioStep, depth VariantDepth) []ScenarioStep {
	if depth == VariantDepthNone || depth == "" {
		return steps
	}

	// Pre-compute capacity: base + additional per executor.
	// Rough upper bound; real count is filtered by CanApply inside SelectedSpecs.
	expanded := make([]ScenarioStep, 0, len(steps)*5)
	for _, base := range steps {
		expanded = append(expanded, base) // base step always first

		specs := SelectedSpecs(depth, base.Executor)
		for _, spec := range specs {
			v := ApplyVariant(base, spec)
			v.BaseTaskID     = base.TaskID
			specCopy         := spec
			v.VariantSpecRef = &specCopy
			expanded = append(expanded, v)
		}
	}
	return expanded
}

// ExpandedStepCount returns the total number of steps that would result from
// expanding the given base step count at the given depth. Used by the UI to
// warn operators before they accidentally queue 3300 executions.
func ExpandedStepCount(baseSteps int, depth VariantDepth, psSteps, cmdSteps int) int {
	switch depth {
	case VariantDepthNone, "":
		return baseSteps
	case VariantDepthFull:
		return psSteps*psVariantsPerStep + cmdSteps*cmdVariantsPerStep
	}

	// Quick and Standard: count valid specs per executor type.
	psExtras  := len(SelectedSpecs(depth, "powershell"))
	cmdExtras := len(SelectedSpecs(depth, "cmd"))
	// Other executors (bash, sh) get 0 extras
	other := baseSteps - psSteps - cmdSteps
	return psSteps*(1+psExtras) + cmdSteps*(1+cmdExtras) + other
}
