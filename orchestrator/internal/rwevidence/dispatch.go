package rwevidence

import (
	"context"
	"strings"

	"github.com/audspect/bas/internal/controlval"
)

// StepInput is the minimal shape EvaluateStep needs from one dispatched
// scenario step's outcome. The caller (internal/api) maps its own
// scenario.Step/models.SimulationResult onto this -- rwevidence never
// imports scenario or models, keeping it a pure evidence/logic package.
type StepInput struct {
	RunID       string
	Action      string // scenario.TaskID(step.TechniqueID, step.Name), built by the caller
	TechniqueID string
	StepName    string
	CheckResult string // "pass"/"fail"/"skipped"/"error"/"vetoed", mirrors models.CheckResult's string values
	Details     string // the step's raw output/detail text, for skip-pattern matching
}

// reconnaissanceStepNames are the modeled-technique steps that only
// enumerate/observe and never attempt the destructive behavior. Matched
// against StepInput.StepName.
var reconnaissanceStepNames = map[string]bool{
	"VSS Snapshot Enumeration":         true,
	"VSS + Backup Catalog Enumeration": true,
}

// classifyRansomwareStep is the first stage of EvaluateStep's decision tree
// (spec section B, rules 1-3). modeled reports whether TechniqueID is one of
// the 3 this package supports. isAttempt reports whether this step tried
// the destructive/attempted behavior (false for recon and for unmodeled
// techniques). specificReason is set whenever this function alone can
// already determine the row's fate without calling any evaluator --
// "technique_not_mapped", "not_an_attempt", "gate_not_confirmed",
// "no_target_precondition", or "skip_unclassified". It is empty when the
// attempt genuinely ran and needs real evaluation (Task 3).
func classifyRansomwareStep(in StepInput) (modeled bool, isAttempt bool, specificReason string) {
	switch in.TechniqueID {
	case "T1490", "T1486", "T1567.002":
		modeled = true
	default:
		return false, false, "technique_not_mapped"
	}

	if reconnaissanceStepNames[in.StepName] {
		return true, false, "not_an_attempt"
	}

	if in.CheckResult == "vetoed" {
		// scenario.Interpret can report ResultVetoed independently of any
		// scenario-authored safety gate (interpreter.go:75-89) -- Audspect's
		// own local destructive-action policy refused to run the step, for
		// any framework. Treating this as a genuine attempt would fabricate
		// Prevention/Recovery/Detection/DataProtection findings for a
		// technique never actually tried -- found during final review.
		return true, false, "vetoed_by_policy"
	}

	if in.CheckResult != "skipped" {
		return true, true, ""
	}

	lower := strings.ToLower(in.Details)
	switch {
	case strings.Contains(lower, "bas_confirm_vss_delete not set"):
		return true, true, "gate_not_confirmed"
	case strings.Contains(lower, "no c: vss shadow copies exist"):
		return true, true, "no_target_precondition"
	default:
		return true, true, "skip_unclassified"
	}
}

// DetectionLookup stands in for a real detection-profile query (the
// existing windows_vss_inhibition-style verification) until a real
// rwdetect bridge lands -- fake-backed only in this slice, same discipline
// as RecoveryObserver.
type DetectionLookup interface {
	LookupDetection(ctx context.Context, key AttemptKey) (tested bool, verified bool, reason string, err error)
}

// FakeDetectionLookup is keyed exactly like FakeRecoveryObserver: an
// uncaptured key means "never evaluated", not a guessed verdict.
type FakeDetectionLookup struct {
	Tested   map[string]bool
	Verified map[string]bool
	Reason   map[string]string
	Err      map[string]error
}

func (f *FakeDetectionLookup) LookupDetection(_ context.Context, key AttemptKey) (bool, bool, string, error) {
	k := recoveryKey(key) // same RunID/TechniqueID/Action identity, reused rather than reinvented
	if err, ok := f.Err[k]; ok {
		return false, false, "", err
	}
	return f.Tested[k], f.Verified[k], f.Reason[k], nil
}

// DataProtectionLookup stands in for a real DLP Validation Suite query
// until this is wired to reporting's actual VerificationResult -- fake-
// backed only in this slice.
type DataProtectionLookup interface {
	LookupDataProtection(ctx context.Context, key AttemptKey) (status string, reason string, err error)
}

// FakeDataProtectionLookup: an uncaptured key returns "" (which
// DataProtectionFromDLPResult already treats as unrecognized -> fail-closed
// SkipInsufficientEvidence), never a guessed status.
type FakeDataProtectionLookup struct {
	Status map[string]string
	Reason map[string]string
	Err    map[string]error
}

func (f *FakeDataProtectionLookup) LookupDataProtection(_ context.Context, key AttemptKey) (string, string, error) {
	k := recoveryKey(key)
	if err, ok := f.Err[k]; ok {
		return "", "", err
	}
	return f.Status[k], f.Reason[k], nil
}

// StepDependencies bundles the fake-backed observers/lookups EvaluateStep
// needs for a genuine attempt. All 5 are nil-safe: a zero-value
// StepDependencies is fine for a step that classifyRansomwareStep already
// resolved without needing any of them (recon, unmodeled, gated, etc).
type StepDependencies struct {
	Prevention     controlval.Provider
	Recovery       RecoveryObserver
	Containment    ContainmentObserver
	Detection      DetectionLookup
	DataProtection DataProtectionLookup
}

var allCapabilities = []Capability{
	CapabilityPrevention, CapabilityDetection, CapabilityContainment,
	CapabilityRecovery, CapabilityDataProtection,
}

// undecidedApplicability names the (technique, capability) pairs with no
// decided applicability rule in the existing code -- found during this
// sub-project's spec self-review. Never invented here; each pair is
// recorded as SKIPPED/not_tested/applicability_undecided, distinct from
// both not_applicable (a decided no) and technique_not_mapped (the
// technique itself isn't modeled).
var undecidedApplicability = map[string]map[Capability]bool{
	"T1486":     {CapabilityDataProtection: true},
	"T1567.002": {CapabilityPrevention: true, CapabilityRecovery: true, CapabilityDetection: true},
}

// notApplicable names the (technique, capability) pairs with a DECIDED "no"
// in existing code (T1490's Containment/DataProtection, T1486's Recovery,
// T1567.002's Containment).
var notApplicable = map[string]map[Capability]string{
	"T1490":     {CapabilityContainment: "T1490 is a single-host VSS/backup-catalog deletion -- it has no lateral-reachability dimension to contain", CapabilityDataProtection: "T1490 destroys recovery mechanisms; it does not access, stage, or exfiltrate data"},
	"T1486":     {CapabilityRecovery: "T1486 is about whether files get encrypted, not whether recovery mechanisms survive -- that is T1490's domain"},
	"T1567.002": {CapabilityContainment: "containment of an exfil channel is covered by the DataProtection capability, not a separate Containment check"},
}

func techniqueFor(id string) Technique {
	switch id {
	case "T1490":
		return VSSInhibition()
	case "T1486":
		return DataEncryptedForImpact()
	case "T1567.002":
		return DataExfiltrationToCloud()
	}
	return Technique{}
}

// EvaluateStep is the integration entry point: classify, then either return
// an explicit not-tested/not-applicable row for every capability (coverage
// gap paths) or evaluate the complete applicable set for a genuine attempt.
// Never returns a partial set -- every call returns exactly 5 rows, one per
// capability, so a caller can never mistake "only 2 rows written" for "the
// other 3 don't apply".
func EvaluateStep(in StepInput, deps StepDependencies) []CapabilityResult {
	modeled, isAttempt, specificReason := classifyRansomwareStep(in)

	if !modeled {
		return notTestedForAll(in, specificReason)
	}
	tech := techniqueFor(in.TechniqueID)
	if !isAttempt {
		return notTestedForAll(in, specificReason)
	}
	if specificReason != "" { // gate_not_confirmed / no_target_precondition / skip_unclassified
		return notTestedForAll(in, specificReason)
	}

	key := AttemptKey{RunID: in.RunID, TechniqueID: in.TechniqueID, Action: in.Action}
	out := make([]CapabilityResult, 0, 5)
	for _, cap := range allCapabilities {
		if reason, ok := notApplicable[in.TechniqueID][cap]; ok {
			out = append(out, NotApplicable(cap, tech, reason))
			continue
		}
		if undecidedApplicability[in.TechniqueID][cap] {
			// NotTested, not NotApplicable: this is an undecided "we don't
			// know yet", never a decided "no" -- using NotApplicable here
			// would wrongly set skip_reason=not_applicable, contradicting
			// the spec's own table (section B), which pins this case to
			// skip_reason=not_tested.
			out = append(out, withSpecificReason(NotTested(cap, tech, "applicability not yet decided for this (technique, capability) pair"), "applicability_undecided"))
			continue
		}
		out = append(out, evaluateApplicableCapability(cap, tech, key, deps))
	}
	return out
}

func evaluateApplicableCapability(cap Capability, tech Technique, key AttemptKey, deps StepDependencies) CapabilityResult {
	ctx := context.Background()
	switch cap {
	case CapabilityPrevention:
		ck := controlval.CorrelationKey{RunID: key.RunID, Action: key.Action}
		obs, err := deps.Prevention.Observe(ctx, ck)
		return PreventionFromValidation(tech, controlval.Evaluate(PreventionExpectationFor(tech), &obs, err))
	case CapabilityRecovery:
		result, err := deps.Recovery.ObserveSurvival(ctx, key)
		return RecoveryResultFor(tech, result, err, "")
	case CapabilityContainment:
		result, err := deps.Containment.ObserveContainment(ctx, key)
		return ContainmentResultFor(tech, result, err, "")
	case CapabilityDetection:
		tested, verified, reason, err := deps.Detection.LookupDetection(ctx, key)
		if err != nil {
			return CapabilityResult{Capability: CapabilityDetection, TechniqueID: tech.MitreID, Verdict: controlval.VerdictError, Reason: "detection lookup failed: " + err.Error()}
		}
		return DetectionFromProfileResult(tech, tested, verified, reason)
	case CapabilityDataProtection:
		status, reason, err := deps.DataProtection.LookupDataProtection(ctx, key)
		if err != nil {
			return CapabilityResult{Capability: CapabilityDataProtection, TechniqueID: tech.MitreID, Verdict: controlval.VerdictError, Reason: "data-protection lookup failed: " + err.Error()}
		}
		return DataProtectionFromDLPResult(tech, status, reason)
	}
	return CapabilityResult{}
}

func notTestedForAll(in StepInput, specificReason string) []CapabilityResult {
	tech := techniqueFor(in.TechniqueID)
	if tech.MitreID == "" {
		tech.MitreID = in.TechniqueID
	}
	out := make([]CapabilityResult, 0, 5)
	for _, cap := range allCapabilities {
		cr := NotTested(cap, tech, specificReasonText(specificReason))
		out = append(out, withSpecificReason(cr, specificReason))
	}
	return out
}

// specificReasonText renders a short code into a human-readable Reason --
// the existing CapabilityResult.Reason field stays prose; specific_reason
// (set on the persisted row by the Task 4 store, carried here as an
// unexported sidecar) is the queryable short code.
func specificReasonText(code string) string {
	switch code {
	case "technique_not_mapped":
		return "this technique has no rwevidence capability model yet"
	case "not_an_attempt":
		return "this step observes/enumerates, it does not attempt the destructive behavior"
	case "gate_not_confirmed":
		return "the scenario's own safety gate was not confirmed, so the attempt never ran"
	case "no_target_precondition":
		return "no viable target existed for the attempt to run against"
	case "skip_unclassified":
		return "the step reported skipped for a reason this integration does not yet recognize"
	case "vetoed_by_policy":
		return "Audspect's own destructive-action policy prevented this step from running -- it was never actually attempted"
	case "applicability_undecided":
		return "applicability not yet decided for this (technique, capability) pair"
	}
	return code
}

func withSpecificReason(cr CapabilityResult, code string) CapabilityResult {
	cr.SpecificReason = code
	return cr
}
