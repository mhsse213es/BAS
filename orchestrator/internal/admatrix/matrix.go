// Package admatrix is the AD capability coverage matrix with an honest
// validation-level spine. For each AD attack capability it records -- grounded
// in the real adprimitive catalog, never a hand-maintained copy -- the required
// environment to truly execute, the execution method and any reused content,
// the expected postconditions, the evidence and cleanup a real run would need,
// and the validation level actually demonstrated so far.
//
// Its reason to exist is requirement #3/#5 of the AD coverage expansion: keep
// model-simulated, endpoint-executed and real-AD-validated results DISTINCT, so
// a planned/graph-reachable attack path is never reported as an executed one.
// Simulate reuses adchain + adlab (the synthetic-env planner) and its result is
// structurally pinned to LevelModelSimulated -- there is no path by which a
// simulation yields a higher level.
//
// It composes existing packages and adds no new inventory, planner, or env
// model: adprimitive (catalog + schema), adchain (reachability), adlab
// (env-backed resolver), adenv (synthetic model), adgate (authorization, used
// only by callers/tests). It executes nothing and does not touch dispatchRun.
package admatrix

import (
	"github.com/audspect/bas/internal/adchain"
	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adlab"
	"github.com/audspect/bas/internal/adprimitive"
)

// ValidationLevel is the honest claim-strength of a capability's validation,
// strictly increasing. A model/graph result is LevelModelSimulated and must
// never be reported as any higher level.
type ValidationLevel int

const (
	LevelModelSimulated    ValidationLevel = iota // planned/graph-reachable in a synthetic env only
	LevelEndpointExecuted                         // executed on an endpoint, no real domain
	LevelRealADExecuted                           // executed against a real domain
	LevelTelemetryObserved                        // outcome proven by observed telemetry/detection
)

func (l ValidationLevel) String() string {
	switch l {
	case LevelModelSimulated:
		return "model_simulated"
	case LevelEndpointExecuted:
		return "endpoint_executed"
	case LevelRealADExecuted:
		return "real_ad_executed"
	case LevelTelemetryObserved:
		return "telemetry_observed"
	default:
		return "unknown"
	}
}

// RequiredEnvironment is the minimum environment a capability needs to truly
// execute (beyond being modelled in a synthetic graph).
type RequiredEnvironment string

const (
	EnvSyntheticModel   RequiredEnvironment = "synthetic_model"    // model-only; cannot execute for real
	EnvDomainJoinedHost RequiredEnvironment = "domain_joined_host" // a domain-joined endpoint
	EnvDomainController RequiredEnvironment = "domain_controller"  // a real DC / CA
)

// Entry is the coverage-matrix record for one AD capability, grounded in a real
// adprimitive.Primitive.
type Entry struct {
	PrimitiveID            string
	TechniqueID            string
	RequiredEnvToExecute   RequiredEnvironment
	ExecutionMethod        string // "synthetic-predicate" | "art-atomic" | "caldera-ability" | "unimplemented"
	ReuseSource            string // non-empty when existing content/predicate is reused
	ExpectedPostconditions []adprimitive.Capability
	EvidenceRequirements   []string
	Cleanup                []string
	CurrentValidation      ValidationLevel // honest: the highest level actually demonstrated so far
}

// SimResult is the typed outcome of a synthetic-env reachability check. Level
// is ALWAYS LevelModelSimulated: there is no field or constructor that raises a
// simulated result to an executed level, so reporting code that reads Level
// cannot present a planned path as an executed attack.
type SimResult struct {
	Target    adprimitive.Capability
	Reachable bool
	Steps     []adprimitive.Primitive
	Level     ValidationLevel
}

// Simulate reports whether target is reachable from held in the given synthetic
// environment, reusing adlab's env-backed resolver and adchain's planner. It
// executes nothing; the result is always LevelModelSimulated.
func Simulate(catalog []adprimitive.Primitive, env adenv.Environment, attacker string, held []adprimitive.Capability, target adprimitive.Capability) SimResult {
	resolver := adlab.NewEnvResolver(env, attacker)
	steps, ok := adchain.Plan(catalog, held, target, resolver)
	if !ok {
		steps = nil
	}
	return SimResult{Target: target, Reachable: ok, Steps: steps, Level: LevelModelSimulated}
}

// ADCS per-primitive reuse/evidence/cleanup metadata. Keyed by the real catalog
// ID so a missing key surfaces as empty and is caught by the grounding test.
var adcsReuse = map[string]string{
	"adcs-esc1": "adenv.IsESC1Vulnerable + adlab EnvResolver(esc1_vulnerable_template)",
	"adcs-esc2": "adenv.IsESC2Vulnerable + adlab EnvResolver(esc2_vulnerable_template)",
	"adcs-esc3": "adenv.IsESC3Vulnerable + adlab EnvResolver(esc3_vulnerable_template)",
	"adcs-esc4": "adenv.HasTemplateWriteAccess + adlab EnvResolver(esc4_template_write_access)",
}

var adcsEvidence = map[string][]string{
	"adcs-esc1": {"certificate issued with an attacker-chosen subject (CA audit / event 4886/4887)", "successful PKINIT authentication as the impersonated principal using that certificate"},
	"adcs-esc2": {"certificate issued from an Any-Purpose template", "certificate used for client authentication as a non-held principal"},
	"adcs-esc3": {"enrollment-agent certificate issued", "on-behalf-of certificate request succeeded for a target principal"},
	"adcs-esc4": {"template ACL modification event on the template object", "template reconfigured to an ESC1-equivalent state"},
}

var adcsCleanup = map[string][]string{
	"adcs-esc1": {"revoke the issued certificate", "remove any attacker-created enrollment rights"},
	"adcs-esc2": {"revoke the issued certificate"},
	"adcs-esc3": {"revoke the enrollment-agent and on-behalf-of certificates"},
	"adcs-esc4": {"restore the template's original ACL and configuration"},
}

// ADCSEntries returns the coverage-matrix rows for ADCS ESC1-4, iterating the
// real adprimitive.ADCSCatalog so postconditions and IDs cannot drift from it.
func ADCSEntries() []Entry {
	out := make([]Entry, 0, len(adprimitive.ADCSCatalog))
	for _, p := range adprimitive.ADCSCatalog {
		out = append(out, Entry{
			PrimitiveID:            p.ID,
			TechniqueID:            p.TechniqueID,
			RequiredEnvToExecute:   EnvDomainController, // ESC abuse needs a real CA/DC
			ExecutionMethod:        "synthetic-predicate",
			ReuseSource:            adcsReuse[p.ID],
			ExpectedPostconditions: p.Postconditions,
			EvidenceRequirements:   adcsEvidence[p.ID],
			Cleanup:                adcsCleanup[p.ID],
			CurrentValidation:      LevelModelSimulated,
		})
	}
	return out
}

var aclReuse = map[string]string{
	"acl-forcechangepassword-abuse":  "adlab EnvResolver(acl_right_held:ForceChangePassword)",
	"acl-genericall-takeover":        "adlab EnvResolver(acl_right_held:GenericAll)",
	"acl-addmember-privileged-group": "adlab EnvResolver(acl_right_held:AddMember)",
	"acl-addself-privileged-group":   "adlab EnvResolver(acl_right_held:AddSelf)",
}

var aclEvidence = map[string][]string{
	"acl-forcechangepassword-abuse":  {"target account password reset (event 4724)", "successful authentication as the target account"},
	"acl-genericall-takeover":        {"attacker-driven modification of the target object", "successful control/authentication as the target"},
	"acl-addmember-privileged-group": {"group membership change on a privileged group (event 4728/4732)", "attacker principal present in the privileged group"},
	"acl-addself-privileged-group":   {"self-add membership change on a privileged group (event 4728/4732)", "attacker principal present in the privileged group"},
}

var aclCleanup = map[string][]string{
	"acl-forcechangepassword-abuse":  {"restore the target account's original password", "notify the account owner"},
	"acl-genericall-takeover":        {"revert attacker modifications to the target object"},
	"acl-addmember-privileged-group": {"remove the attacker principal from the privileged group"},
	"acl-addself-privileged-group":   {"remove the attacker principal from the privileged group"},
}

// ACLEntries returns the coverage-matrix rows for the ACL-abuse catalog
// (ForceChangePassword, GenericAll, AddMember, AddSelf), iterating the real
// adprimitive.ACLAbuseCatalog so IDs and postconditions cannot drift.
func ACLEntries() []Entry {
	out := make([]Entry, 0, len(adprimitive.ACLAbuseCatalog))
	for _, p := range adprimitive.ACLAbuseCatalog {
		out = append(out, Entry{
			PrimitiveID:            p.ID,
			TechniqueID:            p.TechniqueID,
			RequiredEnvToExecute:   EnvDomainJoinedHost, // ACL abuse runs from a domain-joined host
			ExecutionMethod:        "synthetic-predicate",
			ReuseSource:            aclReuse[p.ID],
			ExpectedPostconditions: p.Postconditions,
			EvidenceRequirements:   aclEvidence[p.ID],
			Cleanup:                aclCleanup[p.ID],
			CurrentValidation:      LevelModelSimulated,
		})
	}
	return out
}
