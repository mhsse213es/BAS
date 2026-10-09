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
	TelemetrySources       []string // the sensors/data sources that would observe this technique
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
	"adcs-esc6": "adenv.IsESC6Vulnerable + adlab EnvResolver(esc6_vulnerable_ca)",
	"adcs-esc8": "adenv.IsESC8Vulnerable + adlab EnvResolver(esc8_relayable_ca)",
}

var adcsEvidence = map[string][]string{
	"adcs-esc1": {"certificate issued with an attacker-chosen subject (CA audit / event 4886/4887)", "successful PKINIT authentication as the impersonated principal using that certificate"},
	"adcs-esc2": {"certificate issued from an Any-Purpose template", "certificate used for client authentication as a non-held principal"},
	"adcs-esc3": {"enrollment-agent certificate issued", "on-behalf-of certificate request succeeded for a target principal"},
	"adcs-esc4": {"template ACL modification event on the template object", "template reconfigured to an ESC1-equivalent state"},
	"adcs-esc6": {"certificate issued with an attacker-chosen SAN from a non-SAN template (CA audit 4886/4887)", "authentication as the impersonated principal using that certificate"},
	"adcs-esc8": {"NTLM authentication relayed to the CA web-enrollment endpoint", "certificate issued for a coerced/relayed principal (CA audit 4886/4887)"},
}

var adcsCleanup = map[string][]string{
	"adcs-esc1": {"revoke the issued certificate", "remove any attacker-created enrollment rights"},
	"adcs-esc2": {"revoke the issued certificate"},
	"adcs-esc3": {"revoke the enrollment-agent and on-behalf-of certificates"},
	"adcs-esc4": {"restore the template's original ACL and configuration"},
	"adcs-esc6": {"revoke the issued certificate", "clear EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA"},
	"adcs-esc8": {"revoke the issued certificate", "disable HTTP web enrollment or enforce EPA/HTTPS on the CA"},
}

var adcsTelemetry = map[string][]string{
	"adcs-esc1": {"AD CS CA issuance audit (events 4886/4887)", "Security event log: PKINIT/Kerberos logon (4768/4624)"},
	"adcs-esc2": {"AD CS CA issuance audit (events 4886/4887)", "Security event log: client-auth logon with the issued certificate"},
	"adcs-esc3": {"AD CS CA issuance audit (events 4886/4887) for the enrollment-agent and on-behalf-of requests"},
	"adcs-esc4": {"Directory Service Changes auditing on the template object (event 5136)"},
	"adcs-esc6": {"AD CS CA issuance audit (events 4886/4887)", "CA policy flag state (certutil -getreg policy\\EditFlags)"},
	"adcs-esc8": {"IIS/certsrv web-enrollment access logs", "AD CS CA issuance audit (events 4886/4887)", "authentication-coercion network signatures (e.g. PetitPotam/EfsRpc)"},
}

// ADCSEntries returns the coverage-matrix rows for the six ESC ABUSE
// primitives (ESC1-4, ESC6, ESC8), iterating the real adprimitive.ADCSCatalog
// so postconditions and IDs cannot drift from it.
//
// Deliberately skips adcs-esc-exposure-check: that read-only discovery
// primitive has its own real committed scenario and is tracked the same way
// the Kerberoasting baseline and the DCSync/ACL exposure-checks are
// (ContentState + CapabilityState's realScenarioEvidenceByID), never as a
// gap Entry here.
func ADCSEntries() []Entry {
	out := make([]Entry, 0, len(adprimitive.ADCSCatalog))
	for _, p := range adprimitive.ADCSCatalog {
		if p.ID == "adcs-esc-exposure-check" {
			continue
		}
		out = append(out, Entry{
			PrimitiveID:            p.ID,
			TechniqueID:            p.TechniqueID,
			RequiredEnvToExecute:   EnvDomainController, // ESC abuse needs a real CA/DC
			ExecutionMethod:        "synthetic-predicate",
			ReuseSource:            adcsReuse[p.ID],
			ExpectedPostconditions: p.Postconditions,
			EvidenceRequirements:   adcsEvidence[p.ID],
			TelemetrySources:       adcsTelemetry[p.ID],
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

var aclTelemetry = map[string][]string{
	"acl-forcechangepassword-abuse":  {"Security event log: account password reset (4724)", "Directory Service Access (4662)"},
	"acl-genericall-takeover":        {"Directory Service Changes on the target object (5136)", "Directory Service Access (4662)"},
	"acl-addmember-privileged-group": {"Security event log: security-enabled group member added (4728/4732/4756)"},
	"acl-addself-privileged-group":   {"Security event log: security-enabled group member added (4728/4732/4756)"},
}

// ACLEntries returns the coverage-matrix rows for the four ACL-ABUSE
// primitives (ForceChangePassword, GenericAll, AddMember, AddSelf),
// iterating the real adprimitive.ACLAbuseCatalog so IDs and postconditions
// cannot drift.
//
// Deliberately skips acl-privilege-exposure-check: that read-only discovery
// primitive has its own real committed scenario and is tracked the same way
// the Kerberoasting baseline and the DCSync exposure-check are (ContentState
// + CapabilityState's realScenarioEvidenceByID), never as a gap Entry here.
func ACLEntries() []Entry {
	out := make([]Entry, 0, len(adprimitive.ACLAbuseCatalog))
	for _, p := range adprimitive.ACLAbuseCatalog {
		if p.ID == "acl-privilege-exposure-check" {
			continue
		}
		out = append(out, Entry{
			PrimitiveID:            p.ID,
			TechniqueID:            p.TechniqueID,
			RequiredEnvToExecute:   EnvDomainJoinedHost, // ACL abuse runs from a domain-joined host
			ExecutionMethod:        "synthetic-predicate",
			ReuseSource:            aclReuse[p.ID],
			ExpectedPostconditions: p.Postconditions,
			EvidenceRequirements:   aclEvidence[p.ID],
			TelemetrySources:       aclTelemetry[p.ID],
			Cleanup:                aclCleanup[p.ID],
			CurrentValidation:      LevelModelSimulated,
		})
	}
	return out
}

var rbcdReuse = map[string]string{
	"rbcd-configure":   "adlab EnvResolver(acl_right_held:GenericWrite) + MachineAccountQuota foothold",
	"rbcd-impersonate": "adchain capability-chain from CapRBCDConfigured (S4U2Self+S4U2Proxy)",
}

var rbcdEvidence = map[string][]string{
	"rbcd-configure":   {"msDS-AllowedToActOnBehalfOfOtherIdentity written on the target computer object", "attacker-controlled principal named in the delegation attribute"},
	"rbcd-impersonate": {"S4U2Self/S4U2Proxy service-ticket request (event 4769) impersonating a privileged user", "successful access to the target service as the impersonated principal"},
}

var rbcdCleanup = map[string][]string{
	"rbcd-configure":   {"clear msDS-AllowedToActOnBehalfOfOtherIdentity on the target", "remove any attacker-created computer account"},
	"rbcd-impersonate": {"purge forged/obtained service tickets"},
}

var rbcdTelemetry = map[string][]string{
	"rbcd-configure":   {"Directory Service Changes: msDS-AllowedToActOnBehalfOfOtherIdentity write (5136)", "computer-account creation (4741)"},
	"rbcd-impersonate": {"Security event log: Kerberos service-ticket request (4769) with S4U2Self/S4U2Proxy"},
}

// RBCDEntries returns the coverage-matrix rows for Resource-Based Constrained
// Delegation (configure -> impersonate), iterating the real
// adprimitive.RBCDCatalog so IDs and postconditions cannot drift.
func RBCDEntries() []Entry {
	out := make([]Entry, 0, len(adprimitive.RBCDCatalog))
	for _, p := range adprimitive.RBCDCatalog {
		out = append(out, Entry{
			PrimitiveID:            p.ID,
			TechniqueID:            p.TechniqueID,
			RequiredEnvToExecute:   EnvDomainController, // RBCD abuse needs a real domain
			ExecutionMethod:        "synthetic-predicate",
			ReuseSource:            rbcdReuse[p.ID],
			ExpectedPostconditions: p.Postconditions,
			EvidenceRequirements:   rbcdEvidence[p.ID],
			TelemetrySources:       rbcdTelemetry[p.ID],
			Cleanup:                rbcdCleanup[p.ID],
			CurrentValidation:      LevelModelSimulated,
		})
	}
	return out
}

// DCSyncEntries returns the coverage-matrix row for the dcsync primitive only
// (the real-replication capability, DOMAIN_CREDENTIAL_MATERIAL). It is the one
// gap capability with genuinely REUSABLE executable content -- the stock
// redcanaryco Atomic Red Team atomic for T1003.006 -- so its ExecutionMethod is
// art-atomic, not a synthetic predicate. Its validation level nonetheless stays
// LevelModelSimulated: reusable content is not evidence that it executed and
// produced the expected outcome against a real domain (requirement #5).
//
// Deliberately scoped to "dcsync" alone, NOT the whole DCSyncCatalog: the
// catalog's second primitive, dcsync-replication-right-exposure-check, has a
// REAL committed scenario of its own and none of this entry's art-atomic/
// replication-evidence shape applies to it -- it is tracked the same way the
// Kerberoasting baseline primitives are (via ContentState + CapabilityState's
// curated evidence, not a gap Entry here), never through this function.
func DCSyncEntries() []Entry {
	for _, p := range adprimitive.DCSyncCatalog {
		if p.ID != "dcsync" {
			continue
		}
		return []Entry{{
			PrimitiveID:            p.ID,
			TechniqueID:            p.TechniqueID,
			RequiredEnvToExecute:   EnvDomainController, // DCSync replicates from a real DC
			ExecutionMethod:        "art-atomic",
			ReuseSource:            "art:T1003.006 (redcanaryco atomic)",
			ExpectedPostconditions: p.Postconditions,
			EvidenceRequirements:   []string{"directory-replication request from a non-DC principal (event 4662 with the replication GUIDs)", "secrets (krbtgt/other hashes) returned by the replication"},
			TelemetrySources:       []string{"Directory Service Access auditing (4662) with the DS-Replication-Get-Changes / -All extended-right GUIDs", "network: DRSUAPI DRSGetNCChanges from a non-DC host"},
			Cleanup:                []string{"none required to undo (read-only replication); remove any ACL grant made to enable it"},
			CurrentValidation:      LevelModelSimulated,
		}}
	}
	return nil
}

var delegationReuse = map[string]string{
	"kerberos-unconstrained-delegation": "adlab EnvResolver(controls_unconstrained_delegation_principal)",
	"kerberos-constrained-delegation":   "adlab EnvResolver(controls_constrained_delegation_principal)",
}

var delegationEvidence = map[string][]string{
	"kerberos-unconstrained-delegation": {"a coerced privileged authentication (e.g. a DC machine account) to the delegation host", "the victim's forwarded TGT captured on the delegation host"},
	"kerberos-constrained-delegation":   {"S4U2Self/S4U2Proxy ticket requests from the controlled principal", "a service ticket to a configured target SPN issued for an arbitrary user"},
}

var delegationCleanup = map[string][]string{
	"kerberos-unconstrained-delegation": {"remove the TRUSTED_FOR_DELEGATION flag from the abused principal", "purge captured tickets"},
	"kerberos-constrained-delegation":   {"remove the msDS-AllowedToDelegateTo / protocol-transition configuration from the principal", "purge obtained service tickets"},
}

var delegationTelemetry = map[string][]string{
	"kerberos-unconstrained-delegation": {"authentication-coercion signatures (PetitPotam/PrinterBug/DFSCoerce)", "Kerberos AS/TGS activity to the delegation host (events 4768/4769)", "accounts flagged TRUSTED_FOR_DELEGATION in userAccountControl"},
	"kerberos-constrained-delegation":   {"Kerberos service-ticket requests with the S4U2Proxy flag (event 4769)", "msDS-AllowedToDelegateTo attribute state", "TrustedToAuthForDelegation (protocol transition) flag changes"},
}

// DelegationEntries returns the coverage-matrix rows for non-RBCD Kerberos
// delegation abuse (unconstrained TGT capture, constrained S4U2Proxy), iterating
// the real adprimitive.DelegationCatalog so IDs and postconditions cannot drift.
func DelegationEntries() []Entry {
	out := make([]Entry, 0, len(adprimitive.DelegationCatalog))
	for _, p := range adprimitive.DelegationCatalog {
		if p.ID == "kerberos-delegation-exposure-check" {
			continue // read-only discovery primitive, tracked via realScenarioEvidenceByID
		}
		out = append(out, Entry{
			PrimitiveID:            p.ID,
			TechniqueID:            p.TechniqueID,
			RequiredEnvToExecute:   EnvDomainController, // delegation abuse needs a real domain
			ExecutionMethod:        "synthetic-predicate",
			ReuseSource:            delegationReuse[p.ID],
			ExpectedPostconditions: p.Postconditions,
			EvidenceRequirements:   delegationEvidence[p.ID],
			TelemetrySources:       delegationTelemetry[p.ID],
			Cleanup:                delegationCleanup[p.ID],
			CurrentValidation:      LevelModelSimulated,
		})
	}
	return out
}

var trustReuse = map[string]string{
	"trust-intra-forest-sid-history": "adenv.IsIntraForestTrustAbusable + adlab EnvResolver(intra_forest_trust_abusable)",
	"trust-cross-forest-sid-history": "adenv.IsCrossForestSIDAbusable + adlab EnvResolver(cross_forest_trust_sid_filter_disabled)",
}

var trustEvidence = map[string][]string{
	"trust-intra-forest-sid-history": {"an inter-realm TGT forged with an extra SID (forest-root Enterprise Admins) presented across the trust", "access to the forest-root domain as a principal never granted it"},
	"trust-cross-forest-sid-history": {"an inter-realm TGT carrying a cross-forest SID that SID filtering should have stripped", "access in the trusting forest as a filtered SID"},
}

var trustCleanup = map[string][]string{
	"trust-intra-forest-sid-history": {"rotate the compromised domain's krbtgt twice", "invalidate forged tickets"},
	"trust-cross-forest-sid-history": {"re-enable SID filtering/quarantine on the trust (netdom trust /quarantine:yes)", "invalidate forged tickets"},
}

var trustTelemetry = map[string][]string{
	"trust-intra-forest-sid-history": {"Kerberos TGS referrals carrying unexpected SID history (event 4769)", "krbtgt usage anomalies / golden-ticket indicators", "cross-domain authentications from a newly-privileged SID"},
	"trust-cross-forest-sid-history": {"trust SID-filtering/quarantine configuration state (netdom trust)", "Kerberos cross-forest TGS with unexpected SIDs (event 4769)", "authentications from foreign-forest SIDs that should be filtered"},
}

// TrustEntries returns the coverage-matrix rows for AD trust abuse (SID-history
// injection intra- and cross-forest), iterating adprimitive.TrustAbuseCatalog so
// IDs and postconditions cannot drift.
func TrustEntries() []Entry {
	out := make([]Entry, 0, len(adprimitive.TrustAbuseCatalog))
	for _, p := range adprimitive.TrustAbuseCatalog {
		if p.ID == "trust-sid-history-exposure-check" {
			continue // read-only discovery primitive, tracked via realScenarioEvidenceByID
		}
		out = append(out, Entry{
			PrimitiveID:            p.ID,
			TechniqueID:            p.TechniqueID,
			RequiredEnvToExecute:   EnvDomainController, // trust abuse crosses real domains
			ExecutionMethod:        "synthetic-predicate",
			ReuseSource:            trustReuse[p.ID],
			ExpectedPostconditions: p.Postconditions,
			EvidenceRequirements:   trustEvidence[p.ID],
			TelemetrySources:       trustTelemetry[p.ID],
			Cleanup:                trustCleanup[p.ID],
			CurrentValidation:      LevelModelSimulated,
		})
	}
	return out
}

// AllEntries is the full AD coverage matrix across every gap catalog, in a
// deterministic order (ADCS, ACL, RBCD, DCSync, delegation, trust).
func AllEntries() []Entry {
	var out []Entry
	out = append(out, ADCSEntries()...)
	out = append(out, ACLEntries()...)
	out = append(out, RBCDEntries()...)
	out = append(out, DCSyncEntries()...)
	out = append(out, DelegationEntries()...)
	out = append(out, TrustEntries()...)
	out = append(out, GPOEntries()...)
	return out
}

// Summary is a measurable rollup of a set of matrix entries.
type Summary struct {
	Total               int
	ByValidationLevel   map[ValidationLevel]int
	WithReusableContent int // entries backed by reusable EXECUTABLE content (art-atomic / caldera-ability)
	RequiringDC         int
	RequiringHost       int
}

// Summarize computes coverage counts. "Reusable content" means a real,
// executable asset exists (an ART atomic or a Caldera ability) -- a synthetic
// predicate reuses a model check, not executable content, so it does not count.
func Summarize(entries []Entry) Summary {
	s := Summary{Total: len(entries), ByValidationLevel: map[ValidationLevel]int{}}
	for _, e := range entries {
		s.ByValidationLevel[e.CurrentValidation]++
		switch e.ExecutionMethod {
		case "art-atomic", "caldera-ability":
			s.WithReusableContent++
		}
		switch e.RequiredEnvToExecute {
		case EnvDomainController:
			s.RequiringDC++
		case EnvDomainJoinedHost:
			s.RequiringHost++
		}
	}
	return s
}
