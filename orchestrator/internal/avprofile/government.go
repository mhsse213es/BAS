package avprofile

import "fmt"

// governmentControlObjectives maps av.txt §3's own six named Government
// priorities one at a time, per the explicit directive this profile was
// built under: define the risk/control objective first, then map an
// existing avcatalog vector only where real evidence supports the
// relationship, and record an explicit gap rather than force an
// unrelated vector onto a priority nothing in the catalog actually
// tests.
//
// Three of the six resolve to a real vector:
//   - restricted or disconnected networks -> AV-CONFIG-002 (degraded/
//     offline-protection testing is the direct operational analogue of
//     a restricted or disconnected government network)
//   - privileged workstations -> AV-CREDACCESS-001 (credential-access
//     behavior is the dominant threat model on a privileged/admin
//     workstation, where a successful credential-store access has the
//     largest blast radius)
//   - auditability -> AV-CONFIG-003 (security-tampering testing
//     specifically measures whether an unauthorized configuration-
//     change attempt is itself recorded by the product -- exactly what
//     an auditability priority requires)
//
// Three remain gaps, because the real capability that would satisfy
// them lives at avval's evaluation layer (a snapshot-vs-baseline
// comparison), not as a Vector execution, or does not exist at all:
//   - legacy and unsupported endpoints: no vector tests EOL/unsupported
//     OS compatibility; avcatalog's Platform field only enumerates
//     which supported platforms a vector runs on.
//   - centralized policy enforcement: avval.EvaluateConfigurationDrift
//     compares a managed policy baseline to a live snapshot, but this
//     is an evaluation-layer capability given caller-supplied evidence,
//     not a Vector that executes anything.
//   - constrained update delivery: avval.EvaluateConfigurationSnapshot's
//     SignatureAgeHours-vs-baseline check is the existing capability
//     for signature/definition currency, again evaluation-layer only,
//     not a Vector execution.
func governmentControlObjectives() ([]ControlObjectiveCoverage, error) {
	var out []ControlObjectiveCoverage

	legacyEndpoints, err := NewControlObjectiveCoverage(
		"legacy and unsupported endpoints", "",
		"no avcatalog vector tests EOL/unsupported-OS compatibility; Platform only enumerates which supported platforms a vector may run on, it does not probe behavior on an unsupported one",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("governmentControlObjectives: %w", err)
	}
	out = append(out, legacyEndpoints)

	disconnectedNetworks, err := NewControlObjectiveCoverage(
		"restricted or disconnected networks", "AV-CONFIG-002",
		"AV-CONFIG-002 tests whether local, offline protection still operates as expected while cloud-reputation lookup is unavailable -- the direct operational analogue of a restricted or disconnected government network",
		"prevention evidence (AV engine block/allow outcome) collected while cloud-lookup connectivity is unavailable",
		CoverageStatusCovered)
	if err != nil {
		return nil, fmt.Errorf("governmentControlObjectives: %w", err)
	}
	out = append(out, disconnectedNetworks)

	centralizedPolicy, err := NewControlObjectiveCoverage(
		"centralized policy enforcement", "",
		"the real capability here is avval.EvaluateConfigurationDrift, a snapshot-vs-managed-baseline comparison given caller-supplied evidence -- it is an evaluation-layer capability, not a Vector execution, so it cannot honestly be named as this profile's vector mapping",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("governmentControlObjectives: %w", err)
	}
	out = append(out, centralizedPolicy)

	privilegedWorkstations, err := NewControlObjectiveCoverage(
		"privileged workstations", "AV-CREDACCESS-001",
		"credential-access behavior is the dominant threat model on a privileged/administrator workstation, where a successful credential-store access has the largest blast radius of any endpoint in a government estate",
		"prevention/detection evidence from the benign credential-store process-access probe",
		CoverageStatusCovered)
	if err != nil {
		return nil, fmt.Errorf("governmentControlObjectives: %w", err)
	}
	out = append(out, privilegedWorkstations)

	auditability, err := NewControlObjectiveCoverage(
		"auditability", "AV-CONFIG-003",
		"AV-CONFIG-003's own design measures whether an unauthorized real-time-protection-disable attempt is itself recorded by the product's audit/telemetry trail -- precisely the auditability question this priority asks, independent of whether the attempt was also blocked",
		"the resulting protection state after the attempt, plus best-effort local Defender-operational-log telemetry for the attempt itself",
		CoverageStatusCovered)
	if err != nil {
		return nil, fmt.Errorf("governmentControlObjectives: %w", err)
	}
	out = append(out, auditability)

	constrainedUpdates, err := NewControlObjectiveCoverage(
		"constrained update delivery", "",
		"the real capability here is avval.EvaluateConfigurationSnapshot's SignatureAgeHours-vs-baseline check, again evaluation-layer only given caller-supplied evidence, not a Vector that executes a real signature/update-delivery test",
		"", CoverageStatusGap)
	if err != nil {
		return nil, fmt.Errorf("governmentControlObjectives: %w", err)
	}
	out = append(out, constrainedUpdates)

	return out, nil
}

// governmentCoveredVectorIDs derives Profile.VectorIDs from the Covered
// subset of objectives, deduplicated -- so the flat list a caller
// iterating VectorIDs sees always matches what ControlObjectives says is
// real, with no second, hand-maintained copy of the same judgment.
func governmentCoveredVectorIDs(objectives []ControlObjectiveCoverage) []string {
	var out []string
	seen := map[string]bool{}
	for _, o := range objectives {
		if o.Status == CoverageStatusCovered && !seen[o.VectorID] {
			out = append(out, o.VectorID)
			seen[o.VectorID] = true
		}
	}
	return out
}

// MSPControlObjectives returns av.txt §3's five named MSP priorities as
// an explicit, fully-gapped coverage record. No AVPROFILE-MSP Profile is
// minted at all: every one of these priorities (multi-tenant isolation,
// customer-specific policy drift, agent health across customer estates,
// inconsistent product configurations, and evidence attribution to the
// correct tenant) describes a multi-tenant fleet/platform-management
// concern, not a single-endpoint AV/NGAV technique -- the axis every
// avcatalog vector is built to test. Forcing any of the 15 real vectors
// onto one of these priorities would misrepresent what that vector
// actually measures, which is exactly what av.txt's own directive says
// not to do ("mark the requirement as a gap rather than assigning an
// unrelated vector"). This function exists so that finding stays a
// visible, durable, structured record instead of a silent omission.
func MSPControlObjectives() ([]ControlObjectiveCoverage, error) {
	objectives := []struct {
		name   string
		reason string
	}{
		{"multi-tenant isolation", "no avcatalog vector tests whether one tenant's endpoint telemetry or configuration can affect or be observed by another tenant -- this is a platform/data-model property of the MSP's own management layer, not an endpoint AV/NGAV technique"},
		{"customer-specific policy drift", "the real capability here would be comparing each customer's managed policy baseline against its own live snapshot across many separate estates -- an evaluation-layer, multi-tenant aggregation problem with no single-endpoint Vector equivalent"},
		{"agent health across customer estates", "fleet-wide agent-health rollup across many separate customer estates is an orchestrator/reporting concern, not an attack vector an endpoint's AV/NGAV engine can be tested against"},
		{"inconsistent product configurations", "comparing configuration consistency across many customers' deployments is a cross-estate reporting concern; no single vector execution produces or measures this"},
		{"evidence attribution to the correct tenant", "correct tenant attribution is a property of how the platform stores and queries evidence, not of anything an AV/NGAV vector's own execution or outcome can demonstrate"},
	}
	var out []ControlObjectiveCoverage
	for _, o := range objectives {
		gap, err := NewControlObjectiveCoverage(o.name, "", o.reason, "", CoverageStatusGap)
		if err != nil {
			return nil, fmt.Errorf("MSPControlObjectives: %w", err)
		}
		out = append(out, gap)
	}
	return out, nil
}
