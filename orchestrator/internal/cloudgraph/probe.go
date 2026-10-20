package cloudgraph

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Read-only cloud probes. A probe asks a provider one read-only question about
// one approved account. It never changes state. Scenario execution is still
// separate: this package only predicts and observes.
//
// Layers, in order. A request must pass every layer before any provider is
// contacted:
//   1. mode is known (dry-run or live-readonly);
//   2. the provider and account are on the server's allow-list;
//   3. the operation is in the fixed registry below, read-only by construction;
//   4. the target and action match the operation's expected shape and belong to
//      the named account.
// Dry-run stops after layer 4. It never calls a provider.

// ErrProbeRejected means a request failed a validation layer. Its wrapped
// message names the layer. No provider was contacted for a rejected request.
var ErrProbeRejected = errors.New("probe rejected")

// ProbeMode selects whether a probe is planned or executed.
type ProbeMode string

const (
	// ProbeDryRun plans the probe and returns the plan. It contacts no provider.
	ProbeDryRun ProbeMode = "dry-run"
	// ProbeLiveReadOnly executes the registered read-only probe.
	ProbeLiveReadOnly ProbeMode = "live-readonly"
)

// EvidenceKind says what kind of proof a probe outcome is. The kinds are never
// interchangeable: a simulated policy decision is not proof that a real action
// was blocked.
type EvidenceKind string

const (
	// EvidencePlan: the request was validated and planned. Nothing was run.
	EvidencePlan EvidenceKind = "dry-run-plan"
	// EvidenceObserved: the provider answered a real call.
	EvidenceObserved EvidenceKind = "provider-response"
	// EvidenceSimulated: the provider's policy simulator answered. It describes
	// what policy would decide, not what a call would do.
	EvidenceSimulated EvidenceKind = "simulated-decision"
)

// ProbeRequest is one probe request. Callers cannot add fields: the decoder
// rejects unknown fields, so a read-only label cannot be supplied by a client.
type ProbeRequest struct {
	Provider  string    `json:"provider"`
	AccountID string    `json:"accountId"`
	Operation string    `json:"operation"`
	Target    string    `json:"target"`
	Action    string    `json:"action,omitempty"`
	Mode      ProbeMode `json:"mode"`
}

// ProbeResult is the record of one probe: what was asked, and the outcome.
type ProbeResult struct {
	Mode      ProbeMode    `json:"mode"`
	Provider  string       `json:"provider"`
	AccountID string       `json:"accountId"`
	Operation string       `json:"operation"`
	Target    string       `json:"target"`
	Action    string       `json:"action,omitempty"`
	Outcome   string       `json:"outcome"`
	Evidence  EvidenceKind `json:"evidence"`
	Simulated bool         `json:"simulated"`
	Detail    string       `json:"detail,omitempty"`
}

// ProbeOutcome is what a Prober reports for one executed probe.
type ProbeOutcome struct {
	Outcome  string
	Evidence EvidenceKind
	Detail   string
}

// Prober executes one validated read-only probe against a provider.
type Prober interface {
	Probe(ctx context.Context, req ProbeRequest) (ProbeOutcome, error)
}

// probeTargetKind names the target shape an operation accepts.
type probeTargetKind int

const (
	targetS3Bucket probeTargetKind = iota
	targetIAMPrincipal
)

// probeDescriptor is one entry in the registry. Registry entries are fixed in
// code. A request can select an entry but cannot add one.
type probeDescriptor struct {
	Provider    string
	Operation   string
	Evidence    EvidenceKind
	target      probeTargetKind
	needsAction bool
}

// probeRegistry lists every operation the probe executor will run. Each entry is
// read-only by construction: ListObjectsV2 and SimulatePrincipalPolicy change
// nothing in the account.
var probeRegistry = []probeDescriptor{
	{Provider: "aws", Operation: "s3:ListBucket", Evidence: EvidenceObserved, target: targetS3Bucket},
	{Provider: "aws", Operation: "iam:SimulatePrincipalPolicy", Evidence: EvidenceSimulated, target: targetIAMPrincipal, needsAction: true},
}

var (
	s3BucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	iamActionPattern    = regexp.MustCompile(`^[a-z0-9]+:[A-Za-z0-9*]+$`)
	iamPrincipalARN     = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):(role|user)/[^\s]+$`)
)

// ProbeAllowList is the server's set of accounts that may be probed. It is
// configured on the server, never taken from a request, and an empty list
// permits nothing.
type ProbeAllowList struct {
	allowed map[string]bool
}

// ParseProbeAllowList parses "provider:accountID" entries separated by commas.
// An empty string yields an empty list that permits nothing. A malformed entry
// is an error, so a typo cannot silently widen or narrow the scope.
func ParseProbeAllowList(s string) (ProbeAllowList, error) {
	list := ProbeAllowList{allowed: map[string]bool{}}
	for _, raw := range strings.Split(s, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		provider, account, ok := strings.Cut(entry, ":")
		provider, account = strings.TrimSpace(provider), strings.TrimSpace(account)
		if !ok || provider == "" || account == "" {
			return ProbeAllowList{}, fmt.Errorf("probe allow-list entry %q must be provider:accountId", entry)
		}
		list.allowed[provider+"|"+account] = true
	}
	return list, nil
}

// Permits reports whether the provider and account are on the list.
func (l ProbeAllowList) Permits(provider, accountID string) bool {
	return provider != "" && accountID != "" && l.allowed[provider+"|"+accountID]
}

// lookupProbe returns the registry entry for a provider and operation.
func lookupProbe(provider, operation string) (probeDescriptor, bool) {
	for _, d := range probeRegistry {
		if d.Provider == provider && d.Operation == operation {
			return d, true
		}
	}
	return probeDescriptor{}, false
}

// ValidateProbe applies layers 1 to 4 and returns the registry entry it matched.
// It makes no provider call. Every failure wraps ErrProbeRejected.
func ValidateProbe(req ProbeRequest, allow ProbeAllowList) (probeDescriptor, error) {
	reject := func(format string, args ...any) (probeDescriptor, error) {
		return probeDescriptor{}, fmt.Errorf("%w: "+format, append([]any{ErrProbeRejected}, args...)...)
	}

	if req.Mode != ProbeDryRun && req.Mode != ProbeLiveReadOnly {
		return reject("mode %q is not dry-run or live-readonly", req.Mode)
	}
	if !allow.Permits(req.Provider, req.AccountID) {
		return reject("account %s/%s is not on the probe allow-list", req.Provider, req.AccountID)
	}
	desc, ok := lookupProbe(req.Provider, req.Operation)
	if !ok {
		return reject("operation %q is not in the read-only probe registry for %s", req.Operation, req.Provider)
	}

	switch desc.target {
	case targetS3Bucket:
		bucket, ok := strings.CutPrefix(req.Target, "arn:aws:s3:::")
		if !ok || !s3BucketNamePattern.MatchString(bucket) {
			return reject("target %q must be an S3 bucket ARN (arn:aws:s3:::name), without a key", req.Target)
		}
	case targetIAMPrincipal:
		m := iamPrincipalARN.FindStringSubmatch(req.Target)
		if m == nil {
			return reject("target %q must be an IAM role or user ARN", req.Target)
		}
		if m[1] != req.AccountID {
			return reject("target principal is in account %s, probe names %s", m[1], req.AccountID)
		}
	}

	switch {
	case desc.needsAction && !iamActionPattern.MatchString(req.Action):
		return reject("operation %s needs an action such as s3:GetObject", desc.Operation)
	case !desc.needsAction && req.Action != "":
		return reject("operation %s does not take an action", desc.Operation)
	}
	return desc, nil
}

// RunProbe validates a request and, for live mode, executes it through prober.
// Dry-run returns the plan and never touches prober. A rejected request returns
// an error wrapping ErrProbeRejected, and prober is not called.
func RunProbe(ctx context.Context, req ProbeRequest, allow ProbeAllowList, prober Prober) (ProbeResult, error) {
	desc, err := ValidateProbe(req, allow)
	if err != nil {
		return ProbeResult{}, err
	}
	res := ProbeResult{
		Mode: req.Mode, Provider: req.Provider, AccountID: req.AccountID,
		Operation: req.Operation, Target: req.Target, Action: req.Action,
	}
	if req.Mode == ProbeDryRun {
		res.Outcome = "planned"
		res.Evidence = EvidencePlan
		res.Detail = "validated; no provider was contacted, so the account identity and target ownership are not verified"
		return res, nil
	}
	if prober == nil {
		return ProbeResult{}, fmt.Errorf("probe: no prober configured for %s", req.Provider)
	}
	out, err := prober.Probe(ctx, req)
	if err != nil {
		return ProbeResult{}, err
	}
	// A prober must report the evidence kind its operation produces. A mismatch
	// means its answer cannot be trusted to carry the right weight.
	if out.Evidence != desc.Evidence {
		return ProbeResult{}, fmt.Errorf("probe: %s reported evidence %q, registry expects %q", req.Operation, out.Evidence, desc.Evidence)
	}
	res.Outcome = out.Outcome
	res.Evidence = out.Evidence
	res.Simulated = out.Evidence == EvidenceSimulated
	res.Detail = out.Detail
	return res, nil
}
