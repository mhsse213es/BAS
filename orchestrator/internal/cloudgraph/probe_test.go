package cloudgraph

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const probeAcct = "111111111111"

// countingProber records whether it was called, and returns a fixed outcome.
type countingProber struct {
	calls   int
	outcome ProbeOutcome
}

func (p *countingProber) Probe(context.Context, ProbeRequest) (ProbeOutcome, error) {
	p.calls++
	return p.outcome, nil
}

func probeAllow(t *testing.T) ProbeAllowList {
	t.Helper()
	list, err := ParseProbeAllowList("aws:" + probeAcct)
	if err != nil {
		t.Fatalf("ParseProbeAllowList: %v", err)
	}
	return list
}

func s3Req(mode ProbeMode, target string) ProbeRequest {
	return ProbeRequest{Provider: "aws", AccountID: probeAcct, Operation: "s3:ListBucket", Target: target, Mode: mode}
}

func simReq(mode ProbeMode, target, action string) ProbeRequest {
	return ProbeRequest{Provider: "aws", AccountID: probeAcct, Operation: "iam:SimulatePrincipalPolicy", Target: target, Action: action, Mode: mode}
}

func requireRejected(t *testing.T, err error, mention string) {
	t.Helper()
	if !errors.Is(err, ErrProbeRejected) {
		t.Fatalf("err = %v, want ErrProbeRejected", err)
	}
	if mention != "" && !strings.Contains(err.Error(), mention) {
		t.Errorf("err = %q, want it to mention %q", err, mention)
	}
}

// An empty allow-list permits nothing. A malformed entry is a parse error, so a
// typo cannot silently change scope.
func TestParseProbeAllowList(t *testing.T) {
	empty, err := ParseProbeAllowList("")
	if err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if empty.Permits("aws", probeAcct) {
		t.Error("an empty allow-list permitted an account")
	}
	if _, err := ParseProbeAllowList("aws"); err == nil {
		t.Error("an entry without an account must be an error")
	}
	list, err := ParseProbeAllowList(" aws:" + probeAcct + " , gcp:proj-1 ")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !list.Permits("aws", probeAcct) || !list.Permits("gcp", "proj-1") || list.Permits("aws", "999") {
		t.Error("allow-list membership is wrong")
	}
}

// An account that is not allow-listed is rejected before the registry or the
// prober is consulted.
func TestRunProbe_UnlistedAccountRejectedBeforeAnyProviderCall(t *testing.T) {
	prober := &countingProber{outcome: ProbeOutcome{Outcome: "allowed", Evidence: EvidenceObserved}}
	req := s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket")
	req.AccountID = "999999999999"
	_, err := RunProbe(context.Background(), req, probeAllow(t), prober)
	requireRejected(t, err, "allow-list")
	if prober.calls != 0 {
		t.Fatal("prober was called for an unlisted account")
	}
}

// An operation outside the registry is rejected, including a state-changing one.
func TestRunProbe_StateChangingOperationRejected(t *testing.T) {
	for _, op := range []string{"s3:PutObject", "ec2:TerminateInstances", "iam:CreateRole", "s3:ListBucket "} {
		prober := &countingProber{}
		req := s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket")
		req.Operation = op
		_, err := RunProbe(context.Background(), req, probeAllow(t), prober)
		requireRejected(t, err, "registry")
		if prober.calls != 0 {
			t.Errorf("prober was called for %q", op)
		}
	}
}

// A client cannot add a read-only label. The request struct has no field a
// client could set to claim read-only status, and the decoder rejects unknown
// fields. The field list is read from the type itself.
func TestProbeRequest_HasNoClientSuppliedReadOnlyField(t *testing.T) {
	typ := reflect.TypeOf(ProbeRequest{})
	allowed := map[string]bool{"Provider": true, "AccountID": true, "Operation": true, "Target": true, "Action": true, "Mode": true}
	for i := 0; i < typ.NumField(); i++ {
		if name := typ.Field(i).Name; !allowed[name] {
			t.Errorf("ProbeRequest has unexpected field %q", name)
		}
	}
}

// A bucket target must be a bare bucket ARN. A key path, or a name that is not a
// valid bucket name, is rejected.
func TestRunProbe_BucketTargetMustBeBareBucketARN(t *testing.T) {
	for _, target := range []string{
		"arn:aws:s3:::corp-bucket/secret.txt",
		"arn:aws:s3:::Bad_Bucket",
		"corp-bucket",
		"",
	} {
		prober := &countingProber{}
		_, err := RunProbe(context.Background(), s3Req(ProbeLiveReadOnly, target), probeAllow(t), prober)
		requireRejected(t, err, "S3 bucket ARN")
		if prober.calls != 0 {
			t.Errorf("prober was called for target %q", target)
		}
	}
}

// A principal must belong to the named account. A principal from another account
// is rejected before any call.
func TestRunProbe_PrincipalMustBeInNamedAccount(t *testing.T) {
	prober := &countingProber{}
	req := simReq(ProbeLiveReadOnly, "arn:aws:iam::999999999999:role/admin", "s3:GetObject")
	_, err := RunProbe(context.Background(), req, probeAllow(t), prober)
	requireRejected(t, err, "probe names")
	if prober.calls != 0 {
		t.Fatal("prober was called for a principal in another account")
	}
}

// The simulator needs an action, and only a well-formed one. An action on an
// operation that takes none is also rejected.
func TestRunProbe_ActionShape(t *testing.T) {
	target := "arn:aws:iam::" + probeAcct + ":role/app"
	for _, action := range []string{"", "GetObject", "s3:Get Object"} {
		_, err := RunProbe(context.Background(), simReq(ProbeLiveReadOnly, target, action), probeAllow(t), &countingProber{})
		requireRejected(t, err, "action")
	}
	req := s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket")
	req.Action = "s3:GetObject"
	_, err := RunProbe(context.Background(), req, probeAllow(t), &countingProber{})
	requireRejected(t, err, "does not take an action")
}

// Dry-run returns the plan and never calls the prober, even when the prober is
// present and would succeed.
func TestRunProbe_DryRunNeverContactsProvider(t *testing.T) {
	prober := &countingProber{outcome: ProbeOutcome{Outcome: "allowed", Evidence: EvidenceObserved}}
	res, err := RunProbe(context.Background(), s3Req(ProbeDryRun, "arn:aws:s3:::corp-bucket"), probeAllow(t), prober)
	if err != nil {
		t.Fatalf("RunProbe: %v", err)
	}
	if prober.calls != 0 {
		t.Fatal("dry-run called the prober")
	}
	if res.Outcome != "planned" || res.Evidence != EvidencePlan {
		t.Errorf("dry-run result = %+v, want planned with dry-run-plan evidence", res)
	}
	if !strings.Contains(res.Detail, "not verified") {
		t.Errorf("dry-run must say account and ownership are not verified, got %q", res.Detail)
	}
}

// Dry-run is not authorization. A dry-run of an unlisted account is still rejected.
func TestRunProbe_DryRunDoesNotBypassAllowList(t *testing.T) {
	req := s3Req(ProbeDryRun, "arn:aws:s3:::corp-bucket")
	req.AccountID = "999999999999"
	_, err := RunProbe(context.Background(), req, probeAllow(t), nil)
	requireRejected(t, err, "allow-list")
}

func TestRunProbe_UnknownModeRejected(t *testing.T) {
	req := s3Req("live-write", "arn:aws:s3:::corp-bucket")
	_, err := RunProbe(context.Background(), req, probeAllow(t), &countingProber{})
	requireRejected(t, err, "mode")
}

// A prober that reports the wrong evidence kind is refused. A simulated answer
// cannot be recorded as an observed one.
func TestRunProbe_EvidenceKindMismatchRefused(t *testing.T) {
	prober := &countingProber{outcome: ProbeOutcome{Outcome: "simulated-denied", Evidence: EvidenceSimulated}}
	_, err := RunProbe(context.Background(), s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket"), probeAllow(t), prober)
	if err == nil || !strings.Contains(err.Error(), "evidence") {
		t.Fatalf("err = %v, want an evidence-kind refusal", err)
	}
}

// A live probe with no prober configured fails rather than running unchecked.
func TestRunProbe_LiveWithoutProberFails(t *testing.T) {
	_, err := RunProbe(context.Background(), s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket"), probeAllow(t), nil)
	if err == nil {
		t.Fatal("live probe without a prober must fail")
	}
}

// A simulated outcome is marked as simulated, so it is never read as observed.
func TestRunProbe_SimulatedOutcomeIsMarked(t *testing.T) {
	prober := &countingProber{outcome: ProbeOutcome{Outcome: "simulated-allowed", Evidence: EvidenceSimulated}}
	res, err := RunProbe(context.Background(), simReq(ProbeLiveReadOnly, "arn:aws:iam::"+probeAcct+":role/app", "s3:GetObject"), probeAllow(t), prober)
	if err != nil {
		t.Fatalf("RunProbe: %v", err)
	}
	if !res.Simulated || res.Evidence != EvidenceSimulated {
		t.Errorf("result = %+v, want simulated evidence", res)
	}
}
