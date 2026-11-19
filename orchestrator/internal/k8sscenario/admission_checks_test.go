package k8sscenario

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// fakeAdmission answers the three admission calls from fields set by each test.
type fakeAdmission struct {
	level     string
	found     bool
	levelErr  error
	dry       DryRunResult
	dryErr    error
	sides     []string
	sidesErr  error
	dryCalled bool
	pod       map[string]any
}

func (f *fakeAdmission) NamespacePSALevel(context.Context, string) (string, bool, error) {
	return f.level, f.found, f.levelErr
}
func (f *fakeAdmission) DryRunPod(_ context.Context, _ string, pod map[string]any) (DryRunResult, error) {
	f.dryCalled = true
	f.pod = pod
	return f.dry, f.dryErr
}
func (f *fakeAdmission) WebhookSideEffects(context.Context) ([]string, error) {
	return f.sides, f.sidesErr
}

func runAdm(t *testing.T, id string, f *fakeAdmission) AdmissionCheckResult {
	t.Helper()
	check, ok := AdmissionCheckByID(id)
	if !ok {
		t.Fatalf("%s missing", id)
	}
	return RunAdmissionCheck(context.Background(), f, check, "lab-ns", time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC))
}

func TestS7_RefusedInRestrictedNamespaceIsBlockedAndPasses(t *testing.T) {
	f := &fakeAdmission{level: "restricted", found: true,
		dry: DryRunResult{StatusCode: 403, Reason: "Forbidden", Message: `pods "x" is forbidden: violates PodSecurity "restricted:latest"`}}
	res := runAdm(t, "privileged-pod-restricted-namespace", f)
	if res.Outcome != controlval.OutcomeBlocked || res.Verdict != controlval.VerdictPass {
		t.Errorf("want blocked/PASS, got %s/%s", res.Outcome, res.Verdict)
	}
	if !res.Evidence.PSAViolation || res.NamespaceLevel != "restricted" || res.Source != "admission-dry-run" {
		t.Errorf("evidence wrong: %+v", res)
	}
	if !f.dryCalled {
		t.Fatal("dry-run was not sent")
	}
	sc := f.pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["securityContext"].(map[string]any)
	if sc["privileged"] != true {
		t.Errorf("S7 pod must request privileged: %v", sc)
	}
}

func TestS7_AllowedInRestrictedNamespaceIsFail(t *testing.T) {
	f := &fakeAdmission{level: "restricted", found: true, dry: DryRunResult{StatusCode: 201, Allowed: true}}
	res := runAdm(t, "privileged-pod-restricted-namespace", f)
	if res.Outcome != controlval.OutcomeAllowed || res.Verdict != controlval.VerdictFail {
		t.Errorf("an allowed privileged pod must be allowed/FAIL, got %s/%s", res.Outcome, res.Verdict)
	}
}

func TestS7_SkippedUnlessNamespaceIsRestricted(t *testing.T) {
	f := &fakeAdmission{level: "baseline", found: true}
	res := runAdm(t, "privileged-pod-restricted-namespace", f)
	if res.Verdict != controlval.VerdictSkipped || f.dryCalled {
		t.Errorf("baseline namespace must be SKIPPED without a dry-run, got %s (sent=%v)", res.Verdict, f.dryCalled)
	}
	if res.Note == "" {
		t.Error("a skip must say why")
	}
}

func TestS8_AppliesAtBaselineOrRestricted(t *testing.T) {
	for _, level := range []string{"baseline", "restricted"} {
		f := &fakeAdmission{level: level, found: true, dry: DryRunResult{StatusCode: 403, Message: "admission webhook denied"}}
		res := runAdm(t, "host-namespaces-hostpath-policy", f)
		if res.Outcome != controlval.OutcomeBlocked || res.Verdict != controlval.VerdictPass {
			t.Errorf("%s: want blocked/PASS, got %s/%s", level, res.Outcome, res.Verdict)
		}
		if res.Evidence.PSAViolation {
			t.Errorf("%s: a non-PSA refusal must not be recorded as a PSA violation", level)
		}
	}
	f := &fakeAdmission{level: "privileged", found: true}
	if res := runAdm(t, "host-namespaces-hostpath-policy", f); res.Verdict != controlval.VerdictSkipped {
		t.Errorf("privileged namespace must be SKIPPED, got %s", res.Verdict)
	}
}

func TestS8_PodCarriesHostNamespacesAndHostPath(t *testing.T) {
	f := &fakeAdmission{level: "baseline", found: true, dry: DryRunResult{StatusCode: 403}}
	runAdm(t, "host-namespaces-hostpath-policy", f)
	spec := f.pod["spec"].(map[string]any)
	if spec["hostPID"] != true || spec["hostNetwork"] != true {
		t.Errorf("host namespaces missing: %v", spec)
	}
	vol := spec["volumes"].([]any)[0].(map[string]any)
	if vol["hostPath"].(map[string]any)["path"] != "/" {
		t.Errorf("hostPath / missing: %v", vol)
	}
}

func TestAllowedWithUnsafeWebhookIsUnknownNotAllowed(t *testing.T) {
	f := &fakeAdmission{level: "restricted", found: true, dry: DryRunResult{StatusCode: 201, Allowed: true},
		sides: []string{"None", "Some"}}
	res := runAdm(t, "privileged-pod-restricted-namespace", f)
	if res.Outcome != controlval.OutcomeUnknown || res.Verdict != controlval.VerdictError {
		t.Errorf("a dry-run that a webhook may not honour must not be reported as allowed: got %s/%s", res.Outcome, res.Verdict)
	}
	if len(res.Evidence.WebhookSideNotes) != 1 || res.Evidence.WebhookSideNotes[0] != "Some" {
		t.Errorf("the unsafe side effect must be recorded: %+v", res.Evidence)
	}
}

func TestAllowedWithDryRunSafeWebhooksIsStillFail(t *testing.T) {
	f := &fakeAdmission{level: "restricted", found: true, dry: DryRunResult{StatusCode: 201, Allowed: true},
		sides: []string{"None", "NoneOnDryRun"}}
	if res := runAdm(t, "privileged-pod-restricted-namespace", f); res.Verdict != controlval.VerdictFail {
		t.Errorf("dry-run-safe webhooks must not change an allowed result: %s", res.Verdict)
	}
}

func TestAdmissionErrorsAreErrorsNotPasses(t *testing.T) {
	cases := []*fakeAdmission{
		{levelErr: errors.New("namespace read failed")},
		{level: "restricted", found: false},
		{level: "restricted", found: true, dryErr: errors.New("dry-run failed")},
		{level: "restricted", found: true, dry: DryRunResult{StatusCode: 201, Allowed: true}, sidesErr: errors.New("list failed")},
	}
	for i, f := range cases {
		res := runAdm(t, "privileged-pod-restricted-namespace", f)
		if res.Verdict != controlval.VerdictError || res.Outcome != controlval.OutcomeUnknown || res.Error == "" {
			t.Errorf("case %d: want unknown/ERROR, got %s/%s", i, res.Outcome, res.Verdict)
		}
	}
}

func TestAdmissionCheckByID_Unknown(t *testing.T) {
	if _, ok := AdmissionCheckByID("nope"); ok {
		t.Error("unknown check must not resolve")
	}
}
