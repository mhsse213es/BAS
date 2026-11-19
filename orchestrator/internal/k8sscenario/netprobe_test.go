package k8sscenario

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// fakeProbe is an in-memory cluster for probe pods. logFor chooses the log text by pod name.
type fakeProbe struct {
	created   []map[string]any
	deleted   []string
	exists    map[string]bool
	logFor    func(name string) string
	createErr error
	stuck     bool
}

func newFakeProbe(logFor func(string) string) *fakeProbe {
	return &fakeProbe{exists: map[string]bool{}, logFor: logFor}
}

func (f *fakeProbe) CreatePod(_ context.Context, _ string, pod map[string]any) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, pod)
	f.exists[pod["metadata"].(map[string]any)["name"].(string)] = true
	return nil
}
func (f *fakeProbe) WaitPod(_ context.Context, _, _ string) (PodState, error) {
	return PodState{Phase: "Succeeded", ExitCode: 0}, nil
}
func (f *fakeProbe) PodLogs(_ context.Context, _, name string) (string, error) {
	return f.logFor(name), nil
}
func (f *fakeProbe) DeletePod(_ context.Context, _, name string) error {
	f.deleted = append(f.deleted, name)
	if !f.stuck {
		f.exists[name] = false
	}
	return nil
}
func (f *fakeProbe) PodExists(_ context.Context, _, name string) (bool, error) {
	return f.exists[name] || f.stuck, nil
}

func shortCleanup(t *testing.T) {
	t.Helper()
	oldWait, oldPoll := cleanupWait, cleanupPoll
	cleanupWait, cleanupPoll = 20*time.Millisecond, time.Millisecond
	t.Cleanup(func() { cleanupWait, cleanupPoll = oldWait, oldPoll })
}

var s9Target = NetworkBoundaryTarget{ProbeNamespace: "np-app", TargetNamespace: "np-db", Service: "db",
	AllowedPort: 5432, BlockedPort: 3306}

func s9Logs(blocked, allowed string) func(string) string {
	return func(string) string {
		return "PORT 3306 " + blocked + "\nPORT 5432 " + allowed + "\n"
	}
}

func TestS9_BlockedClosedAllowedOpenIsBlockedAndPasses(t *testing.T) {
	shortCleanup(t)
	f := newFakeProbe(s9Logs("CLOSED", "OPEN"))
	res := RunNetworkBoundary(context.Background(), f, "a1b2c3", s9Target, time.Now())
	if res.Outcome != controlval.OutcomeBlocked || res.Verdict != controlval.VerdictPass {
		t.Errorf("want blocked/PASS, got %s/%s (%s)", res.Outcome, res.Verdict, res.Error)
	}
	if len(res.Probes) != 2 || !res.Probes[0].Matched || !res.Probes[1].Matched {
		t.Errorf("both expectations must match: %+v", res.Probes)
	}
	if len(f.deleted) != 1 || len(res.Cleanup) != 1 || !strings.Contains(res.Cleanup[0], "removed") {
		t.Errorf("the probe pod must be removed and the removal recorded: %v %v", f.deleted, res.Cleanup)
	}
	script := f.created[0]["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["command"].([]any)[2].(string)
	if !strings.Contains(script, "db.np-db.svc.cluster.local") || !strings.Contains(script, "3306") {
		t.Errorf("probe script does not target the service and ports: %s", script)
	}
	if f.created[0]["spec"].(map[string]any)["automountServiceAccountToken"] != false {
		t.Error("the S9 probe must not mount a service account token")
	}
}

func TestS9_BlockedPortOpenIsAllowedAndFails(t *testing.T) {
	shortCleanup(t)
	res := RunNetworkBoundary(context.Background(), newFakeProbe(s9Logs("OPEN", "OPEN")), "a1b2c3", s9Target, time.Now())
	if res.Outcome != controlval.OutcomeAllowed || res.Verdict != controlval.VerdictFail {
		t.Errorf("a blocked port that connects must be allowed/FAIL, got %s/%s", res.Outcome, res.Verdict)
	}
}

func TestS9_AllowedPortClosedIsBlockedAndFails(t *testing.T) {
	shortCleanup(t)
	res := RunNetworkBoundary(context.Background(), newFakeProbe(s9Logs("CLOSED", "CLOSED")), "a1b2c3", s9Target, time.Now())
	if res.Outcome != controlval.OutcomeBlocked || res.Verdict != controlval.VerdictFail {
		t.Errorf("a legitimate flow that is refused must be blocked/FAIL, got %s/%s", res.Outcome, res.Verdict)
	}
}

func TestS9_CleanupNotConfirmedIsError(t *testing.T) {
	shortCleanup(t)
	f := newFakeProbe(s9Logs("CLOSED", "OPEN"))
	f.stuck = true
	res := RunNetworkBoundary(context.Background(), f, "a1b2c3", s9Target, time.Now())
	if res.Verdict != controlval.VerdictError || !strings.Contains(res.Error, "probe pod was not removed") {
		t.Errorf("a pod that stays behind must make the result ERROR: %s %q", res.Verdict, res.Error)
	}
}

func TestS9_CreateFailureIsErrorAndRunTagIsChecked(t *testing.T) {
	shortCleanup(t)
	f := newFakeProbe(s9Logs("CLOSED", "OPEN"))
	f.createErr = errors.New("forbidden")
	if res := RunNetworkBoundary(context.Background(), f, "a1b2c3", s9Target, time.Now()); res.Verdict != controlval.VerdictError {
		t.Errorf("a create failure must be ERROR, got %s", res.Verdict)
	}
	f2 := newFakeProbe(s9Logs("CLOSED", "OPEN"))
	if res := RunNetworkBoundary(context.Background(), f2, "Bad Tag!", s9Target, time.Now()); res.Verdict != controlval.VerdictError || len(f2.created) != 0 {
		t.Errorf("a bad run tag must be refused before anything is created: %s %d", res.Verdict, len(f2.created))
	}
}

func apiLogs(anon, token string) func(string) string {
	return func(name string) string {
		if strings.HasPrefix(name, "bas-s10a") {
			return "wget: note\nHTTP/1.1 " + anon + " Forbidden\n"
		}
		return "HTTP/1.1 " + token + " Forbidden\n"
	}
}

func TestS10_RefusedBothWaysIsBlockedAndPasses(t *testing.T) {
	shortCleanup(t)
	f := newFakeProbe(apiLogs("401", "403"))
	res := RunAPIReachability(context.Background(), f, "a1b2c3", "np-app", time.Now())
	if res.Outcome != controlval.OutcomeBlocked || res.Verdict != controlval.VerdictPass {
		t.Errorf("want blocked/PASS, got %s/%s (%s)", res.Outcome, res.Verdict, res.Error)
	}
	if len(f.created) != 2 || len(f.deleted) != 2 || len(res.Cleanup) != 2 {
		t.Fatalf("two probe pods must be created and both removed: created=%d deleted=%v", len(f.created), f.deleted)
	}
	anonSpec := f.created[0]["spec"].(map[string]any)
	tokenSpec := f.created[1]["spec"].(map[string]any)
	if anonSpec["automountServiceAccountToken"] != false || tokenSpec["automountServiceAccountToken"] != true {
		t.Error("the anonymous probe must not mount a token; the token probe must")
	}
	for _, note := range res.Cleanup {
		if !strings.Contains(note, "removed") {
			t.Errorf("cleanup not recorded: %q", note)
		}
	}
}

func TestS10_AcceptedRequestIsAllowedAndFails(t *testing.T) {
	shortCleanup(t)
	res := RunAPIReachability(context.Background(), newFakeProbe(apiLogs("401", "200")), "a1b2c3", "np-app", time.Now())
	if res.Outcome != controlval.OutcomeAllowed || res.Verdict != controlval.VerdictFail {
		t.Errorf("a request the API accepted must be allowed/FAIL, got %s/%s", res.Outcome, res.Verdict)
	}
}

func TestS10_NoStatusLineIsError(t *testing.T) {
	shortCleanup(t)
	res := RunAPIReachability(context.Background(), newFakeProbe(func(string) string { return "wget: timeout\n" }),
		"a1b2c3", "np-app", time.Now())
	if res.Verdict != controlval.VerdictError {
		t.Errorf("a probe with no HTTP status must be ERROR, got %s", res.Verdict)
	}
}

func TestNetProbeClient_RefusesWhatItShouldNot(t *testing.T) {
	if _, err := NewNetProbeKubeClient("http://plain.example", "tok", nil); err == nil {
		t.Error("plain http must be refused")
	}
	if _, err := NewNetProbeKubeClient("https://a.example", " ", nil); err == nil {
		t.Error("an empty token must be refused")
	}
}
