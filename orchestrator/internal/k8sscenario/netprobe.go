package k8sscenario

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/audspect/bas/internal/controlval"
)

// NetProbeClient creates a short-lived probe pod, waits for it, reads its logs, and removes it. These are Lab-profile
// operations: they change the cluster, so they are only used for lab-class clusters (SPEC section 2).
type NetProbeClient interface {
	CreatePod(ctx context.Context, namespace string, pod map[string]any) error
	// WaitPod returns when the pod has finished (Succeeded or Failed), or when ctx ends.
	WaitPod(ctx context.Context, namespace, name string) (PodState, error)
	PodLogs(ctx context.Context, namespace, name string) (string, error)
	DeletePod(ctx context.Context, namespace, name string) error
	PodExists(ctx context.Context, namespace, name string) (bool, error)
}

// PodState is the terminal state of a probe pod.
type PodState struct {
	Phase string
	// ExitCode is the probe container's exit code. The probe scripts always exit 0, so a non-zero value means the
	// script itself failed.
	ExitCode int
}

// NetProbeEvidence is one observation made by a probe.
type NetProbeEvidence struct {
	Probe    string `json:"probe"`
	Target   string `json:"target"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Matched  bool   `json:"matched"`
	Detail   string `json:"detail,omitempty"`
}

// NetCheckResult is the recorded result of a network check.
type NetCheckResult struct {
	CheckID     string             `json:"checkId"`
	Title       string             `json:"title"`
	Technique   string             `json:"technique"`
	Profile     string             `json:"profile"`
	Namespace   string             `json:"namespace"`
	Outcome     controlval.Outcome `json:"outcome"`
	Verdict     controlval.Verdict `json:"verdict"`
	Probes      []NetProbeEvidence `json:"probes"`
	Cleanup     []string           `json:"cleanup"`
	Remediation string             `json:"remediation"`
	Source      string             `json:"source"`     // "network-probe"
	Confidence  string             `json:"confidence"` // "observed"
	Error       string             `json:"error,omitempty"`
	ExecutedAt  time.Time          `json:"executedAt"`
}

// runTagRE restricts the run tag used in probe pod names to a DNS-safe, short form.
var runTagRE = regexp.MustCompile(`^[a-z0-9]{4,12}$`)

// netProbeImage is the image of the S9 probe pods. It provides sh and nc.
const netProbeImage = "busybox:1.36"

// netProbeCurlImage is the image of the S10 probe pods. busybox wget cannot complete a TLS handshake with the lab API
// server (alert 40), so S10 uses curl, which can.
const netProbeCurlImage = "curlimages/curl:8.11.1"

// cleanupWait bounds how long a deleted pod may take to disappear. It is a variable so tests can shorten it.
var cleanupWait = 60 * time.Second

// cleanupPoll is how often removal is checked. A variable so tests can shorten it.
var cleanupPoll = 2 * time.Second

// probeSpec is one probe pod: its name, labels, service-account token setting, and shell script.
type probeSpec struct {
	name      string
	labels    map[string]string
	automount bool
	image     string
	script    string
}

func (p probeSpec) imageOrDefault() string {
	if p.image != "" {
		return p.image
	}
	return netProbeImage
}

func (p probeSpec) pod() map[string]any {
	labels := map[string]any{}
	for k, v := range p.labels {
		labels[k] = v
	}
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": p.name, "labels": labels},
		"spec": map[string]any{
			"restartPolicy":                "Never",
			"automountServiceAccountToken": p.automount,
			"containers": []any{map[string]any{
				"name": "probe", "image": p.imageOrDefault(),
				"command": []any{"sh", "-c", p.script},
			}},
		},
	}
}

// runProbe creates the pod, waits for it, reads its logs, and deletes it. The returned cleanup note says whether the
// pod was removed. A pod that could not be removed is reported, never ignored.
func runProbe(ctx context.Context, c NetProbeClient, namespace string, p probeSpec) (logs string, cleanup string, err error) {
	if err := c.CreatePod(ctx, namespace, p.pod()); err != nil {
		return "", cleanupNote(c, namespace, p.name, ctx), fmt.Errorf("creating probe pod %s: %w", p.name, err)
	}
	state, err := c.WaitPod(ctx, namespace, p.name)
	if err != nil {
		return "", cleanupNote(c, namespace, p.name, ctx), fmt.Errorf("waiting for probe pod %s: %w", p.name, err)
	}
	if state.ExitCode != 0 {
		return "", cleanupNote(c, namespace, p.name, ctx), fmt.Errorf("probe pod %s exited %d", p.name, state.ExitCode)
	}
	logs, err = c.PodLogs(ctx, namespace, p.name)
	if err != nil {
		return "", cleanupNote(c, namespace, p.name, ctx), fmt.Errorf("reading probe pod %s logs: %w", p.name, err)
	}
	return logs, cleanupNote(c, namespace, p.name, ctx), nil
}

// cleanupNote deletes the pod and confirms it is gone. It returns a line for the result.
func cleanupNote(c NetProbeClient, namespace, name string, ctx context.Context) string {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupWait)
	defer cancel()
	if err := c.DeletePod(dctx, namespace, name); err != nil {
		return fmt.Sprintf("%s: delete failed: %v", name, err)
	}
	deadline := time.Now().Add(cleanupWait)
	for {
		exists, err := c.PodExists(dctx, namespace, name)
		if err != nil {
			return fmt.Sprintf("%s: could not confirm removal: %v", name, err)
		}
		if !exists {
			return name + ": removed"
		}
		if time.Now().After(deadline) {
			return name + ": still present after delete; remove it by hand"
		}
		select {
		case <-dctx.Done():
			return name + ": removal not confirmed before timeout"
		case <-time.After(cleanupPoll):
		}
	}
}

// portLine matches the lines written by the S9 probe script: "PORT <n> OPEN" or "PORT <n> CLOSED".
var portLine = regexp.MustCompile(`PORT (\d+) (OPEN|CLOSED)`)

// NetworkBoundaryTarget is the service the S9 probe reaches, and the two ports whose expected results are fixed.
type NetworkBoundaryTarget struct {
	ProbeNamespace  string // namespace the probe pod runs in (np-app in the lab fixtures)
	TargetNamespace string // namespace of the service (np-db)
	Service         string // service name (db)
	AllowedPort     int    // expected OPEN from the probe namespace (5432)
	BlockedPort     int    // expected CLOSED from the probe namespace (3306)
}

// RunNetworkBoundary (S9) connects from a probe pod to the target service on a port the policy should allow and one
// it should block, and compares what it observes with the expectations.
//
//	blocked port open               -> Allowed, FAIL (the policy did not stop the flow)
//	allowed port closed             -> Blocked, FAIL (a flow the policy should permit is refused)
//	allowed port open, blocked closed -> Blocked, PASS
func RunNetworkBoundary(ctx context.Context, c NetProbeClient, runTag string, t NetworkBoundaryTarget, now time.Time) NetCheckResult {
	res := NetCheckResult{CheckID: "cross-namespace-service-reachability", Title: "Cross-namespace pod-to-service reachability",
		Technique: "Unauthorized pod-to-pod communication", Profile: "lab", Namespace: t.ProbeNamespace,
		Source: "network-probe", Confidence: "observed", ExecutedAt: now.UTC(),
		Remediation: "Change the NetworkPolicy so the blocked port is refused from this namespace and the allowed port stays open. " +
			"Confirm the CNI enforces NetworkPolicy; an open blocked port with a correct policy is a CNI finding."}
	if !runTagRE.MatchString(runTag) {
		res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError, "run tag must be 4 to 12 lower-case letters or digits"
		return res
	}
	host := fmt.Sprintf("%s.%s.svc.cluster.local", t.Service, t.TargetNamespace)
	script := fmt.Sprintf("for p in %d %d; do if nc -z -w 3 %s $p; then echo PORT $p OPEN; else echo PORT $p CLOSED; fi; done",
		t.BlockedPort, t.AllowedPort, host)
	spec := probeSpec{name: "bas-s9-" + runTag, labels: map[string]string{"app": "web", "bas-probe": "s9"},
		automount: false, script: script}
	logs, cleanup, err := runProbe(ctx, c, t.ProbeNamespace, spec)
	res.Cleanup = append(res.Cleanup, cleanup)
	if err != nil {
		res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError, err.Error()
		return res
	}
	observed := map[int]string{}
	for _, m := range portLine.FindAllStringSubmatch(logs, -1) {
		var port int
		fmt.Sscanf(m[1], "%d", &port)
		observed[port] = m[2]
	}
	blocked, okB := observed[t.BlockedPort]
	allowed, okA := observed[t.AllowedPort]
	if !okB || !okA {
		res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError, "the probe did not report both ports"
		return res
	}
	res.Probes = []NetProbeEvidence{
		{Probe: "blocked-port", Target: fmt.Sprintf("%s:%d", host, t.BlockedPort), Expected: "CLOSED", Observed: blocked, Matched: blocked == "CLOSED"},
		{Probe: "allowed-port", Target: fmt.Sprintf("%s:%d", host, t.AllowedPort), Expected: "OPEN", Observed: allowed, Matched: allowed == "OPEN"},
	}
	switch {
	case blocked == "OPEN":
		res.Outcome, res.Verdict = controlval.OutcomeAllowed, controlval.VerdictFail
	case allowed == "CLOSED":
		res.Outcome, res.Verdict = controlval.OutcomeBlocked, controlval.VerdictFail
	default:
		res.Outcome, res.Verdict = controlval.OutcomeBlocked, controlval.VerdictPass
	}
	if !strings.Contains(cleanup, "removed") {
		res.Verdict = controlval.VerdictError
		res.Error = "probe pod was not removed: " + cleanup
	}
	return res
}

// httpStatusLine matches the status line busybox wget prints with -S: "HTTP/1.1 403 Forbidden".
var httpStatusLine = regexp.MustCompile(`HTTP/[0-9.]+ (\d{3})`)

// apiURL is the API server address the S10 probes call.
const apiURL = "https://kubernetes.default.svc/api/v1/namespaces"

// RunAPIReachability (S10) calls the API server from a workload namespace twice: once anonymously, and once with the
// namespace's default service account token. Both must be refused.
//
//	any call returns 2xx -> Allowed, FAIL
//	both refused (401 or 403) -> Blocked, PASS
func RunAPIReachability(ctx context.Context, c NetProbeClient, runTag, namespace string, now time.Time) NetCheckResult {
	res := NetCheckResult{CheckID: "api-server-reachability-from-workload", Title: "Reachability to the Kubernetes API from a workload namespace",
		Technique: "Kubernetes API endpoint exposure and service account token use", Profile: "lab", Namespace: namespace,
		Source: "network-probe", Confidence: "observed", ExecutedAt: now.UTC(),
		Remediation: "Set automountServiceAccountToken: false on workloads that do not need the API, and remove grants from the " +
			"default service account."}
	if !runTagRE.MatchString(runTag) {
		res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError, "run tag must be 4 to 12 lower-case letters or digits"
		return res
	}
	// curl -D - prints the response headers, including the status line, to stdout.
	curlAnon := "curl -sk -D - -o /dev/null -m 10 " + apiURL + "; true"
	anon := probeSpec{name: "bas-s10a-" + runTag, labels: map[string]string{"bas-probe": "s10"}, automount: false,
		image: netProbeCurlImage, script: curlAnon}
	tokenScript := `curl -sk -D - -o /dev/null -m 10 -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" ` + apiURL + "; true"
	withToken := probeSpec{name: "bas-s10b-" + runTag, labels: map[string]string{"bas-probe": "s10"}, automount: true,
		image: netProbeCurlImage, script: tokenScript}

	var cleanups []string
	var outcomes []NetProbeEvidence
	failed := ""
	for _, p := range []struct {
		spec     probeSpec
		label    string
		expected string
	}{
		{anon, "anonymous", "refused (401 or 403)"},
		{withToken, "default-service-account-token", "refused (401 or 403)"},
	} {
		logs, cleanup, err := runProbe(ctx, c, namespace, p.spec)
		cleanups = append(cleanups, cleanup)
		if err != nil {
			failed = err.Error()
			break
		}
		status := ""
		if m := httpStatusLine.FindStringSubmatch(logs); m != nil {
			status = m[1]
		}
		if status == "" {
			// Keep a short excerpt of the probe output so the reason is visible in the result.
			excerpt := strings.TrimSpace(logs)
			if len(excerpt) > 400 {
				excerpt = excerpt[:400] + "..."
			}
			failed = p.label + ": no HTTP status in the probe output: " + excerpt
			break
		}
		outcomes = append(outcomes, NetProbeEvidence{Probe: p.label, Target: apiURL, Expected: p.expected,
			Observed: "HTTP " + status, Matched: status == "401" || status == "403"})
	}
	res.Probes, res.Cleanup = outcomes, cleanups
	if failed != "" {
		res.Outcome, res.Verdict, res.Error = controlval.OutcomeUnknown, controlval.VerdictError, failed
		return res
	}
	res.Outcome, res.Verdict = controlval.OutcomeBlocked, controlval.VerdictPass
	for _, o := range outcomes {
		if !o.Matched && strings.HasPrefix(o.Observed, "HTTP 2") {
			res.Outcome, res.Verdict = controlval.OutcomeAllowed, controlval.VerdictFail
		}
	}
	for _, note := range cleanups {
		if !strings.Contains(note, "removed") {
			res.Verdict = controlval.VerdictError
			res.Error = "probe pod was not removed: " + note
		}
	}
	return res
}
