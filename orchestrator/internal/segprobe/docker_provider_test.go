package segprobe

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeRun returns canned output keyed by the docker compose subcommand text.
func fakeRun(responses map[string]struct {
	out []byte
	err error
}) commandRunner {
	return func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		for key, r := range responses {
			if strings.Contains(joined, key) {
				return r.out, r.err
			}
		}
		return nil, errors.New("unexpected command: " + joined)
	}
}

func TestDockerProvider_FirewallEvents_CollectorDownIsUnavailable(t *testing.T) {
	p := &DockerProvider{composeFile: "c.yml", run: fakeRun(map[string]struct {
		out []byte
		err error
	}{"[u]logd": {err: errors.New("no match")}})}
	ev, ok, err := p.FirewallEvents(context.Background(), TimeWindow{})
	if ok || err == nil || ev != nil {
		t.Fatalf("got events=%v ok=%v err=%v; want unavailable with an error", ev, ok, err)
	}
	if !errors.Is(err, errCollectorDown) {
		t.Fatalf("got %v, want errCollectorDown", err)
	}
}

func TestDockerProvider_FirewallEvents_FiltersToWindow(t *testing.T) {
	data, err := os.ReadFile("testdata/fw_sample.log")
	if err != nil {
		t.Fatal(err)
	}
	p := &DockerProvider{composeFile: "c.yml", run: fakeRun(map[string]struct {
		out []byte
		err error
	}{
		"[u]logd": {out: nil},
		"cat":     {out: data},
	})}
	// A window that excludes every record in the capture.
	ev, ok, err := p.FirewallEvents(context.Background(), TimeWindow{
		From: time.Unix(0, 0), To: time.Unix(1, 0),
	})
	if err != nil || !ok || len(ev) != 0 {
		t.Fatalf("got %d events ok=%v err=%v; want 0 events, available", len(ev), ok, err)
	}
}

func TestDockerProvider_FirewallEvents_UnreadableLogIsUnavailable(t *testing.T) {
	p := &DockerProvider{composeFile: "c.yml", run: fakeRun(map[string]struct {
		out []byte
		err error
	}{
		"[u]logd": {out: nil},
		"cat":     {err: errors.New("No such file")},
	})}
	_, ok, err := p.FirewallEvents(context.Background(), TimeWindow{})
	if ok || err == nil {
		t.Fatalf("ok=%v err=%v; want unavailable with error", ok, err)
	}
}

func TestDockerProvider_Probe_ParsesRunnerOutput(t *testing.T) {
	out := []byte(`{"outcome":"timeout","start":"2026-11-11T10:00:00Z","end":"2026-11-11T10:00:03Z"}`)
	p := &DockerProvider{composeFile: "c.yml", run: fakeRun(map[string]struct {
		out []byte
		err error
	}{"segprobe-runner": {out: out}})}
	res, err := p.Probe(context.Background(), ProbeRequest{SrcZone: "corp", DstIP: "172.31.60.10", DstPort: 5432, Proto: "tcp", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Outcome != OutcomeTimeout || res.End.Sub(res.Start) != 3*time.Second {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestDockerProvider_Probe_UnknownOutcomeIsError(t *testing.T) {
	p := &DockerProvider{composeFile: "c.yml", run: fakeRun(map[string]struct {
		out []byte
		err error
	}{"segprobe-runner": {out: []byte(`{"outcome":"maybe"}`)}})}
	if _, err := p.Probe(context.Background(), ProbeRequest{SrcZone: "corp", DstIP: "x", DstPort: 1, Proto: "tcp"}); err == nil {
		t.Fatal("want error for unknown outcome")
	}
}

func TestDockerProvider_Healthy_TargetDownIsError(t *testing.T) {
	p := &DockerProvider{composeFile: "c.yml", run: fakeRun(map[string]struct {
		out []byte
		err error
	}{
		"probe-app": {},
		"core-app":  {err: errors.New("container not running")},
	})}
	if err := p.Healthy(context.Background(), ZoneApp); err == nil {
		t.Fatal("want error when target is down")
	}
}

func TestDockerProvider_TargetIP_CorpUsesProbeAddress(t *testing.T) {
	p := NewDockerProvider("c.yml")
	ip, err := p.TargetIP(ZoneCorp)
	if err != nil || ip != "172.31.10.10" {
		t.Fatalf("got %q, %v; want 172.31.10.10", ip, err)
	}
}
