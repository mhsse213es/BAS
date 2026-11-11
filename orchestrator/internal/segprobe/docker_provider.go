package segprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// fwLogPath is where seg-fw's ulogd collector writes OPRINT records.
const fwLogPath = "/var/log/seg/fw.log"

// commandRunner runs one external command and returns its stdout. It exists so
// the provider can be unit-tested without Docker.
type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", name, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// DockerProvider drives the seg-lab compose project. Addresses and service
// names are the fixed values from lab/segmentation/docker-compose.yml.
type DockerProvider struct {
	composeFile string
	run         commandRunner
}

func NewDockerProvider(composeFile string) *DockerProvider {
	return &DockerProvider{composeFile: composeFile, run: execRunner}
}

var probeService = map[Zone]string{
	ZoneCorp: "probe-corp", ZoneSWIFT: "probe-swift", ZoneCDE: "probe-cde",
	ZoneATM: "probe-atm", ZoneApp: "probe-app", ZoneDB: "probe-db",
}

var targetService = map[Zone]string{
	ZoneSWIFT: "swift-gateway", ZoneCDE: "cde-app", ZoneATM: "atm-mgmt",
	ZoneApp: "core-app", ZoneDB: "core-db",
}

var probeIP = map[Zone]string{
	ZoneCorp: "172.31.10.10", ZoneSWIFT: "172.31.20.20", ZoneCDE: "172.31.30.20",
	ZoneATM: "172.31.40.20", ZoneApp: "172.31.50.20", ZoneDB: "172.31.60.20",
}

var targetIP = map[Zone]string{
	ZoneSWIFT: "172.31.20.10", ZoneCDE: "172.31.30.10", ZoneATM: "172.31.40.10",
	ZoneApp: "172.31.50.10", ZoneDB: "172.31.60.10",
}

func (p *DockerProvider) compose(ctx context.Context, args ...string) ([]byte, error) {
	return p.run(ctx, "docker", append([]string{"compose", "-f", p.composeFile}, args...)...)
}

func (p *DockerProvider) Healthy(ctx context.Context, zone Zone) error {
	svc, ok := probeService[zone]
	if !ok {
		return fmt.Errorf("unknown zone %q", zone)
	}
	if _, err := p.compose(ctx, "exec", "-T", svc, "true"); err != nil {
		return fmt.Errorf("probe runner %s: %w", svc, err)
	}
	if target, ok := targetService[zone]; ok {
		if _, err := p.compose(ctx, "exec", "-T", target, "true"); err != nil {
			return fmt.Errorf("target %s: %w", target, err)
		}
	}
	return nil
}

func (p *DockerProvider) Lookup(zone Zone) (string, error) {
	ip, ok := probeIP[zone]
	if !ok {
		return "", fmt.Errorf("no probe address for zone %q", zone)
	}
	return ip, nil
}

// Corporate IT has no target service. Denied probes to it are dropped by the
// firewall, so its probe address is the destination; no listener is needed.
func (p *DockerProvider) TargetIP(zone Zone) (string, error) {
	if ip, ok := targetIP[zone]; ok {
		return ip, nil
	}
	if zone == ZoneCorp {
		return probeIP[ZoneCorp], nil
	}
	return "", fmt.Errorf("no target address for zone %q", zone)
}

type runnerOutput struct {
	Outcome string    `json:"outcome"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
}

func (p *DockerProvider) Probe(ctx context.Context, req ProbeRequest) (ProbeResult, error) {
	svc, ok := probeService[Zone(req.SrcZone)]
	if !ok {
		return ProbeResult{}, fmt.Errorf("unknown source zone %q", req.SrcZone)
	}
	out, err := p.compose(ctx, "exec", "-T", svc,
		"/usr/local/bin/segprobe-runner",
		"--dst", req.DstIP,
		"--port", fmt.Sprint(req.DstPort),
		"--proto", req.Proto,
		"--timeout", req.Timeout.String())
	if err != nil {
		return ProbeResult{}, fmt.Errorf("run probe from %s: %w", svc, err)
	}
	var r runnerOutput
	if err := json.Unmarshal(out, &r); err != nil {
		return ProbeResult{}, fmt.Errorf("parse probe output %q: %w", out, err)
	}
	outcome := Outcome(r.Outcome)
	switch outcome {
	case OutcomeConnected, OutcomeRefused, OutcomeTimeout, OutcomeDestinationUnavailable:
	default:
		return ProbeResult{}, fmt.Errorf("unknown probe outcome %q", r.Outcome)
	}
	return ProbeResult{Outcome: outcome, Start: r.Start, End: r.End}, nil
}

var errCollectorDown = errors.New("firewall log collector is not running")

// FirewallEvents reports the firewall evidence inside the window. It is
// available only when the collector process is running and its log can be read
// and parsed; anything else returns false, which the verdict engine turns into
// UNKNOWN rather than PASS.
func (p *DockerProvider) FirewallEvents(ctx context.Context, w TimeWindow) ([]FirewallEvent, bool, error) {
	if _, err := p.compose(ctx, "exec", "-T", "seg-fw", "sh", "-c", "ps | grep '[u]logd' >/dev/null"); err != nil {
		return nil, false, errCollectorDown
	}
	data, err := p.compose(ctx, "exec", "-T", "seg-fw", "cat", fwLogPath)
	if err != nil {
		return nil, false, fmt.Errorf("read firewall log: %w", err)
	}
	all, err := ParseFirewallLog(data)
	if err != nil {
		return nil, false, err
	}
	var in []FirewallEvent
	for _, e := range all {
		if !e.Time.Before(w.From) && !e.Time.After(w.To) {
			in = append(in, e)
		}
	}
	return in, true, nil
}
