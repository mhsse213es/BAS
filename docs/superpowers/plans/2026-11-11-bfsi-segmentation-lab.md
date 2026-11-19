# BFSI Segmentation Lab, Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-hosted, emulated BFSI network on staging, plus a Go probe layer that proves segmentation with firewall-backed verdicts (PASS, FAIL, UNKNOWN, ERROR).

**Architecture:** Six Docker networks stand in for the zones, with one router firewall (`seg-fw`) enforcing default-deny and logging each decision through NFLOG and ulogd2 into a file. Pure Go code (`internal/segprobe`) holds the verdict engine, evidence matcher, scenario model and executor, all behind a provider interface. Only the Docker provider talks to the lab. The existing `internal/zoneisolation` package is not touched.

**Tech Stack:** Go (orchestrator module, `github.com/audspect/bas`), Docker Compose, iptables, ulogd2, YAML scenario files, Postgres 16 image for the DB target.

**Spec:** `docs/superpowers/specs/2026-11-11-bfsi-segmentation-lab-design.md`

## Global Constraints

- Verdict set is exactly `PASS`, `FAIL`, `UNKNOWN`, `ERROR`.
- A `PASS` requires firewall evidence matching the probe's source IP, destination IP, destination port, protocol and time window.
- Firewall log unavailable or unreadable yields `UNKNOWN`, never `PASS`.
- Probe or destination unavailable yields `ERROR`.
- `internal/zoneisolation` is not modified in Phase 1.
- Lab networks use the fixed subnets in Task 5. The lab publishes no host ports in Phase 1.
- Live lab tests run only when `SEG_LAB=1` is set. `go test ./...` on the build host never requires the lab.
- Denied traffic is dropped by default; one scenario also exercises REJECT.
- Firewall rules are reset to the scenario's rule set at the start of every run.

## Review Focus

1. Probe connects but the firewall log cannot be read: must be UNKNOWN for an expected-deny probe, not FAIL or PASS. Pinned in Task 1 (`TestEvaluate_FirewallLogUnavailable_IsUnknown`).
2. Destination not listening, connection refused, expected deny: a refusal with no matching firewall event is UNKNOWN, not PASS. Pinned in Task 1 (`TestEvaluate_RefusedWithoutEvidence_IsUnknown`).
3. Unrelated firewall events (other probes, earlier runs) inside the same time window must not be attributed to this probe. Pinned in Task 2 (`TestMatchEvidence_ExcludesOtherTuples`).
4. Expected-allow probe that fails: the positive control is broken, so the verdict is ERROR, not PASS or FAIL. Pinned in Task 1 (`TestEvaluate_AllowRefused_IsError`).
5. Rules left from a previous run changing the next run's result. Pinned in Task 10 (`TestLive_RulesResetBetweenRuns`).

---

### Task 1: Verdict engine

**Files:**
- Create: `orchestrator/internal/segprobe/verdict.go`
- Test: `orchestrator/internal/segprobe/verdict_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type Expect string` with `ExpectAllow Expect = "allow"`, `ExpectDeny Expect = "deny"`
  - `type Outcome string` with `OutcomeConnected`, `OutcomeRefused`, `OutcomeTimeout`, `OutcomeProbeUnavailable`, `OutcomeDestinationUnavailable` (values `connected`, `refused`, `timeout`, `probe_unavailable`, `destination_unavailable`)
  - `type ProbeResult struct { Outcome Outcome; Start, End time.Time }`
  - `type FirewallEvent struct { Time time.Time; RuleID string; Action string; SrcIP, DstIP string; DstPort int; Proto string }`
  - `type Verdict string` with `PASS`, `FAIL`, `UNKNOWN`, `ERROR`
  - `type Evidence struct { ProbeResult ProbeResult; Events []FirewallEvent; FirewallAvailable bool }`
  - `func Evaluate(expect Expect, ev Evidence) (Verdict, string)`: returns the verdict and a short reason string.

**Rules (exact):**
- `!FirewallAvailable` → `UNKNOWN` (reason `firewall logging unavailable`), checked first for every outcome except `probe_unavailable` and `destination_unavailable`.
- `probe_unavailable` or `destination_unavailable` → `ERROR`.
- `expect == allow`:
  - `connected` with an `ACCEPT` event in `Events` → `PASS`.
  - `connected` with no `ACCEPT` event → `UNKNOWN` (reason `connected without firewall accept evidence`).
  - anything else → `ERROR` (reason `positive control failed`).
- `expect == deny`:
  - `connected` → `FAIL` (reason `prohibited connection succeeded`), regardless of events.
  - `refused` or `timeout` with a `DROP` or `REJECT` event in `Events` → `PASS`.
  - `refused` or `timeout` with no such event → `UNKNOWN`.

- [ ] **Step 1: Write the failing tests**

```go
package segprobe

import (
	"testing"
	"time"
)

func TestEvaluate_ProhibitedConnectionSucceeds_IsFail(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeConnected}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != FAIL {
		t.Fatalf("got %s, want FAIL", got)
	}
}

func TestEvaluate_FirewallBlockConfirmed_IsPass(t *testing.T) {
	ev := Evidence{
		ProbeResult:       ProbeResult{Outcome: OutcomeTimeout},
		Events:            []FirewallEvent{{RuleID: "SEG-DENY-001", Action: "DROP"}},
		FirewallAvailable: true,
	}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != PASS {
		t.Fatalf("got %s, want PASS", got)
	}
}

func TestEvaluate_TimeoutWithoutEvidence_IsUnknown(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeTimeout}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != UNKNOWN {
		t.Fatalf("got %s, want UNKNOWN", got)
	}
}

func TestEvaluate_RefusedWithoutEvidence_IsUnknown(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeRefused}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != UNKNOWN {
		t.Fatalf("got %s, want UNKNOWN", got)
	}
}

func TestEvaluate_DestinationUnavailable_IsError(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeDestinationUnavailable}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectDeny, ev)
	if got != ERROR {
		t.Fatalf("got %s, want ERROR", got)
	}
}

func TestEvaluate_AuthorizedConnectionSucceeds_IsPass(t *testing.T) {
	ev := Evidence{
		ProbeResult:       ProbeResult{Outcome: OutcomeConnected, Start: time.Unix(10, 0)},
		Events:            []FirewallEvent{{RuleID: "SEG-ALLOW-001", Action: "ACCEPT"}},
		FirewallAvailable: true,
	}
	got, _ := Evaluate(ExpectAllow, ev)
	if got != PASS {
		t.Fatalf("got %s, want PASS", got)
	}
}

func TestEvaluate_AllowRefused_IsError(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeRefused}, FirewallAvailable: true}
	got, _ := Evaluate(ExpectAllow, ev)
	if got != ERROR {
		t.Fatalf("got %s, want ERROR", got)
	}
}

func TestEvaluate_FirewallLogUnavailable_IsUnknown(t *testing.T) {
	ev := Evidence{ProbeResult: ProbeResult{Outcome: OutcomeConnected}, FirewallAvailable: false}
	got, _ := Evaluate(ExpectAllow, ev)
	if got != UNKNOWN {
		t.Fatalf("got %s, want UNKNOWN", got)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd orchestrator && go test ./internal/segprobe/ -run TestEvaluate -v`
Expected: FAIL, build error (undefined `Evaluate`, `Evidence`, and the other types).

- [ ] **Step 3: Implement the types and `Evaluate` in `orchestrator/internal/segprobe/verdict.go`**

Implement exactly the rules listed above. The function is pure: no I/O, no time.Now.

- [ ] **Step 4: Run to verify pass**

Run: `cd orchestrator && go test ./internal/segprobe/ -run TestEvaluate -v`
Expected: all 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/segprobe/verdict.go orchestrator/internal/segprobe/verdict_test.go
git commit -m "segprobe: add evidence-backed verdict engine"
```

---

### Task 2: Evidence matcher

**Files:**
- Create: `orchestrator/internal/segprobe/evidence.go`
- Test: `orchestrator/internal/segprobe/evidence_test.go`

**Interfaces:**
- Consumes: `ProbeRequest`, `ProbeResult`, `FirewallEvent` (Task 1 types).
- Produces:
  - `type ProbeRequest struct { SrcZone, DstZone, DstIP string; DstPort int; Proto string; Timeout time.Duration; Expect Expect; SrcIP string }`
  - `func MatchEvidence(req ProbeRequest, res ProbeResult, events []FirewallEvent, slack time.Duration) []FirewallEvent`

**Rule:** return only events where `SrcIP == req.SrcIP`, `DstIP == req.DstIP`, `DstPort == req.DstPort`, `Proto == req.Proto`, and `Time` is within `[res.Start - slack, res.End + slack]`. Preserve input order.

- [ ] **Step 1: Write the failing tests**

```go
package segprobe

import (
	"testing"
	"time"
)

func TestMatchEvidence_ExcludesOtherTuples(t *testing.T) {
	start := time.Unix(100, 0)
	req := ProbeRequest{SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp"}
	res := ProbeResult{Start: start, End: start.Add(time.Second)}
	events := []FirewallEvent{
		{Time: start, SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp", RuleID: "A"},
		{Time: start, SrcIP: "172.30.1.99", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp", RuleID: "B"},
		{Time: start, SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 5432, Proto: "tcp", RuleID: "C"},
	}
	got := MatchEvidence(req, res, events, time.Second)
	if len(got) != 1 || got[0].RuleID != "A" {
		t.Fatalf("got %+v, want only RuleID A", got)
	}
}

func TestMatchEvidence_ExcludesOutsideWindow(t *testing.T) {
	start := time.Unix(100, 0)
	req := ProbeRequest{SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp"}
	res := ProbeResult{Start: start, End: start.Add(time.Second)}
	events := []FirewallEvent{{Time: start.Add(time.Minute), SrcIP: "172.30.1.10", DstIP: "172.30.2.10", DstPort: 8443, Proto: "tcp"}}
	if got := MatchEvidence(req, res, events, time.Second); len(got) != 0 {
		t.Fatalf("got %d events, want 0", len(got))
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd orchestrator && go test ./internal/segprobe/ -run TestMatchEvidence -v`
Expected: FAIL, undefined `MatchEvidence`, `ProbeRequest`.

- [ ] **Step 3: Implement `MatchEvidence` in `orchestrator/internal/segprobe/evidence.go`**

Apply the rule above. Compare IP strings as given.

- [ ] **Step 4: Run to verify pass**

Run: `cd orchestrator && go test ./internal/segprobe/ -v`
Expected: all Task 1 and Task 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/segprobe/evidence.go orchestrator/internal/segprobe/evidence_test.go
git commit -m "segprobe: match probes to firewall evidence by tuple and window"
```

---

### Task 3: Scenario model and loader

**Files:**
- Create: `orchestrator/internal/segprobe/scenario.go`
- Test: `orchestrator/internal/segprobe/scenario_test.go`

**Interfaces:**
- Consumes: `Expect`, `ProbeRequest` (Tasks 1–2).
- Produces:
  - `type Zone string` with the six constants `ZoneCorp="corp"`, `ZoneSWIFT="swift"`, `ZoneCDE="cde"`, `ZoneATM="atm"`, `ZoneApp="app"`, `ZoneDB="db"`
  - `type ProbeSpec struct { ID string \`yaml:"id"\`; Src Zone \`yaml:"src"\`; Dst Zone \`yaml:"dst"\`; DstPort int \`yaml:"port"\`; Proto string \`yaml:"proto"\`; Expect Expect \`yaml:"expect"\`; Note string \`yaml:"note"\` }`
  - `type Scenario struct { ID string \`yaml:"id"\`; Name string \`yaml:"name"\`; Probes []ProbeSpec \`yaml:"probes"\` }`
  - `func LoadScenario(data []byte) (Scenario, error)`: parse YAML, then validate.

**Validation (errors):** empty `ID`; no probes; probe `ID` duplicated; `Src` or `Dst` not one of the six zones; `Src == Dst`; `Expect` not `allow` or `deny`; `Proto` not `tcp`; `DstPort` not in 1–65535.

Add `gopkg.in/yaml.v3` to `orchestrator/go.mod` if it is not already a dependency: check with `grep yaml.v3 orchestrator/go.mod` first.

- [ ] **Step 1: Write the failing tests**

```go
package segprobe

import "testing"

const validScenario = `
id: swift-isolation
name: SWIFT isolation
probes:
  - id: corp-to-swift
    src: corp
    dst: swift
    port: 8443
    proto: tcp
    expect: deny
`

func TestLoadScenario_Valid(t *testing.T) {
	s, err := LoadScenario([]byte(validScenario))
	if err != nil {
		t.Fatalf("LoadScenario: %v", err)
	}
	if s.ID != "swift-isolation" || len(s.Probes) != 1 || s.Probes[0].Expect != ExpectDeny {
		t.Fatalf("unexpected scenario %+v", s)
	}
}

func TestLoadScenario_RejectsUnknownZone(t *testing.T) {
	bad := `
id: x
name: x
probes:
  - id: p
    src: corp
    dst: mars
    port: 80
    proto: tcp
    expect: deny
`
	if _, err := LoadScenario([]byte(bad)); err == nil {
		t.Fatal("want error for unknown zone")
	}
}

func TestLoadScenario_RejectsDuplicateProbeID(t *testing.T) {
	bad := `
id: x
name: x
probes:
  - {id: p, src: corp, dst: swift, port: 80, proto: tcp, expect: deny}
  - {id: p, src: corp, dst: cde, port: 80, proto: tcp, expect: deny}
`
	if _, err := LoadScenario([]byte(bad)); err == nil {
		t.Fatal("want error for duplicate probe id")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd orchestrator && go test ./internal/segprobe/ -run TestLoadScenario -v`
Expected: FAIL, undefined `LoadScenario`, `Zone`.

- [ ] **Step 3: Implement in `orchestrator/internal/segprobe/scenario.go`**

Implement the types and validation listed above.

- [ ] **Step 4: Run to verify pass**

Run: `cd orchestrator && go test ./internal/segprobe/ -v`
Expected: all tests in the package PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/segprobe/scenario.go orchestrator/internal/segprobe/scenario_test.go orchestrator/go.mod orchestrator/go.sum
git commit -m "segprobe: add scenario model with validation"
```

---

### Task 4: Provider interface and executor

**Files:**
- Create: `orchestrator/internal/segprobe/provider.go`
- Create: `orchestrator/internal/segprobe/executor.go`
- Test: `orchestrator/internal/segprobe/executor_test.go`

**Interfaces:**
- Consumes: Tasks 1–3 types.
- Produces:
  - `type TimeWindow struct { From, To time.Time }`
  - `type Provider interface { Healthy(ctx context.Context, zone Zone) error; Lookup(zone Zone) (string, error); Probe(ctx context.Context, req ProbeRequest) (ProbeResult, error); FirewallEvents(ctx context.Context, w TimeWindow) ([]FirewallEvent, bool, error) }`. `Lookup` returns the IP for a zone's probe runner or target. The `bool` from `FirewallEvents` is `FirewallAvailable`.
  - `type ProbeOutcome struct { Spec ProbeSpec; Verdict Verdict; Reason string; Result ProbeResult; Events []FirewallEvent }`
  - `type RunResult struct { ScenarioID string; RunIndex int; Outcomes []ProbeOutcome }`
  - `func RunScenario(ctx context.Context, p Provider, s Scenario, runIndex int, runs int) (RunResult, error)`

**Executor behavior:**
1. For each probe spec, call `p.Healthy` on `Src` and `Dst`. Any failure: the probe's verdict is `ERROR` (reason `destination or probe unavailable`), and no probe is sent.
2. Otherwise build a `ProbeRequest`, with `SrcIP` and `DstIP` from `p.Lookup`. Call `p.Probe`. Use the returned `ProbeResult`.
3. Call `p.FirewallEvents` for the window `[res.Start-2s, res.End+2s]`, then `MatchEvidence` with slack 2s.
4. Call `Evaluate` with `FirewallAvailable` from step 3.

Add `Lookup(zone Zone) (string, error)` to the `Provider` interface in this task (the implementation lands in Task 7).

- [ ] **Step 1: Write the failing test with a fake provider**

```go
package segprobe

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeProvider struct {
	healthyErr map[Zone]error
	result     ProbeResult
	events     []FirewallEvent
	fwOK       bool
}

func (f *fakeProvider) Healthy(_ context.Context, z Zone) error { return f.healthyErr[z] }
func (f *fakeProvider) Lookup(z Zone) (string, error)          { return "10.0.0." + string(z[0]), nil }
func (f *fakeProvider) Probe(_ context.Context, _ ProbeRequest) (ProbeResult, error) {
	return f.result, nil
}
func (f *fakeProvider) FirewallEvents(_ context.Context, _ TimeWindow) ([]FirewallEvent, bool, error) {
	return f.events, f.fwOK, nil
}

func TestRunScenario_DestinationDown_IsError(t *testing.T) {
	p := &fakeProvider{healthyErr: map[Zone]error{ZoneSWIFT: errors.New("down")}, fwOK: true}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	got, err := RunScenario(context.Background(), p, s, 0, 1)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != ERROR {
		t.Fatalf("got %s, want ERROR", got.Outcomes[0].Verdict)
	}
}

func TestRunScenario_BlockedWithEvidence_IsPass(t *testing.T) {
	start := time.Unix(100, 0)
	p := &fakeProvider{
		result: ProbeResult{Outcome: OutcomeTimeout, Start: start, End: start.Add(time.Second)},
		events: []FirewallEvent{{Time: start, RuleID: "SEG-DENY-SWIFT", Action: "DROP", SrcIP: "10.0.0.c", DstIP: "10.0.0.s", DstPort: 8443, Proto: "tcp"}},
		fwOK:   true,
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	got, err := RunScenario(context.Background(), p, s, 0, 1)
	if err != nil {
		t.Fatalf("RunScenario: %v", err)
	}
	if got.Outcomes[0].Verdict != PASS {
		t.Fatalf("got %s (%s), want PASS", got.Outcomes[0].Verdict, got.Outcomes[0].Reason)
	}
}
```

Note: the fake's `Lookup` builds IPs by zone initial, so the event's `SrcIP`/`DstIP` in the test must match what `Lookup` returns. Keep them consistent when implementing: `10.0.0.c` for corp, `10.0.0.s` for swift.

- [ ] **Step 2: Run to verify failure**

Run: `cd orchestrator && go test ./internal/segprobe/ -run TestRunScenario -v`
Expected: FAIL, undefined `Provider`, `RunScenario`.

- [ ] **Step 3: Implement `provider.go` and `executor.go`**

Implement the interface and the executor behavior above. `RunScenario` runs the scenario `runs` times internally only if `runs > 1`; the `runIndex` argument is recorded. Keep `RunScenario` single-pass; repetition is done by the caller (Task 10).

- [ ] **Step 4: Run to verify pass**

Run: `cd orchestrator && go test ./internal/segprobe/ -v`
Expected: all package tests PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/segprobe/provider.go orchestrator/internal/segprobe/executor.go orchestrator/internal/segprobe/executor_test.go
git commit -m "segprobe: add provider interface and scenario executor"
```

---

### Task 5: Lab topology and fixed subnets

**Files:**
- Create: `lab/segmentation/docker-compose.yml`
- Create: `lab/segmentation/README.md`

**Interfaces:**
- Consumes: nothing.
- Produces (fixed values every later task relies on):

| Zone | Network name | Subnet | `seg-fw` IP on this network | Target IP | Target service |
|---|---|---|---|---|---|
| corp | `seg-corp` | 172.31.10.0/24 | 172.31.10.1 | 172.31.10.10 (probe-corp) | none |
| swift | `seg-swift` | 172.31.20.0/24 | 172.31.20.1 | 172.31.20.10 (swift-gateway) | TCP 8443 |
| cde | `seg-cde` | 172.31.30.0/24 | 172.31.30.1 | 172.31.30.10 (cde-app) | TCP 8443 |
| atm | `seg-atm` | 172.31.40.0/24 | 172.31.40.1 | 172.31.40.10 (atm-mgmt) | TCP 9000 |
| app | `seg-app` | 172.31.50.0/24 | 172.31.50.1 | 172.31.50.10 (core-app, probe-app) | TCP 8080 |
| db | `seg-db` | 172.31.60.0/24 | 172.31.60.1 | 172.31.60.10 (core-db) | TCP 5432 |

Probe runners: `probe-corp` (172.31.10.10), `probe-swift` (172.31.20.20), `probe-cde` (172.31.30.20), `probe-atm` (172.31.40.20), `probe-app` (172.31.50.20), `probe-db` (172.31.60.20). Target IPs above are fixed by the compose file.

Services are: `swift-gateway`, `cde-app`, `atm-mgmt`, `core-app`, `core-db`, each a simple TCP listener (busybox `nc -lk -p <port>` for 8443/9000/8080, `postgres:16-alpine` for core-db 5432), plus the probe runners and `seg-fw`.

Image digests: pin every image by digest. Resolve digests on staging with `docker pull` then `docker image inspect --format '{{index .RepoDigests 0}}'` and record them in `lab/segmentation/README.md`.

- [ ] **Step 1: Write the compose file**

Write `lab/segmentation/docker-compose.yml` with: six networks with the subnets above (driver bridge, `internal: true` so networks have no default route; `seg-fw` is the only route between zones), `seg-fw` attached to all six networks with its fixed IPs and `cap_add: [NET_ADMIN]`, `sysctls: net.ipv4.ip_forward=1`, the five service containers and six probe runners with their fixed IPs. Do not publish any host port.

- [ ] **Step 2: Validate the file**

Run on staging: `docker compose -f lab/segmentation/docker-compose.yml config --quiet && echo CONFIG_OK`
Expected: `CONFIG_OK`.

- [ ] **Step 3: Record digests in the README and commit**

```bash
git add lab/segmentation/docker-compose.yml lab/segmentation/README.md
git commit -m "lab/segmentation: add six-zone compose topology with fixed subnets"
```

---

### Task 6: Firewall rule set and NFLOG logging

**Files:**
- Create: `lab/segmentation/fw/Dockerfile`
- Create: `lab/segmentation/fw/ulogd.conf`
- Create: `lab/segmentation/fw/rules/default.sh`
- Create: `lab/segmentation/fw/rules/swift.sh`
- Create: `lab/segmentation/fw/rules/cde-atm.sh`
- Create: `lab/segmentation/fw/rules/core-banking.sh`
- Modify: `lab/segmentation/docker-compose.yml` (mount `./fw/rules` into `seg-fw` at `/rules`; mount a named volume `seg-logs` at `/var/log/seg`)

**Interfaces:**
- Consumes: Task 5 topology.
- Produces:
  - `/rules/apply.sh <scenario-rules-file>`: flushes the FORWARD chain, sets default policy `DROP`, appends `ESTABLISHED,RELATED ACCEPT`, then appends the rules in the given file, then appends a catch-all `NFLOG` for any packet reaching the end of FORWARD. Every rule carries an `NFLOG --nflog-prefix "SEG-<RULEID>"` line immediately before its ACCEPT or DROP.
  - Rule IDs have the form `SEG-ALLOW-NNN`, `SEG-DENY-NNN`, and `SEG-CATCHALL`.
  - `ulogd2` (NFLOG group 1) writes one line per packet to `/var/log/seg/fw.log` with fields: timestamp (ISO-8601), prefix, src IP, dst IP, proto, dst port, action (`ACCEPT`, `DROP`, or `REJECT`), in a fixed `key=value` format.
  - The file is the only logging contract. Task 7 parses it.

- [ ] **Step 1: Spike: confirm ulogd2 is available on the chosen base image**

On staging, build a throwaway image from `alpine:3.20` with `apk add iptables ulogd`, run it with `--cap-add NET_ADMIN`, and confirm `ulogd -V` runs and `iptables -j NFLOG --nflog-group 1` is accepted.

Expected: `ulogd` prints its version and `iptables` accepts the NFLOG target. If either fails, stop and report to the user before continuing. The fallback (kernel log via the host) needs a decision from them.

- [ ] **Step 2: Write `fw/Dockerfile` and `fw/ulogd.conf`**

`ulogd.conf` must configure the NFLOG input on group 1 and an output to `/var/log/seg/fw.log` using the key=value format above. Pin the Alpine digest from Task 5.

- [ ] **Step 3: Write `fw/rules/default.sh`**

The script runs `apply.sh` against a file with no allow rules, which means everything is denied. Make rule files one line per rule, format: `<RULEID> <ACTION> <srcCIDR> <dstIP> <dstPort> <proto>` where ACTION is ACCEPT, DROP or REJECT. Example:
`SEG-DENY-SWIFT-1 DROP 172.31.10.0/24 172.31.20.10 8443 tcp`

- [ ] **Step 4: Write the three scenario rule files**

`swift.sh`, `cde-atm.sh`, `core-banking.sh` each contain only rule lines for their pack, including the authorized paths (for core-banking: `SEG-ALLOW-DB-1 ACCEPT 172.31.50.0/24 172.31.60.10 5432 tcp`). Rule lines use `REJECT` in exactly one scenario, `cde-atm.sh`, for `SEG-DENY-CDE-REJECT-1`.

- [ ] **Step 5: Verify on staging**

Run on staging:
```
docker compose -f lab/segmentation/docker-compose.yml up -d seg-fw
docker compose -f lab/segmentation/docker-compose.yml exec seg-fw /rules/apply.sh /rules/core-banking.sh
docker compose -f lab/segmentation/docker-compose.yml exec probe-app sh -c 'nc -z -w 2 172.31.60.10 5432 && echo OPEN'
docker compose -f lab/segmentation/docker-compose.yml exec probe-corp sh -c 'nc -z -w 2 172.31.60.10 5432 || echo BLOCKED'
docker compose -f lab/segmentation/docker-compose.yml exec seg-fw tail -n 2 /var/log/seg/fw.log
```
Expected: `OPEN`, `BLOCKED`, and the last two log lines show an `ACCEPT` for the app probe and a `DROP` for the corp probe with the matching rule IDs.

- [ ] **Step 6: Commit**

```bash
git add lab/segmentation/fw lab/segmentation/docker-compose.yml
git commit -m "lab/segmentation: add default-deny firewall rules with NFLOG evidence"
```

---

### Task 7: Docker provider

**Files:**
- Create: `orchestrator/internal/segprobe/docker_provider.go`
- Create: `orchestrator/internal/segprobe/fwlog.go`
- Test: `orchestrator/internal/segprobe/fwlog_test.go`
- Test (live, env-gated): `orchestrator/internal/segprobe/docker_provider_live_test.go`

**Interfaces:**
- Consumes: Tasks 1–4.
- Produces:
  - `func ParseFirewallLog(data []byte) ([]FirewallEvent, error)`: parses the Task 6 key=value lines. Unparseable lines are skipped; a line missing a required field is an error for the whole call.
  - `type DockerProvider struct { Compose string; Project string; FWLogPath string }` implementing `Provider`. `Probe` runs `docker compose exec -T probe-<src> /usr/local/bin/segprobe-runner --dst <ip> --port <p> --proto tcp --timeout 3s` and parses its JSON stdout into `ProbeResult`. `Healthy` runs `docker compose exec -T probe-<src> true` and `docker compose exec -T <target-service> true`, returning an error on failure. `FirewallEvents` runs `docker compose exec -T seg-fw cat /var/log/seg/fw.log`, parses, and filters by window; `available` is false if the command fails or the file is missing.

**Required log fields:** `ts`, `prefix`, `src`, `dst`, `proto`, `dpt`, `action`. A line missing `prefix` or `action` is an error.

- [ ] **Step 1: Write the failing parser test**

```go
package segprobe

import "testing"

func TestParseFirewallLog_ParsesFields(t *testing.T) {
	data := []byte("ts=2026-11-11T10:00:00Z prefix=SEG-DENY-SWIFT-1 src=172.31.10.10 dst=172.31.20.10 proto=tcp dpt=8443 action=DROP\n")
	ev, err := ParseFirewallLog(data)
	if err != nil {
		t.Fatalf("ParseFirewallLog: %v", err)
	}
	if len(ev) != 1 || ev[0].RuleID != "SEG-DENY-SWIFT-1" || ev[0].Action != "DROP" || ev[0].DstPort != 8443 {
		t.Fatalf("unexpected events %+v", ev)
	}
}

func TestParseFirewallLog_MissingActionIsError(t *testing.T) {
	if _, err := ParseFirewallLog([]byte("ts=2026-11-11T10:00:00Z prefix=SEG-X src=a dst=b proto=tcp dpt=1\n")); err == nil {
		t.Fatal("want error")
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd orchestrator && go test ./internal/segprobe/ -run TestParseFirewallLog -v`
Expected: FAIL, undefined `ParseFirewallLog`.

- [ ] **Step 3: Implement `fwlog.go` and `docker_provider.go`**

Implement the parser and the provider as described. `Lookup(zone)` returns the fixed target IPs from Task 5's table for the zone's target, and the probe runner IP for the source.

- [ ] **Step 4: Run unit tests**

Run: `cd orchestrator && go test ./internal/segprobe/ -v`
Expected: all unit tests PASS. The live test is skipped unless `SEG_LAB=1`.

- [ ] **Step 5: Live check on staging**

Run on staging with the Task 6 rules applied: `SEG_LAB=1 go test ./internal/segprobe/ -run TestLive_ProviderProbeAndEvidence -v`
Expected: PASS. The test sends one denied and one allowed probe and asserts the denied probe has a DROP event for its tuple.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/segprobe/fwlog.go orchestrator/internal/segprobe/fwlog_test.go orchestrator/internal/segprobe/docker_provider.go orchestrator/internal/segprobe/docker_provider_live_test.go
git commit -m "segprobe: add Docker provider and firewall log parser"
```

---

### Task 8: Probe runner binary

**Files:**
- Create: `orchestrator/cmd/segprobe-runner/main.go`
- Test: `orchestrator/cmd/segprobe-runner/main_test.go`

**Interfaces:**
- Consumes: `OutcomeConnected`, `OutcomeRefused`, `OutcomeTimeout`, `ProbeResult` (Task 1).
- Produces: a static binary that takes `--dst`, `--port`, `--proto`, `--timeout`, dials TCP, and prints one JSON object `{"outcome": "...", "start": "<RFC3339Nano>", "end": "<RFC3339Nano>"}` to stdout. Mapping: dial success → `connected`; `ECONNREFUSED` → `refused`; deadline exceeded → `timeout`; other errors → `destination_unavailable`.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"net"
	"testing"
	"time"
)

func TestProbeTCP_Connected(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	out := probeTCP(l.Addr().String(), 2*time.Second)
	if out != "connected" {
		t.Fatalf("got %s, want connected", out)
	}
}

func TestProbeTCP_Refused(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	if out := probeTCP(addr, 2*time.Second); out != "refused" {
		t.Fatalf("got %s, want refused", out)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd orchestrator && go test ./cmd/segprobe-runner/ -v`
Expected: FAIL, undefined `probeTCP`.

- [ ] **Step 3: Implement `main.go`**

Implement `probeTCP(addr string, timeout time.Duration) string` returning the outcome name, and `main` that wraps it with timestamps and JSON output.

- [ ] **Step 4: Run to verify pass**

Run: `cd orchestrator && go test ./cmd/segprobe-runner/ -v`
Expected: both tests PASS.

- [ ] **Step 5: Build the static binary**

Run: `cd orchestrator && CGO_ENABLED=0 GOOS=linux go build -o ../lab/segmentation/bin/segprobe-runner ./cmd/segprobe-runner`
Expected: a binary is written. Mount `lab/segmentation/bin` read-only into each probe runner at `/usr/local/bin` by adding that volume to `docker-compose.yml`, and commit the compose change in this task.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/cmd/segprobe-runner lab/segmentation/docker-compose.yml
git commit -m "segprobe: add static TCP probe runner"
```

---

### Task 9: Scenario packs

**Files:**
- Create: `lab/segmentation/scenarios/swift-isolation.yaml`
- Create: `lab/segmentation/scenarios/cde-atm-isolation.yaml`
- Create: `lab/segmentation/scenarios/core-banking-tiering.yaml`
- Test: `orchestrator/internal/segprobe/packs_test.go`

**Interfaces:**
- Consumes: `LoadScenario` (Task 3).
- Produces: three scenario files matching the spec's packs. Each file must load with `LoadScenario` and include at least one positive control (`expect: allow`) and at least one denied probe.

Contents:
- `swift-isolation.yaml`: `corp-to-swift` (corp→swift, 8443, deny), `swift-to-corp` (swift→corp, 8443, deny), `swift-local-control` (swift→swift, 8443, allow). The SWIFT pack has no routed authorized path, so its positive control is same-zone: probe-swift reaches swift-gateway without crossing `seg-fw`. Record this decision in the pack's header comment.
- `cde-atm-isolation.yaml`: `corp-to-cde` (corp→cde, 8443, deny), `corp-to-atm` (corp→atm, 9000, deny), `app-to-cde` (app→cde, 8443, deny, uses REJECT rule `SEG-DENY-CDE-REJECT-1`), `atm-local-control` (atm→atm, 9000, allow, same-zone as above).
- `core-banking-tiering.yaml`: `corp-to-db` (corp→db, 5432, deny), `app-to-db-authorized` (app→db, 5432, allow), `app-to-db-other-port` (app→db, 3306, deny), `user-to-db` (corp→db, 5432, deny).

Same-zone probes: the executor (Task 4) must treat `src == dst` as `connected`-means-PASS without firewall evidence, and this rule must be covered by a test in this task.

- [ ] **Step 1: Write the failing test**

```go
package segprobe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPacks_LoadAndHavePositiveControls(t *testing.T) {
	files, _ := filepath.Glob("../../../lab/segmentation/scenarios/*.yaml")
	if len(files) != 3 {
		t.Fatalf("got %d packs, want 3", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s, err := LoadScenario(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var hasAllow, hasDeny bool
		for _, p := range s.Probes {
			hasAllow = hasAllow || p.Expect == ExpectAllow
			hasDeny = hasDeny || p.Expect == ExpectDeny
		}
		if !hasAllow || !hasDeny {
			t.Fatalf("%s: needs both an allow and a deny probe", f)
		}
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd orchestrator && go test ./internal/segprobe/ -run TestPacks -v`
Expected: FAIL, `got 0 packs, want 3`.

- [ ] **Step 3: Write the three YAML files and the same-zone rule**

Write the three files as listed. Add the same-zone rule in `executor.go` with a test `TestRunScenario_SameZoneConnected_IsPassWithoutFirewall` in `executor_test.go`.

- [ ] **Step 4: Run to verify pass**

Run: `cd orchestrator && go test ./internal/segprobe/ -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add lab/segmentation/scenarios orchestrator/internal/segprobe/packs_test.go orchestrator/internal/segprobe/executor.go orchestrator/internal/segprobe/executor_test.go
git commit -m "segprobe: add SWIFT, CDE/ATM and core-banking scenario packs"
```

---

### Task 10: Repeated runs and live gates G1–G6

**Files:**
- Create: `orchestrator/internal/segprobe/gates_live_test.go` (all live, env-gated by `SEG_LAB=1`)
- Create: `orchestrator/cmd/segprobe/main.go` (CLI: `segprobe run --scenario <file> --runs 3`)
- Create: `docs/segmentation-mastery-qa-log.md` (QA log per the project convention)

**Interfaces:**
- Consumes: everything above.
- Produces: `RunRepeated(ctx, p Provider, s Scenario, runs int) ([]RunResult, bool, error)` where the `bool` is true only when every run produced identical verdicts per probe. Add this function to `executor.go` in this task, with a unit test using the fake provider.

Live tests (each one reconfigures the lab with `apply.sh` and restores `core-banking.sh` at the end):
- `TestLive_RulesResetBetweenRuns` (Review Focus 5): apply a rule set that allows a denied path, run once, then apply the normal set and run again. The second run must be FAIL-free for that probe (verdict PASS).
- G1 `TestLive_G1_OpenedProhibitedPath_IsFail`: apply a rule that ACCEPTs corp→db 5432, run `corp-to-db`, assert FAIL.
- G2 `TestLive_G2_FirewallBlock_IsPass`: normal rules, run `corp-to-db`, assert PASS.
- G3 `TestLive_G3_NoEvidence_IsUnknown`: apply a rule set with no DROP or REJECT rule for the denied path and no catch-all, so the probe times out and nothing is logged for its tuple. Assert UNKNOWN.
- G4 `TestLive_G4_DestinationDown_IsError`: `docker compose stop core-db`, run `app-to-db-authorized`, assert ERROR, then restart.
- G5 `TestLive_G5_AuthorizedPath_IsPass`: normal rules, run `app-to-db-authorized`, assert PASS.
- G6 `TestLive_G6_LogDisabled_IsUnknown`: stop `ulogd` in `seg-fw` (`docker compose exec seg-fw pkill ulogd`), run `corp-to-db`, assert UNKNOWN for every probe, restart `ulogd`.
- Determinism: `TestLive_ThreeRunsIdentical` runs each pack 3 times and asserts identical verdicts per probe.

- [ ] **Step 1: Write the failing `RunRepeated` unit test**

```go
func TestRunRepeated_IdenticalRunsAreStable(t *testing.T) {
	start := time.Unix(100, 0)
	p := &fakeProvider{
		result: ProbeResult{Outcome: OutcomeTimeout, Start: start, End: start.Add(time.Second)},
		events: []FirewallEvent{{Time: start, RuleID: "SEG-DENY-1", Action: "DROP", SrcIP: "10.0.0.c", DstIP: "10.0.0.s", DstPort: 8443, Proto: "tcp"}},
		fwOK:   true,
	}
	s := Scenario{ID: "s", Probes: []ProbeSpec{{ID: "p", Src: ZoneCorp, Dst: ZoneSWIFT, DstPort: 8443, Proto: "tcp", Expect: ExpectDeny}}}
	runs, stable, err := RunRepeated(context.Background(), p, s, 3)
	if err != nil || len(runs) != 3 || !stable {
		t.Fatalf("runs=%d stable=%v err=%v", len(runs), stable, err)
	}
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd orchestrator && go test ./internal/segprobe/ -run TestRunRepeated -v`
Expected: FAIL, undefined `RunRepeated`.

- [ ] **Step 3: Implement `RunRepeated` and the CLI**

`RunRepeated` calls `RunScenario` `runs` times with `runIndex` 0..runs-1 and compares verdicts per probe ID. The CLI loads a scenario file, builds a `DockerProvider`, prints a table of verdicts and reasons for each run, and exits 0 after printing. It does not decide pass or fail for the whole pack; that is a reporting question for Phase 2.

- [ ] **Step 4: Run unit tests**

Run: `cd orchestrator && go test ./internal/segprobe/ -v`
Expected: PASS.

- [ ] **Step 5: Run the live gates on staging**

Run on staging: `SEG_LAB=1 go test ./internal/segprobe/ -run TestLive -v -timeout 20m`
Expected: all live tests PASS. Record the output in `docs/segmentation-mastery-qa-log.md`.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/segprobe orchestrator/cmd/segprobe docs/segmentation-mastery-qa-log.md
git commit -m "segprobe: add repeated runs, CLI and live gates G1-G6"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-11-11-bfsi-segmentation-lab.md`. Which execution approach would you prefer?

- **Subagent-driven:** a fresh subagent implements each task and a fresh reviewer checks it before the next starts. Most thorough, but each task re-reads the codebase from zero.
- **Native:** I implement every task in this session, then one fresh reviewer checks the whole branch at the end. Cheapest and faster, with no per-task review.

For this plan I recommend **native**, because the tasks depend on each other's interfaces and the live gates need staging access in the same session. Which approach should we use?
