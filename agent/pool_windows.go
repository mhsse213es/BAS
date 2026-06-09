//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/audspect/bas-agent/sched"
)

// ── PowerShell host pool ───────────────────────────────────────────────────────
//
// Spawning powershell.exe per step costs ~300–700ms of CLR + startup. The pool
// keeps a small set of long-lived powershell.exe "hosts" warm and feeds each step
// to one of them, eliminating that cold start. Each step runs in a FRESH runspace
// inside the host (see hostHarness) so no variable, function, drive, or module
// state leaks between steps — the pooled path is observationally identical to a
// fresh process for the read-only steps it serves.
//
// Only idempotent, read-only discovery steps are ever pooled (see pooledCandidate),
// which is what makes the design safe: a host failure can simply fall back to the
// per-process path without risk of double side-effects, and security-block /
// Job-Object semantics remain on the per-process path for everything that mutates.

// hostHarness is the PowerShell read-eval-print loop each host runs. It reads one
// JSON request per line from stdin, executes the command in a brand-new runspace
// with the request's env vars applied (then cleared), and writes one compact JSON
// response line to stdout. Nothing else is ever written to stdout, so each request
// maps to exactly one response line.
const hostHarness = `
$ErrorActionPreference = 'Continue'
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  if ($line.Length -eq 0) { continue }
  $req = $null
  try { $req = $line | ConvertFrom-Json } catch { continue }
  $stdout = ''; $stderr = ''; $exit = 0
  $rs = $null; $ps = $null; $envKeys = @()
  try {
    if ($req.env) {
      foreach ($p in $req.env.PSObject.Properties) {
        [Environment]::SetEnvironmentVariable($p.Name, [string]$p.Value)
        $envKeys += $p.Name
      }
    }
    $rs = [runspacefactory]::CreateRunspace()
    $rs.Open()
    $ps = [powershell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript([string]$req.command)
    $res = $ps.Invoke()
    $stdout = ($res | Out-String -Width 4096)
    if ($ps.HadErrors -and $ps.Streams.Error.Count -gt 0) {
      $stderr = ($ps.Streams.Error | Out-String -Width 4096)
      $exit = 1
    }
  } catch {
    $stderr = $_.Exception.Message
    $exit = 1
  } finally {
    if ($ps) { $ps.Dispose() }
    if ($rs) { $rs.Close(); $rs.Dispose() }
    foreach ($k in $envKeys) { [Environment]::SetEnvironmentVariable($k, $null) }
  }
  $resp = [ordered]@{ id = $req.id; exitCode = $exit; stdout = $stdout; stderr = $stderr } | ConvertTo-Json -Compress -Depth 4
  [Console]::Out.WriteLine($resp)
}
`

var reqSeq int64 // monotonic request id, shared across hosts

type hostReq struct {
	ID      int64             `json:"id"`
	Command string            `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
}

type hostResp struct {
	ID       int64  `json:"id"`
	ExitCode int    `json:"exitCode"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
}

// psHost is a single long-lived powershell.exe running hostHarness.
type psHost struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	resp   chan string // one stdout line per executed request
	errBuf *bytes.Buffer
	dead   int32
}

func startHost() (*psHost, error) {
	cmd := exec.Command("powershell",
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", encodePowerShell(hostHarness))
	silentCmd(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	h := &psHost{cmd: cmd, stdin: stdin, resp: make(chan string, 4), errBuf: &bytes.Buffer{}}
	go h.readLoop(stdout)
	go func() { _, _ = io.Copy(h.errBuf, stderr) }()
	return h, nil
}

func (h *psHost) readLoop(stdout io.Reader) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024) // tolerate large discovery output
	for sc.Scan() {
		h.resp <- sc.Text()
	}
	atomic.StoreInt32(&h.dead, 1)
	close(h.resp)
}

func (h *psHost) kill() {
	atomic.StoreInt32(&h.dead, 1)
	_ = h.stdin.Close() // harness exits when stdin closes
	if h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
	}
}

// exec submits one step to this host. It returns the result, whether a result was
// produced at all (ok=false → caller should fall back to the per-process path),
// and whether the host is still healthy enough to reuse.
func (h *psHost) exec(ctx context.Context, step ScenarioStep) (res ExecResult, ok, healthy bool) {
	id := atomic.AddInt64(&reqSeq, 1)
	env := map[string]string{}
	if step.PayloadDir != "" {
		env["BAS_PAYLOAD_DIR"] = step.PayloadDir
	}
	maps.Copy(env, step.Env)
	req := hostReq{ID: id, Command: step.Command, Env: env}
	b, _ := json.Marshal(req)
	b = append(b, '\n')

	start := time.Now()
	if _, err := h.stdin.Write(b); err != nil {
		return ExecResult{}, false, false // could not submit → safe to fall back
	}

	select {
	case line, open := <-h.resp:
		if !open {
			return ExecResult{}, false, false // host died before responding
		}
		var hr hostResp
		if err := json.Unmarshal([]byte(line), &hr); err != nil || hr.ID != id {
			return ExecResult{}, false, false // desync → discard host, fall back
		}
		return ExecResult{
			TaskID:     step.TaskID,
			ExitCode:   hr.ExitCode,
			Stdout:     trimOutput([]byte(hr.Stdout)),
			Stderr:     trimOutput([]byte(hr.Stderr)),
			DurationMs: time.Since(start).Milliseconds(),
			ExecutedAt: time.Now(),
		}, true, true
	case <-ctx.Done():
		// Step timeout or scenario cancel: the command may still be running in the
		// host, so the host is no longer reusable — discard it. The result is owned
		// by us (no fall-back re-run).
		return ExecResult{
			TaskID:     step.TaskID,
			ExitCode:   -1,
			Stderr:     "step timed out or was cancelled",
			DurationMs: time.Since(start).Milliseconds(),
			ExecutedAt: time.Now(),
		}, true, false
	}
}

// HostPool hands out warm hosts, one command at a time. Pool size matches the
// scheduler's worker count, so contention is bounded.
type HostPool struct {
	free chan *psHost
	live int32 // hosts the pool currently owns (free + in use)
}

// NewHostPool starts up to size warm hosts. If some fail to start the pool is
// simply smaller; if none start, Run always falls back to the per-process path.
func NewHostPool(size int) *HostPool {
	if size < 1 {
		size = 1
	}
	p := &HostPool{free: make(chan *psHost, size)}
	for range size {
		h, err := startHost()
		if err != nil {
			continue
		}
		p.free <- h
		atomic.AddInt32(&p.live, 1)
	}
	return p
}

func (p *HostPool) acquire(ctx context.Context) (*psHost, bool) {
	if p == nil || atomic.LoadInt32(&p.live) == 0 {
		return nil, false
	}
	select {
	case h := <-p.free:
		return h, true
	case <-ctx.Done():
		return nil, false
	}
}

// discard kills a broken host and tries to replace it so the pool stays warm.
func (p *HostPool) discard(h *psHost) {
	h.kill()
	if nh, err := startHost(); err == nil {
		p.free <- nh
		return
	}
	atomic.AddInt32(&p.live, -1)
}

// Run executes a pooled-candidate step on a warm host. ok=false means nothing ran
// and the caller must use the per-process path.
func (p *HostPool) Run(ctx context.Context, step ScenarioStep) (ExecResult, bool) {
	h, got := p.acquire(ctx)
	if !got {
		return ExecResult{}, false
	}
	res, ok, healthy := h.exec(ctx, step)
	if healthy {
		p.free <- h
	} else {
		p.discard(h)
	}
	return res, ok
}

// Close kills every pooled host. Call it only after the scheduler has finished, so
// all hosts have been returned to the free channel.
func (p *HostPool) Close() {
	if p == nil {
		return
	}
	atomic.StoreInt32(&p.live, 0)
	for {
		select {
		case h := <-p.free:
			h.kill()
		default:
			return
		}
	}
}

// pooledCandidate reports whether a step is safe to route through the warm pool:
// a no-payload PowerShell step that the server labelled as read-only observation.
// These are idempotent, so a host failure can fall back to a fresh process, and
// they never trip the AV/Job-Object semantics that the per-process path provides.
func pooledCandidate(step ScenarioStep) bool {
	if len(step.Payloads) > 0 {
		return false
	}
	switch strings.ToLower(step.Executor) {
	case "", "powershell", "psh":
	default:
		return false
	}
	return step.Resource != nil && step.Resource.Risk == sched.RiskObservation
}

// encodePowerShell encodes a script for powershell.exe -EncodedCommand: UTF-16LE
// then base64. This sidesteps all command-line quoting of the harness.
func encodePowerShell(s string) string {
	u := utf16.Encode([]rune(s))
	buf := make([]byte, len(u)*2)
	for i, r := range u {
		buf[2*i] = byte(r)
		buf[2*i+1] = byte(r >> 8)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
