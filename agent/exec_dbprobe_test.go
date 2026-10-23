package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

// fakeDBAdapter is a scriptable dbprobe.Adapter. It records every call so tests
// can assert what was (not) reached.
type fakeDBAdapter struct {
	mu          sync.Mutex
	calls       []string
	gotCfg      dbprobe.ConnectionConfig
	identity    string
	connectErr  error
	probeFn     func(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error)
	caps        []string
	capsSet     bool
	closeCalled bool

	// audit scripting (Task 9)
	auditSources     []string
	auditError       string
	auditFn          func(ctx context.Context, q dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error)
	auditQueries     []dbprobe.AuditQuery
	auditHadDeadline bool
}

func (f *fakeDBAdapter) rec(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeDBAdapter) count(s string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == s {
			n++
		}
	}
	return n
}

func (f *fakeDBAdapter) Connect(_ context.Context, cfg dbprobe.ConnectionConfig) error {
	f.rec("Connect")
	f.gotCfg = cfg
	return f.connectErr
}
func (f *fakeDBAdapter) Identity(context.Context) (string, error) {
	f.rec("Identity")
	return f.identity, nil
}
func (f *fakeDBAdapter) EnumerateRoles(context.Context) ([]dbprobe.Role, error) { return nil, nil }
func (f *fakeDBAdapter) ReadGrants(context.Context) ([]dbprobe.Grant, error)    { return nil, nil }
func (f *fakeDBAdapter) RunProbe(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
	f.rec("RunProbe")
	if f.probeFn != nil {
		return f.probeFn(ctx, def, spec)
	}
	return dbprobe.ProbeResult{RowsRead: 3, DBTime: time.Now()}, nil
}
func (f *fakeDBAdapter) CollectAudit(ctx context.Context, q dbprobe.AuditQuery) ([]dbprobe.AuditEvent, error) {
	f.rec("CollectAudit")
	f.mu.Lock()
	f.auditQueries = append(f.auditQueries, q)
	f.auditHadDeadline = func() bool { _, ok := ctx.Deadline(); return ok }()
	f.mu.Unlock()
	if f.auditFn != nil {
		return f.auditFn(ctx, q)
	}
	return nil, nil
}
func (f *fakeDBAdapter) Seed(context.Context, dbprobe.Fixture) error { f.rec("Seed"); return nil }
func (f *fakeDBAdapter) Cleanup(context.Context, dbprobe.Fixture) (dbprobe.CleanupResult, error) {
	f.rec("Cleanup")
	return dbprobe.CleanupResult{}, nil
}
func (f *fakeDBAdapter) Capabilities() dbprobe.Capabilities {
	if f.capsSet {
		return dbprobe.Capabilities{ProbeIDs: f.caps, AuditSources: f.auditSources, AuditError: f.auditError}
	}
	return dbprobe.Capabilities{ProbeIDs: dbprobe.ProbeIDs(), AuditSources: f.auditSources, AuditError: f.auditError}
}
func (f *fakeDBAdapter) Close() error { f.rec("Close"); f.closeCalled = true; return nil }

// installFakeDBAdapter routes every engine to fa for the duration of the test.
// The real adapters stay registered; only the executor's factory seam moves.
func installFakeDBAdapter(t *testing.T, fa *fakeDBAdapter) {
	t.Helper()
	orig := dbprobeNewAdapter
	dbprobeNewAdapter = func(string) (dbprobe.Adapter, bool) { return fa, true }
	t.Cleanup(func() { dbprobeNewAdapter = orig })
}

const testCredPassword = "S3cr3t-Pa55w0rd!"

// provisionDBCred stores a credential for ref via the env mechanism.
func provisionDBCred(t *testing.T, name, user, pw string) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"user": user, "password": pw})
	t.Setenv(dbcredEnvName(name), string(b))
}

func testDBProbeStep(mut func(*protocol.DBProbeSpec)) ScenarioStep {
	spec := protocol.DBProbeSpec{
		Engine: "postgresql", ProbeID: "read_roles", TargetID: "tgt-1",
		Host: "db.lab.internal", Port: 5432, Database: "bas_lab", TLSMode: "verify-full",
		ExpectedIdentity: "sysid-123", CredentialRef: "dbcred:lab-pg-ro",
		RunID: "run-1", Marker: "BAS-DBSIM-1", Mode: protocol.DBModeLab,
		Limits: protocol.DBProbeLimits{MaxRows: 10, TimeoutSec: 5, MaxConns: 1},
	}
	if mut != nil {
		mut(&spec)
	}
	return ScenarioStep{TaskID: "t1", Executor: "dbprobe", Command: spec.ProbeID,
		ExecutionClass: "non_destructive", DBProbe: &spec}
}

func happyFake() *fakeDBAdapter { return &fakeDBAdapter{identity: "sysid-123"} }

func setupHappy(t *testing.T) *fakeDBAdapter {
	t.Helper()
	fa := happyFake()
	installFakeDBAdapter(t, fa)
	provisionDBCred(t, "lab-pg-ro", "ro_user", testCredPassword)
	return fa
}

func TestDBProbeHappyPathOrderAndResult(t *testing.T) {
	fa := setupHappy(t)
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.GateRefusal != "" {
		t.Fatalf("unexpected refusal: %s", out.GateRefusal)
	}
	if out.Result.RowsRead != 3 || out.Result.AgentTime.IsZero() {
		t.Fatalf("bad result: %+v", out.Result)
	}
	want := []string{"Connect", "Identity", "RunProbe", "Close"}
	if strings.Join(fa.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("call order = %v, want %v", fa.calls, want)
	}
	if fa.gotCfg.User != "ro_user" || fa.gotCfg.Password != testCredPassword || fa.gotCfg.Host != "db.lab.internal" ||
		fa.gotCfg.Port != 5432 || fa.gotCfg.Database != "bas_lab" || fa.gotCfg.TLSMode != "verify-full" ||
		fa.gotCfg.Mode != protocol.DBModeLab {
		t.Fatalf("ConnectionConfig not populated from spec/credential: %#v", fa.gotCfg)
	}
}

func TestDBProbeUnknownProbeIDRefused(t *testing.T) {
	fa := setupHappy(t)
	out, err := executeDBProbe(context.Background(), testDBProbeStep(func(s *protocol.DBProbeSpec) { s.ProbeID = "drop_everything" }))
	if err != nil || out.GateRefusal == "" {
		t.Fatalf("unknown probe must be refused: err=%v out=%+v", err, out)
	}
	if fa.count("Connect") != 0 {
		t.Fatal("Connect called for an unknown probe id")
	}
}

func TestDBProbeNilSpecRefused(t *testing.T) {
	fa := setupHappy(t)
	step := testDBProbeStep(nil)
	step.DBProbe = nil
	out, _ := executeDBProbe(context.Background(), step)
	if out.GateRefusal == "" || fa.count("Connect") != 0 {
		t.Fatalf("nil spec must be refused pre-connect: %+v", out)
	}
}

func TestDBProbeRefusalsHappenBeforeConnect(t *testing.T) {
	cases := map[string]func(*protocol.DBProbeSpec){
		"empty expected identity": func(s *protocol.DBProbeSpec) { s.ExpectedIdentity = "" },
		"empty host":              func(s *protocol.DBProbeSpec) { s.Host = "" },
		"bad limits":              func(s *protocol.DBProbeSpec) { s.Limits.MaxRows = 0 },
		"engine unsupported":      func(s *protocol.DBProbeSpec) { s.Engine = "oracle" },
		"undeclared param":        func(s *protocol.DBProbeSpec) { s.Params = map[string]string{"sql": "select 1"} },
		"client mode disabled":    func(s *protocol.DBProbeSpec) { s.Mode = protocol.DBModeClient },
		"invalid mode":            func(s *protocol.DBProbeSpec) { s.Mode = "weird" },
		"cred ref traversal":      func(s *protocol.DBProbeSpec) { s.CredentialRef = "dbcred:../../etc/passwd" },
		"cred ref space":          func(s *protocol.DBProbeSpec) { s.CredentialRef = "dbcred:lab pg" },
		"cred ref empty":          func(s *protocol.DBProbeSpec) { s.CredentialRef = "" },
		"cred ref no prefix":      func(s *protocol.DBProbeSpec) { s.CredentialRef = "lab-pg-ro" },
		"cred ref unresolvable":   func(s *protocol.DBProbeSpec) { s.CredentialRef = "dbcred:nobody-provisioned-this" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			fa := setupHappy(t)
			out, err := executeDBProbe(context.Background(), testDBProbeStep(mut))
			if err != nil {
				t.Fatalf("a refusal is an outcome, not an error: %v", err)
			}
			if out.GateRefusal == "" {
				t.Fatalf("expected refusal, got %+v", out)
			}
			if fa.count("Connect") != 0 {
				t.Fatalf("Connect called despite refusal (%s)", out.GateRefusal)
			}
			if strings.Contains(out.GateRefusal, testCredPassword) {
				t.Fatal("refusal text leaks secret")
			}
		})
	}
}

func TestDBProbeClientModeNeedsLocalEnable(t *testing.T) {
	mut := func(s *protocol.DBProbeSpec) { s.Mode = protocol.DBModeClient }
	fa := setupHappy(t)
	if out, _ := executeDBProbe(context.Background(), testDBProbeStep(mut)); out.GateRefusal == "" || fa.count("Connect") != 0 {
		t.Fatalf("client mode must be refused by default pre-connect: %+v", out)
	}
	// Enabling is only possible via agent-local configuration.
	t.Setenv("BAS_DBPROBE_CLIENT_ENABLED", "1")
	out, err := executeDBProbe(context.Background(), testDBProbeStep(mut))
	if err != nil || out.GateRefusal != "" {
		t.Fatalf("client mode with local enable and read-only probe should run: err=%v out=%+v", err, out)
	}
}

func TestDBProbeLocalPolicyDefaultsOffAndIgnoresServerPayload(t *testing.T) {
	t.Setenv("BAS_DBPROBE_CLIENT_ENABLED", "")
	t.Setenv("BAS_DBPROBE_LAB_MUTATION_ALLOWED", "")
	p := dbprobePolicyFromEnv()
	if p.ClientEnabled || p.LabMutationAllowed {
		t.Fatalf("policy must default off: %+v", p)
	}
	for _, v := range []string{"yes", "0", "false", "2", "on", "enabled"} {
		t.Setenv("BAS_DBPROBE_CLIENT_ENABLED", v)
		if dbprobePolicyFromEnv().ClientEnabled {
			t.Fatalf("value %q must not enable", v)
		}
	}
	t.Setenv("BAS_DBPROBE_CLIENT_ENABLED", "true")
	t.Setenv("BAS_DBPROBE_LAB_MUTATION_ALLOWED", "1")
	p = dbprobePolicyFromEnv()
	if !p.ClientEnabled || !p.LabMutationAllowed {
		t.Fatalf("explicit true/1 must enable: %+v", p)
	}
}

func TestDBProbeIdentityMismatchRefusedAfterConnectBeforeRunProbe(t *testing.T) {
	fa := setupHappy(t)
	fa.identity = "some-other-server"
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil || out.GateRefusal == "" {
		t.Fatalf("identity mismatch must be a refusal: err=%v out=%+v", err, out)
	}
	if fa.count("Connect") != 1 || fa.count("Identity") != 1 {
		t.Fatalf("expected connect+identity before gate, calls=%v", fa.calls)
	}
	if fa.count("RunProbe") != 0 {
		t.Fatal("RunProbe ran despite identity mismatch")
	}
	if !fa.closeCalled {
		t.Fatal("adapter must be closed after refusal")
	}
}

func TestDBProbeEngineWithoutProbeCapabilityRefusedBeforeConnect(t *testing.T) {
	fa := setupHappy(t)
	fa.capsSet = true
	fa.caps = []string{"auth_check"} // adapter does not offer read_roles
	out, _ := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if out.GateRefusal == "" || fa.count("Connect") != 0 {
		t.Fatalf("adapter lacking the probe must be refused pre-connect: %+v calls=%v", out, fa.calls)
	}
}

func TestDBProbeNoAdapterRegisteredRefused(t *testing.T) {
	provisionDBCred(t, "lab-pg-ro", "u", "p")
	orig := dbprobeNewAdapter
	dbprobeNewAdapter = func(string) (dbprobe.Adapter, bool) { return nil, false }
	t.Cleanup(func() { dbprobeNewAdapter = orig })
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil || out.GateRefusal == "" {
		t.Fatalf("missing adapter must be a refusal: %v %+v", err, out)
	}
}

func TestDBProbeContextCancelStopsQueryAndReportsError(t *testing.T) {
	fa := setupHappy(t)
	started := make(chan struct{})
	fa.probeFn = func(ctx context.Context, _ dbprobe.ProbeDef, _ dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		close(started)
		<-ctx.Done()
		return dbprobe.ProbeResult{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	type res struct {
		out DBProbeOutcome
		err error
	}
	done := make(chan res, 1)
	go func() {
		o, e := executeDBProbe(ctx, testDBProbeStep(nil))
		done <- res{o, e}
	}()
	<-started
	cancel()
	select {
	case r := <-done:
		if r.err == nil {
			t.Fatal("cancelled probe must return an error, never a pass")
		}
		if r.out.Result.ErrorClass == "" {
			t.Fatalf("outcome must carry an error class: %+v", r.out.Result)
		}
		if r.out.Result.Denied {
			t.Fatal("cancel must not be reported as a denial")
		}
		if !fa.closeCalled {
			t.Fatal("adapter must be closed after cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("executeDBProbe did not stop after cancel")
	}
}

func TestDBProbeDeadlineFromSpecLimits(t *testing.T) {
	fa := setupHappy(t)
	fa.probeFn = func(ctx context.Context, _ dbprobe.ProbeDef, _ dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		<-ctx.Done()
		return dbprobe.ProbeResult{}, ctx.Err()
	}
	step := testDBProbeStep(func(s *protocol.DBProbeSpec) { s.Limits.TimeoutSec = 1 })
	start := time.Now()
	out, err := executeDBProbe(context.Background(), step)
	if err == nil || out.Result.ErrorClass == "" {
		t.Fatalf("deadline must surface as error: err=%v out=%+v", err, out.Result)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("deadline from Limits.TimeoutSec not applied")
	}
}

func TestDBProbeConnectErrorIsErrorAndScrubbed(t *testing.T) {
	fa := setupHappy(t)
	fa.connectErr = errors.New("dial failed for password " + testCredPassword)
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err == nil {
		t.Fatal("connect failure must be an error")
	}
	if strings.Contains(err.Error(), testCredPassword) || strings.Contains(strings.Join(out.Result.Notes, " "), testCredPassword) ||
		strings.Contains(out.Result.ErrorClass, testCredPassword) {
		t.Fatal("secret leaked in connect error")
	}
	if fa.count("RunProbe") != 0 {
		t.Fatal("RunProbe after failed connect")
	}
}

func TestDBProbeDeniedIsObservationNotError(t *testing.T) {
	fa := setupHappy(t)
	fa.probeFn = func(context.Context, dbprobe.ProbeDef, dbprobe.DBProbeSpec) (dbprobe.ProbeResult, error) {
		return dbprobe.ProbeResult{Denied: true, ErrorClass: "permission_denied"}, nil
	}
	out, err := executeDBProbe(context.Background(), testDBProbeStep(nil))
	if err != nil || !out.Result.Denied || out.GateRefusal != "" {
		t.Fatalf("denied must be a normal observation: %v %+v", err, out)
	}
}

func TestDBProbeResolvesCredentialRefWithoutLoggingSecret(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	fa := setupHappy(t)
	fa.connectErr = errors.New("boom " + testCredPassword)
	_, _ = executeDBProbe(context.Background(), testDBProbeStep(nil))
	// And the happy and refusal paths too.
	fa.connectErr = nil
	_, _ = executeDBProbe(context.Background(), testDBProbeStep(nil))
	_, _ = executeDBProbe(context.Background(), testDBProbeStep(func(s *protocol.DBProbeSpec) { s.ExpectedIdentity = "" }))

	if fa.gotCfg.Password != testCredPassword {
		t.Fatal("credential was not resolved into the connection config")
	}
	if strings.Contains(buf.String(), testCredPassword) {
		t.Fatalf("log output leaked the secret: %s", buf.String())
	}
	// Formatting the config must redact too.
	if s := fa.gotCfg.String(); strings.Contains(s, testCredPassword) {
		t.Fatal("ConnectionConfig.String leaked secret")
	}
}

func TestDBCredRefRegexpRejects(t *testing.T) {
	bad := []string{"", "dbcred:", "dbcred:../x", "dbcred:a/b", `dbcred:a\b`, "dbcred:a b", "dbcred:A", "dbcred:a_b",
		"dbcred:-a", "dbcred:a.b", "dbcred:" + strings.Repeat("a", 64), "x:abc", "dbcred:abc\n", "dbcred:abc\x00"}
	for _, ref := range bad {
		if _, err := resolveDBCredential(ref); err == nil || !errors.Is(err, errDBCredBadRef) {
			t.Errorf("ref %q: want errDBCredBadRef, got %v", ref, err)
		}
	}
	if _, err := resolveDBCredential("dbcred:ok-1"); !errors.Is(err, errDBCredUnresolved) {
		t.Errorf("well-formed but unprovisioned ref: want errDBCredUnresolved, got %v", err)
	}
}

func TestDBCredEnvMalformedJSONRefusedWithoutEchoingValue(t *testing.T) {
	const garbage = "{not json SECRETVALUE-xyz"
	t.Setenv(dbcredEnvName("lab-pg-ro"), garbage)
	_, err := resolveDBCredential("dbcred:lab-pg-ro")
	if err == nil || !errors.Is(err, errDBCredMalformed) {
		t.Fatalf("want errDBCredMalformed, got %v", err)
	}
	if strings.Contains(err.Error(), "SECRETVALUE") {
		t.Fatal("error echoes credential value")
	}
	for _, v := range []string{`{"user":"","password":"p"}`, `{"password":"p"}`, `{"user":"u","password":"p","extra":1}`, `[]`, `{"user":"u"}x`} {
		t.Setenv(dbcredEnvName("lab-pg-ro"), v)
		if _, err := resolveDBCredential("dbcred:lab-pg-ro"); !errors.Is(err, errDBCredMalformed) {
			t.Errorf("value %q: want malformed, got %v", v, err)
		}
	}
}

func TestDBCredEnvMalformedDoesNotFallBackToStore(t *testing.T) {
	orig := readStoredDBCredential
	called := false
	readStoredDBCredential = func(string) ([]byte, bool, error) {
		called = true
		return []byte(`{"user":"x","password":"y"}`), true, nil
	}
	t.Cleanup(func() { readStoredDBCredential = orig })
	t.Setenv(dbcredEnvName("lab-pg-ro"), "garbage")
	if _, err := resolveDBCredential("dbcred:lab-pg-ro"); err == nil {
		t.Fatal("malformed env must fail")
	}
	if called {
		t.Fatal("must not fall back to the store when the env var is present but malformed")
	}
}

func TestDBCredFallsBackToStoreWhenEnvAbsent(t *testing.T) {
	orig := readStoredDBCredential
	readStoredDBCredential = func(name string) ([]byte, bool, error) {
		if name != "lab-pg-ro" {
			t.Errorf("store asked for %q", name)
		}
		return []byte(`{"user":"stored","password":"pw"}`), true, nil
	}
	t.Cleanup(func() { readStoredDBCredential = orig })
	c, err := resolveDBCredential("dbcred:lab-pg-ro")
	if err != nil || c.User != "stored" || c.Password != "pw" {
		t.Fatalf("store fallback failed: %v %+v", err, c)
	}
	if strings.Contains(c.String(), "pw") || strings.Contains(c.GoString(), "pw") {
		t.Fatal("dbCredential must redact in String/GoString")
	}
}

func TestDBCredStoreErrorIsRefusalNeverDefault(t *testing.T) {
	orig := readStoredDBCredential
	readStoredDBCredential = func(string) ([]byte, bool, error) { return nil, false, errors.New("mode too wide") }
	t.Cleanup(func() { readStoredDBCredential = orig })
	if _, err := resolveDBCredential("dbcred:lab-pg-ro"); err == nil {
		t.Fatal("store error must propagate")
	}
}

func TestDBCredPosixFileModeWiderThan0600Refused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-mode check does not apply on Windows (DPAPI registry store is used there)")
	}
	dir := t.TempDir()
	orig := dbcredStoreDir
	dbcredStoreDir = dir
	t.Cleanup(func() { dbcredStoreDir = orig })
	p := filepath.Join(dir, "lab-pg-ro.json")
	if err := os.WriteFile(p, []byte(`{"user":"u","password":"p"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDBCredential("dbcred:lab-pg-ro"); err == nil || errors.Is(err, errDBCredUnresolved) {
		t.Fatalf("0644 file must be refused with a mode error, got %v", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := resolveDBCredential("dbcred:lab-pg-ro")
	if err != nil || c.User != "u" {
		t.Fatalf("0600 file must be accepted: %v %+v", err, c)
	}
}

func TestDBProbeExecStepFillsTypedResultNotStdout(t *testing.T) {
	setupHappy(t)
	r := execStep(context.Background(), testDBProbeStep(nil), nil)
	if r.DBProbe == nil || r.DBProbe.RowsRead != 3 {
		t.Fatalf("typed DBProbe result missing: %+v", r)
	}
	if r.ExitCode != 0 || r.Stdout != "" || r.Vetoed || r.TaskID != "t1" {
		t.Fatalf("bad ExecResult: %+v", r)
	}
	if isRetryableResult(r) {
		t.Fatal("a successful dbprobe result must not be retryable")
	}
}

func TestDBProbeExecStepRefusalIsVetoedNonRetryableAndNeverRunsShell(t *testing.T) {
	fa := setupHappy(t)
	step := testDBProbeStep(func(s *protocol.DBProbeSpec) { s.ExpectedIdentity = "" })
	// A shell-looking Command must never be executed for this executor.
	step.Command = "touch /tmp/pwned && calc.exe"
	r := execStep(context.Background(), step, nil)
	if !r.Vetoed || r.VetoedBlockSource != "dbsim_gate" || r.ExitCode != -1 || r.DBProbe == nil || r.DBProbe.ErrorClass == "" {
		t.Fatalf("refusal result wrong: %+v", r)
	}
	if isRetryableResult(r) {
		t.Fatal("a dbsim gate refusal must not be retried (account lockout risk)")
	}
	if fa.count("Connect") != 0 {
		t.Fatal("connect on refusal")
	}
}

func TestDBProbeExecStepErrorNotRetried(t *testing.T) {
	fa := setupHappy(t)
	fa.connectErr = errors.New("auth failed")
	r := execStep(context.Background(), testDBProbeStep(nil), nil)
	if r.ExitCode != -1 || r.DBProbe == nil || r.DBProbe.ErrorClass == "" || r.Vetoed {
		t.Fatalf("error result wrong: %+v", r)
	}
	if isRetryableResult(r) {
		t.Fatal("DB connect/auth errors must not be retried")
	}
	if fa.count("Connect") != 1 {
		t.Fatalf("connect attempted %d times", fa.count("Connect"))
	}
}

func TestDBProbeExecutorMatchedCaseInsensitively(t *testing.T) {
	fa := setupHappy(t)
	step := testDBProbeStep(nil)
	step.Executor = "DBProbe"
	r := execStep(context.Background(), step, nil)
	if r.DBProbe == nil || fa.count("Connect") != 1 {
		t.Fatalf("executor match must be case-insensitive: %+v", r)
	}
}

// --- step-shape pre-gate (runs before B5 in the step loop) ---

func TestDBProbePreGateRefusesShellBaggage(t *testing.T) {
	ok := testDBProbeStep(nil)
	if msg := dbprobeStepShapeRefusal(ok); msg != "" {
		t.Fatalf("clean dbprobe step refused: %s", msg)
	}
	cases := map[string]func(*ScenarioStep){
		"nil spec":   func(s *ScenarioStep) { s.DBProbe = nil },
		"cleanup":    func(s *ScenarioStep) { s.Cleanup = "rm -rf /" },
		"payload":    func(s *ScenarioStep) { s.Payloads = []protocol.Payload{{Name: "x", Content: "eA=="}} },
		"probe!=cmd": func(s *ScenarioStep) { s.Command = "read_grants" },
	}
	for name, mut := range cases {
		s := testDBProbeStep(nil)
		mut(&s)
		if dbprobeStepShapeRefusal(s) == "" {
			t.Errorf("%s: expected shape refusal", name)
		}
	}
	other := ScenarioStep{Executor: "sh", Command: "echo hi", Cleanup: "x"}
	if dbprobeStepShapeRefusal(other) != "" {
		t.Fatal("pre-gate must not touch non-dbprobe steps")
	}
}

// --- B5 interplay: dbsim must not weaken or bypass B5 ---

func TestDBProbeB5NonDestructiveStepPasses(t *testing.T) {
	s := testDBProbeStep(nil)
	if v, src := evaluateB5Gate(protocol.ScenarioStep{ExecutionClass: s.ExecutionClass, Command: s.Command, Cleanup: s.Cleanup, Payloads: s.Payloads}); v {
		t.Fatalf("non_destructive dbprobe step vetoed by B5 (%s)", src)
	}
}

func TestDBProbeB5UnknownOrMissingClassStillVetoed(t *testing.T) {
	s := testDBProbeStep(nil)
	for _, class := range []string{"", "bogus", "destructive", "NON_DESTRUCTIVE"} {
		if v, _ := evaluateB5Gate(protocol.ScenarioStep{ExecutionClass: class, Command: s.Command}); !v {
			t.Errorf("class %q must stay vetoed by B5 for a dbprobe step", class)
		}
	}
}
