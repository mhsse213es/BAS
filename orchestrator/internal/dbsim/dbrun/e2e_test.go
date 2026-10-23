//go:build dbsim_e2e

package dbrun

// End-to-end harness for the dbsim milestone (plan Task 13). It is correct by
// construction but, on the host it was written on (no Docker, no MySQL), it has
// NEVER been executed against a lab stack: nothing here is evidence that the
// end-to-end path works. See lab/dbsim/E2E.md for how to run it on staging.
//
// What is real when it runs against the lab:
//   - the shipped scenario YAML + .sig, loaded and signature-verified by
//     scenario.Engine.Load (the build must carry the vendor public key);
//   - dbbuild.BuildSteps (target resolution, Authorize, run id, marker);
//   - a CommandEnvelope signed with internal/cmdsigning and verified by the
//     agent's own (*Agent).verifyCommandEnvelope;
//   - the agent's gateStep/execStep -> executeDBProbe, the real adapters and
//     drivers, against the real lab database;
//   - the real detectverify Elastic connector against the lab Elasticsearch;
//   - dbcorrelate.Correlate, dbsim.BuildReport and Record.Validate.
//
// What is NOT real: the agent runs as a go-test binary (the production agent
// has no one-shot mode and only receives work over its enrolled WebSocket from
// a running orchestrator), so the WebSocket transport, enrollment, the run
// event stream and the orchestrator's persistence are not exercised; and the
// signing key/certificate are throwaway, not the deployment's.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/cmdsigning"
	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbbuild"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
	"github.com/audspect/bas/internal/integrity"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

const e2eAgentID = "dbsim-e2e-agent-0001"

// Environment variable NAMES (values are never printed).
//
//	DBSIM_E2E_AGENT_BIN        path to the agent test binary built with -tags dbsim_e2e
//	DBSIM_E2E_ES_URL, DBSIM_E2E_ES_USER, DBSIM_E2E_ES_PASSWORD   alerts reader
//	DBSIM_E2E_AGENT_IP         the agent's source IP as the SIEM sees it
//	DBSIM_E2E_WINDOW           detection window (Go duration, default 3m)
//	DBSIM_E2E_ALERT_WAIT       how long to poll for the alert (default 150s)
//	<ENGINE>_{HOST,PORT,DB,IDENTITY,DBHOSTNAME,DBIP,CRED_LAB,CRED_RO}
//	                           with ENGINE = DBSIM_E2E_PG or DBSIM_E2E_MYSQL
var commonVars = []string{"DBSIM_E2E_AGENT_BIN", "DBSIM_E2E_ES_URL", "DBSIM_E2E_ES_USER", "DBSIM_E2E_ES_PASSWORD", "DBSIM_E2E_AGENT_IP"}
var engineVars = []string{"HOST", "PORT", "DB", "IDENTITY", "DBHOSTNAME", "DBIP", "CRED_LAB", "CRED_RO"}

type e2eConfig struct {
	agentBin, esURL, esUser, esPass, agentIP string
	window, wait                             time.Duration
	engine, prefix                           string
	host, db, identity, dbHostName, dbIP     string
	port                                     int
	credLab, credRO                          string
}

func envSet(names ...string) (set, missing []string) {
	for _, n := range names {
		if os.Getenv(n) != "" {
			set = append(set, n)
		} else {
			missing = append(missing, n)
		}
	}
	return
}

// loadE2E returns the configuration for one engine, or skips when the engine's
// variables are entirely unset. A PARTIAL configuration fails the test: a
// half-configured run must never look like a skipped (or passed) one.
func loadE2E(t *testing.T, engine, prefix string) e2eConfig {
	t.Helper()
	var ev []string
	for _, v := range engineVars {
		ev = append(ev, prefix+"_"+v)
	}
	engSet, engMissing := envSet(ev...)
	comSet, comMissing := envSet(commonVars...)
	if len(engSet) == 0 && len(comSet) == 0 {
		t.Skipf("dbsim E2E not configured (no DBSIM_E2E_* variables set); see lab/dbsim/E2E.md")
	}
	if len(engSet) == 0 {
		t.Skipf("dbsim E2E for %s not configured (no %s_* variables set)", engine, prefix)
	}
	if len(engMissing) > 0 || len(comMissing) > 0 {
		t.Fatalf("partial dbsim E2E configuration for %s: missing %v %v", engine, comMissing, engMissing)
	}
	cfg := e2eConfig{
		agentBin: os.Getenv("DBSIM_E2E_AGENT_BIN"), esURL: os.Getenv("DBSIM_E2E_ES_URL"),
		esUser: os.Getenv("DBSIM_E2E_ES_USER"), esPass: os.Getenv("DBSIM_E2E_ES_PASSWORD"),
		agentIP: os.Getenv("DBSIM_E2E_AGENT_IP"), engine: engine, prefix: prefix,
		host: os.Getenv(prefix + "_HOST"), db: os.Getenv(prefix + "_DB"), identity: os.Getenv(prefix + "_IDENTITY"),
		dbHostName: os.Getenv(prefix + "_DBHOSTNAME"), dbIP: os.Getenv(prefix + "_DBIP"),
		credLab: os.Getenv(prefix + "_CRED_LAB"), credRO: os.Getenv(prefix + "_CRED_RO"),
		window: 3 * time.Minute, wait: 150 * time.Second,
	}
	p, err := strconv.Atoi(os.Getenv(prefix + "_PORT"))
	if err != nil || p <= 0 {
		t.Fatalf("%s_PORT is not a port number", prefix)
	}
	cfg.port = p
	if v := os.Getenv("DBSIM_E2E_WINDOW"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			t.Fatalf("DBSIM_E2E_WINDOW: %q", v)
		}
		cfg.window = d
	}
	if v := os.Getenv("DBSIM_E2E_ALERT_WAIT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			t.Fatalf("DBSIM_E2E_ALERT_WAIT: %q", v)
		}
		cfg.wait = d
	}
	if st, err := os.Stat(cfg.agentBin); err != nil || st.IsDir() {
		t.Fatalf("DBSIM_E2E_AGENT_BIN %q is not a file", cfg.agentBin)
	}
	return cfg
}

// stageScenarios copies the shipped YAML and .sig files into a temp builtin
// directory and loads them through scenario.Engine, which verifies each
// signature. A tampered or unsigned file does not load.
func stageScenarios(t *testing.T, ids ...string) *scenario.Engine {
	t.Helper()
	if !(integrity.CompiledVerifier{}).SigningEnabled() {
		t.Fatal("scenario signature verification is disabled in this build (no vendor public key): the E2E must start from SIGNED scenarios")
	}
	dir := t.TempDir()
	for _, id := range ids {
		for _, ext := range []string{".yaml", ".yaml.sig"} {
			b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scenarios", id+ext))
			if err != nil {
				t.Fatalf("read %s%s: %v", id, ext, err)
			}
			if err := os.WriteFile(filepath.Join(dir, id+ext), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	eng := scenario.NewEngine(dir)
	if err := eng.Load(); err != nil {
		t.Fatalf("load scenarios: %v", err)
	}
	return eng
}

type signer struct {
	key     *rsa.PrivateKey
	certPEM []byte
}

func newSigner(t *testing.T) signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "dbsim-e2e-throwaway"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return signer{key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func randHex(t *testing.T, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// signedEnvelope wraps the steps in a command_scenario CommandEnvelope signed
// like the orchestrator hub does (internal/cmdsigning).
func (s signer) signedEnvelope(t *testing.T, sc *scenario.Scenario, runID string, steps []scenario.ScenarioStep) []byte {
	t.Helper()
	payload, err := json.Marshal(scenario.ScenarioCommand{RunID: runID, ScenarioID: sc.ID, Name: sc.Name, Steps: steps, Mode: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	env := models.CommandEnvelope{
		Version: models.CommandEnvelopeVersion, CommandID: randHex(t, 16), CommandType: "command_scenario",
		AgentID: e2eAgentID, RunID: runID, ScenarioID: sc.ID, Mode: "lab",
		IssuedAt: now, ExpiresAt: now.Add(60 * time.Second), Nonce: randHex(t, 16), Payload: payload,
	}
	sig, err := cmdsigning.SignEnvelope(s.key, env)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = sig
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// runAgent executes the envelope in the agent test binary and returns the
// ExecResults it wrote. The alerts-reader credentials are NOT passed to it.
func runAgent(t *testing.T, bin string, s signer, envelope []byte, extraEnv ...string) ([]AgentExec, string) {
	t.Helper()
	dir := t.TempDir()
	envPath, certPath, outPath := filepath.Join(dir, "envelope.json"), filepath.Join(dir, "signer.pem"), filepath.Join(dir, "results.json")
	if err := os.WriteFile(envPath, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, s.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-test.run", "^TestDBSimE2EStepRunner$", "-test.count=1", "-test.v")
	var childEnv []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DBSIM_E2E_ES_") {
			continue
		}
		childEnv = append(childEnv, kv)
	}
	childEnv = append(childEnv, "DBSIM_E2E_ENVELOPE="+envPath, "DBSIM_E2E_SIGNER_CERT="+certPath,
		"DBSIM_E2E_AGENT_ID="+e2eAgentID, "DBSIM_E2E_RESULT_OUT="+outPath)
	cmd.Env = append(childEnv, extraEnv...)
	out, err := cmd.CombinedOutput()
	logTail := dbsim.Redact(tail(string(out), 3000))
	if err != nil {
		t.Fatalf("agent subprocess failed: %v\n%s", err, logTail)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("agent wrote no results (a skipped runner?): %v\n%s", err, logTail)
	}
	var res []AgentExec
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("decode agent results: %v", err)
	}
	return res, logTail
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

func specOf(t *testing.T, st scenario.ScenarioStep) dbsim.DBProbeSpec {
	t.Helper()
	var sp dbsim.DBProbeSpec
	if err := json.Unmarshal(st.DBProbe, &sp); err != nil {
		t.Fatal(err)
	}
	return sp
}

// TestE2EPlumbing_SignedEnvelopeReachesAgentExecutor needs only the agent test
// binary and no database or SIEM: a signed scenario is compiled, wrapped in a
// signed envelope and handed to the real agent verifier and executor against a
// target whose credential reference cannot be resolved. The agent must verify
// the envelope and refuse to run (credential_unresolved), and a tampered
// envelope must be rejected by the verifier. It proves the harness plumbing,
// not any database behaviour.
func TestE2EPlumbing_SignedEnvelopeReachesAgentExecutor(t *testing.T) {
	bin := os.Getenv("DBSIM_E2E_AGENT_BIN")
	if bin == "" {
		t.Skip("DBSIM_E2E_AGENT_BIN not set")
	}
	eng := stageScenarios(t, "dbsim-db01-auth-policy")
	sc, ok := eng.Get("dbsim-db01-auth-policy")
	if !ok {
		t.Fatal("scenario not loaded")
	}
	tgt := dbsim.Target{ID: "lab-db", Engine: "postgresql", Host: "127.0.0.1", Port: 1, Database: "dbsim", TLSMode: "disable",
		CredentialRef: "dbcred:e2e-plumbing-never-provisioned", Mode: dbsim.ModeLab, ExpectedIdentity: "1", LabConfirmed: true}
	steps, err := dbbuild.BuildSteps(context.Background(), sc, dbbuild.Options{
		Resolver: dbsim.NewMemoryResolver(tgt), RunExpiry: time.Now().Add(10 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	s := newSigner(t)
	runID := specOf(t, steps[0]).RunID
	res, _ := runAgent(t, bin, s, s.signedEnvelope(t, sc, runID, steps))
	if len(res) != len(steps) {
		t.Fatalf("%d results for %d steps", len(res), len(steps))
	}
	for i, r := range res {
		if r.DBProbe == nil || r.DBProbe.ErrorClass != "credential_unresolved" {
			t.Fatalf("step %d: want credential_unresolved from the real executor, got %+v", i, r)
		}
		ev, err := Evaluate(context.Background(), nil, StepInput{
			Scenario: labMeta(sc.ID, specOf(t, steps[i])), Spec: specOf(t, steps[i]), Exec: r, Principal: "none",
			Window: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		if ev.Result != dbsim.ResultSkipped || ev.Record.Validate() != nil {
			t.Fatalf("step %d: result %s validate %v", i, ev.Result, ev.Record.Validate())
		}
	}

	// A tampered envelope must be rejected by the agent verifier, so the runner
	// fails before executing anything.
	env := s.signedEnvelope(t, sc, runID, steps)
	tampered := []byte(strings.Replace(string(env), `"mode":"lab"`, `"mode":"lav"`, 1))
	if string(tampered) == string(env) {
		t.Fatal("tamper did not change the envelope")
	}
	if !agentRejects(t, bin, s, tampered) {
		t.Fatal("the agent accepted a tampered envelope")
	}
}

// agentRejects runs the runner and reports whether it failed at the verifier.
func agentRejects(t *testing.T, bin string, s signer, envelope []byte) bool {
	dir := t.TempDir()
	envPath, certPath, outPath := filepath.Join(dir, "e.json"), filepath.Join(dir, "c.pem"), filepath.Join(dir, "r.json")
	_ = os.WriteFile(envPath, envelope, 0o600)
	_ = os.WriteFile(certPath, s.certPEM, 0o600)
	cmd := exec.Command(bin, "-test.run", "^TestDBSimE2EStepRunner$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "DBSIM_E2E_ENVELOPE="+envPath, "DBSIM_E2E_SIGNER_CERT="+certPath,
		"DBSIM_E2E_AGENT_ID="+e2eAgentID, "DBSIM_E2E_RESULT_OUT="+outPath)
	out, err := cmd.CombinedOutput()
	if _, statErr := os.Stat(outPath); statErr == nil {
		return false // results were produced: the step ran
	}
	return err != nil && strings.Contains(string(out), "envelope rejected by the agent verifier")
}

func TestE2E_PostgreSQL_SignedScenarioToCorrelatedRecord(t *testing.T) {
	runE2E(t, loadE2E(t, "postgresql", "DBSIM_E2E_PG"))
}

func TestE2E_MySQL_SignedScenarioToCorrelatedRecord(t *testing.T) {
	runE2E(t, loadE2E(t, "mysql", "DBSIM_E2E_MYSQL"))
}

var e2eScenarios = []string{
	"dbsim-db01-auth-policy", "dbsim-db02-excessive-grants", "dbsim-db03-unauthorized-access",
	"dbsim-db04-audit-coverage", "dbsim-db05-suspicious-read", "dbsim-db09-bounded-bulk-read",
}

func runE2E(t *testing.T, cfg e2eConfig) {
	eng := stageScenarios(t, e2eScenarios...)
	conn, err := detectverify.NewConnector(detectverify.Config{Provider: "elastic", BaseURL: cfg.esURL, ClientID: cfg.esUser, ClientSecret: cfg.esPass})
	if err != nil {
		t.Fatalf("elastic connector: %v", err)
	}
	if err := conn.TestConnection(context.Background()); err != nil {
		t.Fatalf("the alerts reader cannot reach Elasticsearch (config error, not a product result): %v", dbsim.Redact(err.Error()))
	}
	s := newSigner(t)
	seenMarkers, seenRuns := map[string]bool{}, map[string]bool{}
	summary := map[string]string{}

	for _, id := range e2eScenarios {
		id := id
		t.Run(id, func(t *testing.T) {
			sc, ok := eng.Get(id)
			if !ok {
				t.Fatalf("%s did not load", id)
			}
			cred, principal := cfg.credLab, "dbsim_lab"
			if id == "dbsim-db03-unauthorized-access" {
				cred, principal = cfg.credRO, "dbsim_test" // DB-03 expects the read to be DENIED
			}
			tgt := dbsim.Target{ID: "lab-db", Engine: cfg.engine, Host: cfg.host, Port: cfg.port, Database: cfg.db, TLSMode: "disable",
				CredentialRef: "dbcred:" + cred, Mode: dbsim.ModeLab, ExpectedIdentity: cfg.identity, LabConfirmed: true}
			fixture := id == "dbsim-db05-suspicious-read" || id == "dbsim-db09-bounded-bulk-read"
			steps, err := dbbuild.BuildSteps(context.Background(), sc, dbbuild.Options{
				Resolver: dbsim.NewMemoryResolver(tgt), MutationApproved: fixture, RunExpiry: time.Now().Add(20 * time.Minute)})
			if err != nil {
				t.Fatalf("BuildSteps: %v", err)
			}
			runID := specOf(t, steps[0]).RunID
			if seenRuns[runID] {
				t.Fatalf("run id %s reused", runID)
			}
			seenRuns[runID] = true
			// fixture steps are mutations of the lab database: the agent-local
			// allowance is set for THIS subprocess only.
			var extra []string
			if fixture {
				extra = append(extra, "BAS_DBPROBE_LAB_MUTATION_ALLOWED=true")
			}
			results, logTail := runAgent(t, cfg.agentBin, s, s.signedEnvelope(t, sc, runID, steps), extra...)
			if len(results) != len(steps) {
				t.Fatalf("%d results for %d steps\n%s", len(results), len(steps), logTail)
			}
			for i, st := range steps {
				spec := specOf(t, st)
				if seenMarkers[spec.Marker] {
					t.Fatalf("marker %s reused", spec.Marker)
				}
				seenMarkers[spec.Marker] = true
				in := StepInput{
					Scenario: labMeta(id, spec), Spec: spec, Exec: results[i], Principal: principal,
					DBHost: cfg.dbHostName, DBIP: cfg.dbIP, AgentIP: cfg.agentIP,
					Window: cfg.window, SkewAllowance: 5 * time.Second,
				}
				// The alert arrives some seconds after the statement (rule interval,
				// Filebeat, refresh): re-ask the SIEM until Present or the wait is over.
				// Only the SIEM query repeats; the probe is never re-run.
				var ev Evaluation
				deadline := time.Now().Add(cfg.wait)
				for {
					ev, err = Evaluate(context.Background(), conn, in)
					if err != nil {
						t.Fatalf("Evaluate: %v", err)
					}
					if !in.Scenario.ExpectDetection || ev.Record.Telemetry == dlpreport.TelemetryPresent || time.Now().After(deadline) {
						break
					}
					time.Sleep(10 * time.Second)
				}
				checkStep(t, cfg, id, spec, ev, results[i])
				js, _ := json.Marshal(ev.Record)
				t.Logf("step %d %s: result=%s record=%s", i+1, spec.ProbeID, ev.Result, js)
				summary[cfg.engine+"/"+id+"/"+spec.ProbeID] = string(ev.Result)
			}
		})
	}
	keys := make([]string, 0, len(summary))
	for k := range summary {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("SUMMARY %s = %s", k, summary[k])
	}
}

// checkStep asserts the expected end state for one step.
//
// Mapping of the plan's wording to the real dlpreport enums: "Telemetry=Present"
// is dlpreport.TelemetryPresent; "Response=Alerted" is dlpreport.ResponseAlerted
// (set only for a marker-correlated SIEM alert; no case or remediation is
// assessed); "non-zero latency" is Outcome.Corr.Latency > 0 (alert timestamp
// minus the database-reported probe time).
func checkStep(t *testing.T, cfg e2eConfig, id string, spec dbsim.DBProbeSpec, ev Evaluation, ex AgentExec) {
	t.Helper()
	fail := func(format string, a ...any) {
		t.Errorf("%s/%s %s: "+format+"\n  reason: %s\n  limitations: %s", append([]any{cfg.engine, id, spec.ProbeID}, append(a, ev.Report.Reason, ev.Record.Limitations)...)...)
	}
	if err := ev.Record.Validate(); err != nil {
		fail("Record.Validate: %v", err)
	}
	if ex.DBProbe != nil && ex.DBProbe.CleanupStatus != "" && ex.DBProbe.CleanupStatus != dbsim.CleanupNotApplicable {
		if ex.DBProbe.CleanupStatus != dbsim.CleanupOK || ex.DBProbe.SafetyIncident {
			t.Errorf("%s: fixture cleanup NOT verified (status %q, incident %v): clean the lab by hand before re-running", spec.ProbeID, ex.DBProbe.CleanupStatus, ex.DBProbe.SafetyIncident)
		}
	}
	if ev.Result != dbsim.ResultPass {
		fail("result %s, want PASS", ev.Result)
	}
	if !ev.Outcome.Corr.Evaluated {
		if ev.Outcome.Corr.Telemetry == "" && labExpectationFor(id, spec.ProbeID).detection {
			fail("no SIEM correlation was attempted")
		}
		return
	}
	if ev.Record.Telemetry != dlpreport.TelemetryPresent {
		fail("Telemetry %s, want Present (match %s). If this is MySQL and the marker comment does not appear in the audit source this is the documented 'Unverifiable: audit path strips the marker comment' outcome; record it per lab/dbsim/E2E.md", ev.Record.Telemetry, ev.Outcome.Corr.Match)
	}
	if ev.Record.Response != dlpreport.ResponseAlerted {
		fail("Response %s, want Alerted", ev.Record.Response)
	}
	if ev.Outcome.Corr.Latency <= 0 {
		fail("latency %s, want > 0", ev.Outcome.Corr.Latency)
	}
	if ev.Outcome.Corr.Match != dbsim.MatchExactMarker {
		fail("match grade %s, want exact_marker", ev.Outcome.Corr.Match)
	}
}
