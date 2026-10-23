package main

import (
	"context"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestChildEnvironmentStripsDBSecretsAndPolicy(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"BAS_DBCRED_LAB_PG_RO={\"user\":\"u\",\"password\":\"p\"}",
		"BAS_DBCRED_X_ENC=abcd",
		"bas_dbcred_lower=secret",
		"Bas_DbProbe_Client_Enabled=1",
		"BAS_DBPROBE_LAB_MUTATION_ALLOWED=1",
		"BAS_DBCRED_",            // prefix only, no '='
		"BAS_DBCRED_NOEQUALS",    // malformed entry without '='
		"BAS_DBPROBEX=keepme?",   // starts with BAS_DBPROBE -> prefix is BAS_DBPROBE_, X is not '_' so keep
		"BAS_DBCREDENTIALS=keep", // BAS_DBCRED + 'E', not the BAS_DBCRED_ prefix
		"BAS_PAYLOAD_DIR=/tmp/x",
		"=C:=C:\\work", // Windows drive-cwd pseudo variable
		"NOEQUALS",
		"",
		"HOME=/root",
	}
	want := []string{
		"PATH=/usr/bin",
		"BAS_DBPROBEX=keepme?",
		"BAS_DBCREDENTIALS=keep",
		"BAS_PAYLOAD_DIR=/tmp/x",
		"=C:=C:\\work",
		"NOEQUALS",
		"",
		"HOME=/root",
	}
	got := childEnvironment(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("childEnvironment:\n got %q\nwant %q", got, want)
	}
	// Input must not be modified.
	if in[1] == "" || !strings.HasPrefix(in[1], "BAS_DBCRED_LAB") {
		t.Fatal("input slice was mutated")
	}
	if got := childEnvironment(nil); len(got) != 0 {
		t.Fatalf("nil in -> %q", got)
	}
}

// printEnvStep returns a step that prints the child's environment through the
// real shell path execStep uses on this host.
func printEnvStep() ScenarioStep {
	if runtime.GOOS == "windows" {
		return ScenarioStep{TaskID: "env", Executor: "cmd", Command: "set", TimeoutSec: 30}
	}
	return ScenarioStep{TaskID: "env", Executor: "sh", Command: "env", TimeoutSec: 30}
}

func TestChildEnvShellStepNeverSeesDBSecrets(t *testing.T) {
	t.Setenv("BAS_DBCRED_X", "TOPSECRET-cred-value")
	t.Setenv("BAS_DBPROBE_CLIENT_ENABLED", "1")
	t.Setenv("BAS_VISIBLE_MARKER", "visible-ok")
	r := execStep(context.Background(), printEnvStep(), nil)
	if !strings.Contains(r.Stdout, "visible-ok") {
		t.Fatalf("control: child did not print its environment (exit=%d stdout=%q stderr=%q)", r.ExitCode, r.Stdout, r.Stderr)
	}
	for _, bad := range []string{"TOPSECRET-cred-value", "BAS_DBCRED_X", "BAS_DBPROBE_CLIENT_ENABLED"} {
		if strings.Contains(r.Stdout, bad) || strings.Contains(r.Stderr, bad) {
			t.Fatalf("child environment leaked %q:\n%s", bad, r.Stdout)
		}
	}
}

func TestChildEnvShellStepWithStepEnvAndPayloadDirStillStripped(t *testing.T) {
	t.Setenv("BAS_DBCRED_X", "TOPSECRET-cred-value")
	s := printEnvStep()
	s.PayloadDir = t.TempDir()
	s.Env = map[string]string{"BAS_RUN_MODE": "x"}
	r := execStep(context.Background(), s, nil)
	if !strings.Contains(r.Stdout, "BAS_RUN_MODE") || !strings.Contains(r.Stdout, "BAS_PAYLOAD_DIR") {
		t.Fatalf("control failed: %q", r.Stdout)
	}
	if strings.Contains(r.Stdout, "TOPSECRET-cred-value") {
		t.Fatal("leak with step env/payload dir")
	}
}

func TestChildEnvCleanupScriptNeverSeesDBSecrets(t *testing.T) {
	t.Setenv("BAS_DBCRED_X", "TOPSECRET-cred-value")
	step := ScenarioStep{TaskID: "c", PayloadDir: t.TempDir()}
	if runtime.GOOS == "windows" {
		step.Cleanup = "[Console]::Error.Write($env:BAS_DBCRED_X + '|' + $env:BAS_PAYLOAD_DIR); exit 1"
	} else {
		step.Cleanup = "printf '%s|%s' \"$BAS_DBCRED_X\" \"$BAS_PAYLOAD_DIR\" >&2; exit 1"
	}
	_, detail := runCleanup(step)
	if strings.Contains(detail, "TOPSECRET-cred-value") {
		t.Fatalf("cleanup saw the secret: %q", detail)
	}
	if !strings.Contains(detail, step.PayloadDir) {
		t.Fatalf("control: cleanup did not report PayloadDir: %q", detail)
	}
}

func TestChildEnvStepEnvCannotReintroduceSecrets(t *testing.T) {
	// Defence in depth: even a step-supplied variable with a stripped prefix is dropped.
	s := printEnvStep()
	s.Env = map[string]string{"BAS_DBCRED_SMUGGLED": "smuggled-secret"}
	r := execStep(context.Background(), s, nil)
	if strings.Contains(r.Stdout, "smuggled-secret") {
		t.Fatal("step Env re-introduced a BAS_DBCRED_ variable")
	}
}
