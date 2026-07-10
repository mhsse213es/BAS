package exercise

import (
	"strings"
	"testing"
)

func TestNewResolver_PrecedenceAndSystemVars(t *testing.T) {
	defs := []VarDef{
		{Name: "Greeting", Type: VarTypeString, Default: "hello"},
		{Name: "Runtime", Type: VarTypeRuntime},
	}
	r := NewResolver(defs, map[string]string{"Greeting": "override"}, "exec-1", "alice")

	if got := r.Sub("${ExecutionID}"); got != "exec-1" {
		t.Fatalf("ExecutionID = %q, want exec-1", got)
	}
	if got := r.Sub("${CurrentUser}"); got != "alice" {
		t.Fatalf("CurrentUser = %q, want alice", got)
	}
	if got := r.Sub("${Timestamp}"); got == "${Timestamp}" || got == "" {
		t.Fatalf("Timestamp should be populated, got %q", got)
	}
	if got := r.Sub("${Greeting}"); got != "override" {
		t.Fatalf("operator value must win over default: got %q", got)
	}
	// Runtime var is not pre-populated → reference left literal.
	if got := r.Sub("${Runtime}"); got != "${Runtime}" {
		t.Fatalf("runtime var must be unset until Set: got %q", got)
	}
	// Set injects a runtime value visible to later Sub.
	r.Set("Runtime", "generated")
	if got := r.Sub("${Runtime}"); got != "generated" {
		t.Fatalf("after Set, Runtime = %q, want generated", got)
	}
}

func TestNewResolver_SecretFromEnv(t *testing.T) {
	t.Setenv("BAS_TEST_SECRET", "s3cr3t")
	defs := []VarDef{{Name: "ApiKey", Type: VarTypeSecret, SecretEnv: "BAS_TEST_SECRET"}}
	r := NewResolver(defs, nil, "exec-1", "alice")
	if got := r.Sub("${ApiKey}"); got != "s3cr3t" {
		t.Fatalf("secret = %q, want s3cr3t", got)
	}
}

func TestSub_UnknownRefLeftLiteral(t *testing.T) {
	r := NewResolver(nil, nil, "e", "u")
	if got := r.Sub("a ${Nope} b"); got != "a ${Nope} b" {
		t.Fatalf("unknown ref must be left literal, got %q", got)
	}
}

func TestResolveStepConfig_SubstitutesAndEscapes(t *testing.T) {
	r := NewResolver(nil, map[string]string{
		"Subj":   "Q3 Review",
		"Tricky": `he said "hi"` + "\n" + `path\to`,
	}, "e", "u")
	in := StepConfig{Email: &EmailConfig{
		Subject:  "${Subj}",
		BodyHTML: "value=${Tricky}",
	}}
	out, err := r.ResolveStepConfig(in)
	if err != nil {
		t.Fatalf("ResolveStepConfig: %v", err)
	}
	if out.Email == nil {
		t.Fatal("email config lost during resolution")
	}
	if out.Email.Subject != "Q3 Review" {
		t.Fatalf("Subject = %q, want Q3 Review", out.Email.Subject)
	}
	// Quote/backslash/newline value must survive intact (JSON-safe substitution).
	if out.Email.BodyHTML != `value=he said "hi"`+"\n"+`path\to` {
		t.Fatalf("Tricky value mangled: %q", out.Email.BodyHTML)
	}
}

func TestValidateVars(t *testing.T) {
	defs := []VarDef{
		{Name: "Req", Type: VarTypeString, Required: true},
		{Name: "Opt", Type: VarTypeString},
		{Name: "Sec", Type: VarTypeSecret, Required: true, SecretEnv: "X"},
		{Name: "Run", Type: VarTypeRuntime, Required: true},
		{Name: "Def", Type: VarTypeString, Required: true, Default: "d"},
	}
	// Missing Req only (Sec/Run skipped, Def satisfied by default).
	if err := ValidateVars(defs, nil); err == nil || !strings.Contains(err.Error(), "Req") {
		t.Fatalf("expected missing Req, got %v", err)
	}
	if err := ValidateVars(defs, map[string]string{"Req": "x"}); err != nil {
		t.Fatalf("all requirements met, got %v", err)
	}
}

func TestExtractVarRefs_UniqueAndEmpty(t *testing.T) {
	ps := &PlanStep{Config: StepConfig{Email: &EmailConfig{
		Subject:  "${A} ${B}",
		BodyHTML: "${A} again",
	}}}
	refs := ExtractVarRefs(ps)
	if len(refs) != 2 {
		t.Fatalf("expected 2 unique refs, got %v", refs)
	}
	seen := map[string]bool{}
	for _, r := range refs {
		seen[r] = true
	}
	if !seen["A"] || !seen["B"] {
		t.Fatalf("expected refs A and B, got %v", refs)
	}
	none := &PlanStep{Config: StepConfig{NotifyMsg: "no refs here"}}
	if refs := ExtractVarRefs(none); len(refs) != 0 {
		t.Fatalf("expected no refs, got %v", refs)
	}
}
