package rulelib

import "testing"

func testEngine() *Engine {
	return loadFromBytes([]byte(`[
		{"id":"AUDRULE-000001","sigmaId":"s1","title":"Encoded PowerShell","techniqueIds":["T1059.001"],
		 "severity":"medium","status":"stable","logSource":{"category":"process_creation","product":"windows"},
		 "translations":[{"backend":"splunk","language":"SPL","query":"..."},{"backend":"elastic","language":"Lucene","query":"..."}]},
		{"id":"AUDRULE-000002","sigmaId":"s2","title":"Kerberoasting SPN Enum","techniqueIds":["T1558.003"],
		 "severity":"high","status":"test","logSource":{"category":"process_creation","product":"windows"},
		 "translations":[{"backend":"splunk","language":"SPL","query":"..."}]}
	]`), []byte(`{"schemaVersion":1}`))
}

func TestRuleByID_FoundAndNotFound(t *testing.T) {
	e := testEngine()
	r, ok := e.RuleByID("AUDRULE-000001")
	if !ok || r.Title != "Encoded PowerShell" {
		t.Fatalf("RuleByID(AUDRULE-000001) = %+v, %v", r, ok)
	}
	if _, ok := e.RuleByID("AUDRULE-999999"); ok {
		t.Fatal("expected ok=false for an unknown rule id")
	}
}

func TestRulesByTechnique(t *testing.T) {
	e := testEngine()
	rules := e.RulesByTechnique("T1558.003")
	if len(rules) != 1 || rules[0].ID != "AUDRULE-000002" {
		t.Fatalf("RulesByTechnique(T1558.003) = %+v", rules)
	}
	if len(e.RulesByTechnique("T9999.999")) != 0 {
		t.Fatal("expected no rules for an unknown technique")
	}
}
