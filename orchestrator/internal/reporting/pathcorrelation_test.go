package reporting

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/rulelib"
)

func TestEngine_WithRuleLibrary_ChainsAndStores(t *testing.T) {
	e := NewEngine(nil).WithRuleLibrary(rulelib.NewEngine())
	if e.rules == nil {
		t.Fatal("WithRuleLibrary should set e.rules")
	}
}

func TestEngine_LoadPathCorrelation_NilSafe(t *testing.T) {
	e := NewEngine(nil) // no WithRuleLibrary call — e.rules stays nil

	if got := e.loadPathCorrelation(context.Background(), nil, attackpath.Summary{}); got != nil {
		t.Fatalf("expected nil with g=nil, got %+v", got)
	}

	g := attackpath.New()
	g.AddEdge(attackpath.Edge{From: "A", To: "B", Kind: attackpath.EdgeSMB})
	if got := e.loadPathCorrelation(context.Background(), g, g.Analyze()); got != nil {
		t.Fatalf("expected nil with e.rules unset even though g is non-nil, got %+v", got)
	}
}
