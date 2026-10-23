package campaign

import (
	"context"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/aleef/model"
)

// The engagement's classes are a ceiling: a request may keep or tighten a class, never loosen it,
// and an operation the engagement does not classify never runs.
func TestRequestCannotLoosenEngagementClasses(t *testing.T) {
	ty := newToy()
	cfg, _ := toyConfig(t, ty, newRec())
	cfg.Engagement.Classes["archiveItem"] = "money" // admin: archive is a money operation
	cfg.Classes["archiveItem"] = model.ClassRead    // analyst tries to run it as read
	if _, err := prepare(cfg); err == nil || !strings.Contains(err.Error(), "less restrictive") {
		t.Fatalf("loosening accepted: %v", err)
	}
	if _, err := Run(context.Background(), cfg); err == nil {
		t.Fatal("Run accepted a loosened class")
	}
	if n := ty.total(); n != 0 {
		t.Fatalf("%d requests reached the target", n)
	}
	// equal and more restrictive are accepted
	for _, c := range []model.OpClass{model.ClassMoney, model.ClassUnknown} {
		cfg.Classes["archiveItem"] = c
		m, err := prepare(cfg)
		if err != nil {
			t.Fatalf("%s refused: %v", c, err)
		}
		for _, op := range m.Operations {
			if op.ID == "archiveItem" && op.Class != c {
				t.Fatalf("effective class %s, want %s", op.Class, c)
			}
		}
	}
	// omitted in the request: the engagement's class applies
	delete(cfg.Classes, "archiveItem")
	m, err := prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range m.Operations {
		if op.ID == "archiveItem" && op.Class != model.ClassMoney {
			t.Fatalf("effective class %s, want money", op.Class)
		}
	}
}

func TestUnclassifiedOperationNeverRunsAndIsReported(t *testing.T) {
	ty := newToy()
	cfg, _ := toyConfig(t, ty, newRec())
	// archiveItem is in the model but the engagement does not classify it.
	cfg.Classes["archiveItem"] = model.ClassRead
	if _, err := prepare(cfg); err == nil || !strings.Contains(err.Error(), "not classified by the engagement") {
		t.Fatalf("request class for an unclassified operation accepted: %v", err)
	}
	delete(cfg.Classes, "archiveItem")
	rep, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := ty.hitCount("POST /api/v2/items/{id}/archive"); got != 0 {
		t.Fatalf("unclassified operation was called %d times", got)
	}
	if rep.PerOperation["archiveItem"].Skipped != "not classified by the engagement" {
		t.Fatalf("report: %+v", rep.PerOperation["archiveItem"])
	}
}

func TestSetupAndCompensateAreCheckedAgainstTheEngagementClass(t *testing.T) {
	ty := newToy()
	cfg, _ := toyConfig(t, ty, newRec())
	// setup op the engagement classes as money
	cfg.Engagement.Classes["createItem"] = "money"
	delete(cfg.Classes, "createItem")
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "not setup_safe") {
		t.Fatalf("setup over a money operation: %v", err)
	}
	// trying to loosen it in the request is refused too
	cfg.Classes["createItem"] = model.ClassSetupSafe
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "less restrictive") {
		t.Fatalf("setup loosening: %v", err)
	}
	// compensating operation the engagement does not class reversible
	cfg2, _ := toyConfig(t, ty, newRec())
	cfg2.Engagement.Classes["deleteItem"] = "money"
	delete(cfg2.Classes, "deleteItem")
	if err := Validate(cfg2); err == nil || !strings.Contains(err.Error(), "not reversible") {
		t.Fatalf("compensate over a money operation: %v", err)
	}
	if _, err := Run(context.Background(), cfg2); err == nil {
		t.Fatal("Run accepted it")
	}
	if ty.total() != 0 {
		t.Fatalf("%d requests sent", ty.total())
	}
}
