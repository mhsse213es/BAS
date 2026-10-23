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
	cfg.Engagement.Classes[toySig["archiveItem"]] = "money" // admin: archive is a money operation
	cfg.Classes["archiveItem"] = model.ClassRead            // analyst tries to run it as read
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
	cfg.Engagement.Classes[toySig["createItem"]] = "money"
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
	cfg2.Engagement.Classes[toySig["deleteItem"]] = "money"
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

// The probe: the document under test gives POST /items/{id}/archive the operationId of an operation the
// engagement classified as read or reversible. The class follows the operation's OWN signature, which the
// engagement does not classify, so it is unknown and never runs. The target receives 0 requests for it.
func TestRenamedOperationIDDoesNotInheritAnotherOperationsClass(t *testing.T) {
	for _, stolen := range []string{"getItem", "deleteItem", "listItems"} {
		ty := newToy()
		cfg, _ := toyConfig(t, ty, newRec())
		// the original holder of the id is renamed out of the way; the archive route takes the id
		spec := strings.Replace(toySpec, `"operationId": "`+stolen+`"`, `"operationId": "`+stolen+`_orig"`, 1)
		spec = strings.Replace(spec, `"operationId": "archiveItem"`, `"operationId": "`+stolen+`"`, 1)
		cfg.OpenAPI = []byte(spec)
		cfg.Classes = map[string]model.OpClass{}
		for _, id := range []string{"createItem", "getItem", "deleteItem"} {
			// request keys by signature, so the renamed holders still get their classes
			cfg.Classes[toySig[id]] = map[string]model.OpClass{"createItem": model.ClassSetupSafe, "getItem": model.ClassRead, "deleteItem": model.ClassReversible}[id]
		}
		if stolen == "deleteItem" {
			// the setup still names the id "deleteItem" for compensation, which now belongs to the archive
			// route: refused by that route's own (unclassified) signature, with no request sent.
			if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "not reversible") {
				t.Fatalf("compensation through a stolen id: %v", err)
			}
			if _, err := Run(context.Background(), cfg); err == nil || ty.total() != 0 {
				t.Fatalf("Run accepted a stolen compensation id (%d requests): %v", ty.total(), err)
			}
			cfg.Setup[0].Compensate = "deleteItem_orig"
		}
		m, err := prepare(cfg)
		if err != nil {
			t.Fatalf("%s: %v", stolen, err)
		}
		for _, op := range m.Operations {
			if op.Method == "POST" && strings.HasSuffix(op.Path, "/archive") && op.Class != model.ClassUnknown {
				t.Fatalf("archive route given id %q inherited class %s", stolen, op.Class)
			}
		}
		rep, err := Run(context.Background(), cfg)
		if err != nil {
			t.Fatalf("%s: %v", stolen, err)
		}
		if got := ty.hitCount("POST /api/v2/items/{id}/archive"); got != 0 {
			t.Fatalf("%s: renamed archive route was called %d times", stolen, got)
		}
		if rep.PerOperation[stolen].Skipped != "not classified by the engagement" {
			t.Fatalf("%s: report %+v", stolen, rep.PerOperation[stolen])
		}
	}
}

// Request class keys: a signature and the document's id for the same operation must agree; a request
// cannot tighten under one key and loosen under the other. Param-name variations are one signature.
func TestRequestClassKeysResolveBySignature(t *testing.T) {
	ty := newToy()
	cfg, _ := toyConfig(t, ty, newRec())
	cfg.Engagement.Classes[toySig["archiveItem"]] = "money"
	cfg.Classes["archiveItem"] = model.ClassUnknown
	cfg.Classes["POST /api/v2/items/{anything}/archive"] = model.ClassRead
	if _, err := prepare(cfg); err == nil || !strings.Contains(err.Error(), "different classes") {
		t.Fatalf("mixed keys accepted: %v", err)
	}
	// the loosening is refused by the signature key alone as well
	delete(cfg.Classes, "archiveItem")
	if _, err := prepare(cfg); err == nil || !strings.Contains(err.Error(), "less restrictive") {
		t.Fatalf("signature key loosened: %v", err)
	}
	// agreeing keys for one operation are fine
	cfg.Classes["archiveItem"] = model.ClassMoney
	cfg.Classes["POST /api/v2/items/{anything}/archive"] = model.ClassMoney
	if _, err := prepare(cfg); err != nil {
		t.Fatalf("agreeing keys refused: %v", err)
	}
	// unknown keys are refused
	cfg.Classes["no such op"] = model.ClassRead
	if _, err := prepare(cfg); err == nil || !strings.Contains(err.Error(), "not in the model") {
		t.Fatalf("stray key: %v", err)
	}
}

// Two operations that normalise to the same signature are ambiguous: the run is refused before any request.
func TestDuplicateSignatureDocumentIsRefused(t *testing.T) {
	ty := newToy()
	cfg, _ := toyConfig(t, ty, newRec())
	spec := strings.Replace(toySpec, `"/api/v2/items/{id}/archive": {`, `"/api/v2/items/{other}": {
   "parameters": [{"name": "other", "in": "path", "required": true, "schema": {"type": "string"}}],
   "get": {"operationId": "getItemAgain", "responses": {"200": {"description": "ok"}}}
  },
  "/api/v2/items/{id}/archive": {`, 1)
	cfg.OpenAPI = []byte(spec)
	if _, err := Run(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "same signature") {
		t.Fatalf("duplicate signature accepted: %v", err)
	}
	if ty.total() != 0 {
		t.Fatalf("%d requests sent", ty.total())
	}
}

// The setup operation is resolved by its own signature: a setup op whose path the engagement did not
// classify never runs, whatever its id.
func TestSetupOperationResolvedBySignature(t *testing.T) {
	ty := newToy()
	cfg, _ := toyConfig(t, ty, newRec())
	delete(cfg.Engagement.Classes, toySig["createItem"])
	delete(cfg.Classes, "createItem")
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "not setup_safe") {
		t.Fatalf("setup over an unclassified path: %v", err)
	}
	if ty.total() != 0 {
		t.Fatalf("%d requests sent", ty.total())
	}
}
