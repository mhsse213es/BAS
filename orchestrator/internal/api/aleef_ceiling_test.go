package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/auth"
)

// C1: the engagement's classes (set by the admin) are the ceiling. An analyst cannot loosen a class in
// the run request, cannot use a loosened or unclassified operation as a setup or compensating
// operation, and in every refusal the target receives 0 requests.
func TestRunCannotLoosenEngagementClasses(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		srv := httptest.NewServer(toy)
		defer srv.Close()
		engID := e.createEngagement(srv.URL)

		refused := []struct {
			name   string
			mutate func(m map[string]any)
			want   string
		}{
			{"money op marked read", func(m map[string]any) {
				m["classes"] = map[string]string{"createItem": "setup_safe", "getItem": "read", "deleteItem": "reversible", "settleItem": "read"}
			}, "less restrictive"},
			{"money op marked reversible", func(m map[string]any) {
				m["classes"] = map[string]string{"createItem": "setup_safe", "getItem": "read", "deleteItem": "reversible", "settleItem": "reversible"}
			}, "less restrictive"},
			{"unclassified op given a class", func(m map[string]any) {
				m["classes"] = map[string]string{"createItem": "setup_safe", "getItem": "read", "deleteItem": "reversible", "listItems": "read"}
			}, "not classified by the engagement"},
			{"money op as setup", func(m map[string]any) {
				m["classes"] = map[string]string{"createItem": "setup_safe", "getItem": "read", "deleteItem": "reversible"}
				m["setup"] = []map[string]any{{"operation_id": "settleItem", "body": map[string]any{}, "compensate": "deleteItem"}}
			}, "not setup_safe"},
			{"money op as setup, loosened in the request", func(m map[string]any) {
				m["classes"] = map[string]string{"createItem": "setup_safe", "getItem": "read", "deleteItem": "reversible", "settleItem": "setup_safe"}
				m["setup"] = []map[string]any{{"operation_id": "settleItem", "body": map[string]any{}, "compensate": "deleteItem"}}
			}, "less restrictive"},
			{"money op as compensation", func(m map[string]any) {
				m["setup"] = []map[string]any{{"operation_id": "createItem", "body": map[string]any{}, "compensate": "settleItem"}}
			}, "not reversible"},
			{"unclassified op as compensation", func(m map[string]any) {
				m["setup"] = []map[string]any{{"operation_id": "createItem", "body": map[string]any{}, "compensate": "listItems"}}
			}, "not reversible"},
		}
		for _, c := range refused {
			body := aleefRunBody(engID, srv.URL)
			c.mutate(body)
			rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), c.want) {
				t.Fatalf("%s: %d %s, want 400 containing %q", c.name, rec.Code, rec.Body.String(), c.want)
			}
		}
		time.Sleep(200 * time.Millisecond)
		if n := toy.requests.Load(); n != 0 {
			t.Fatalf("%d requests reached the target for refused runs, want 0", n)
		}
	})
}

// A request may keep or tighten a class. The unclassified and money operations never run, and the
// report says why.
func TestRunMayTightenClassesAndUnclassifiedNeverRuns(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		toy.readFlaw = true
		srv := httptest.NewServer(toy)
		defer srv.Close()
		engID := e.createEngagement(srv.URL)

		body := aleefRunBody(engID, srv.URL)
		body["classes"] = map[string]string{"createItem": "setup_safe", "getItem": "read", "deleteItem": "reversible", "settleItem": "unknown"}
		rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, body)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("tightening refused: %d %s", rec.Code, rec.Body.String())
		}
		runID := decodeMap(t, rec)["run_id"].(string)
		final := e.waitRun(runID, 3*time.Minute)
		if final["status"] != "completed" {
			t.Fatalf("status %v", final["status"])
		}
		if n := toy.settleHits.Load(); n != 0 {
			t.Fatalf("settleItem was called %d times", n)
		}
		per := final["report"].(map[string]any)["PerOperation"].(map[string]any)
		if got := per["listItems"].(map[string]any)["Skipped"]; got != "not classified by the engagement" {
			t.Fatalf("listItems skipped reason %v", got)
		}
	})
}

// I3: only token references the admin declared for the engagement are usable, and the refusal is
// identical for "not allowed", "declared but unresolvable" and "does not exist" (no existence oracle).
func TestTokenRefsAreEngagementScopedAndNoOracle(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		toy := newAleefToy()
		srv := httptest.NewServer(toy)
		defer srv.Close()
		engID := e.createEngagement(srv.URL)
		try := func(ref string) (int, string) {
			body := aleefRunBody(engID, srv.URL)
			body["accounts"] = []map[string]string{{"name": "a", "customer_id": "c", "token_ref": ref, "role": "member"}}
			rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, body)
			return rec.Code, rec.Body.String()
		}
		c1, b1 := try("tok-carol") // exists nowhere
		c2, b2 := try("tok-ghost") // declared, but resolves to nothing
		c3, b3 := try("tok-dave")  // a (hypothetical) other account's reference, not declared
		c4, b4 := try("a b")       // not even a valid reference name
		if c1 != 400 || c1 != c2 || c2 != c3 || c3 != c4 || b1 != b2 || b2 != b3 || b3 != b4 {
			t.Fatalf("responses differ: %d %s | %d %s | %d %s | %d %s", c1, b1, c2, b2, c3, b3, c4, b4)
		}
		if !strings.Contains(b1, "token reference not permitted for this engagement") || strings.Contains(b1, "tok-") {
			t.Fatalf("message: %s", b1)
		}
		// a declared, resolvable reference works
		rec := e.do(http.MethodPost, "/api/aleef/runs", auth.RoleAnalyst, aleefRunBody(engID, srv.URL))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("allowed refs refused: %d %s", rec.Code, rec.Body.String())
		}
		e.do(http.MethodPost, "/api/aleef/runs/"+decodeMap(t, rec)["run_id"].(string)+"/stop", auth.RoleAnalyst, nil)
	})
}

// Two declared references that read the same environment variable are refused at engagement creation.
func TestEngagementRejectsCollidingTokenRefs(t *testing.T) {
	withAleefEnv(t, func(e *aleefEnv) {
		now := time.Now()
		body := aleefEngagementBody("http://127.0.0.1:9", "lab", now.Add(-time.Hour), now.Add(time.Hour))
		body["token_refs"] = []string{"a/b", "a.b"}
		rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin, body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "same server secret") {
			t.Fatalf("collision: %d %s", rec.Code, rec.Body.String())
		}
		for _, bad := range []any{[]string{}, []string{"has space"}, []string{"a", "a"}, nil} {
			body["token_refs"] = bad
			if rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin, body); rec.Code != http.StatusBadRequest {
				t.Fatalf("token_refs %v: %d", bad, rec.Code)
			}
		}
		body["token_refs"] = []string{"a"}
		body["classes"] = map[string]string{"x": "not-a-class"}
		if rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAdmin, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad class name: %d", rec.Code)
		}
		// only the admin sets classes and token refs
		body["classes"] = map[string]string{"x": "read"}
		if rec := e.do(http.MethodPost, "/api/aleef/engagements", auth.RoleAnalyst, body); rec.Code != http.StatusForbidden {
			t.Fatalf("analyst create: %d", rec.Code)
		}
	})
}
