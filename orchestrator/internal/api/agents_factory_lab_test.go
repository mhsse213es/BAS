package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/validationlab"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The agents list reports which agent Audspect designated as the Threat Factory lab, on both the unpaginated and the
// paginated path. The flag comes from the same designation the server uses to gate dispatch, so the console cannot
// show a lab agent the server does not treat as one.
func TestGetAgents_ReportsTheFactoryLabAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), nil, "")
		seedActiveAgent(t, pool, "agent-lab", "Linux")
		seedActiveAgent(t, pool, "agent-plain", "Windows")
		// The server designates the lab from the configured agent ID, exactly as it does at startup.
		if err := validationlab.EnsureSoleFactoryLabAgent(context.Background(), pool, "agent-lab"); err != nil {
			t.Fatal(err)
		}

		check := func(name, url string, decode func([]byte) ([]models.Agent, error)) {
			rec := httptest.NewRecorder()
			h.GetAgents(rec, httptest.NewRequest(http.MethodGet, url, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status = %d, body = %s", name, rec.Code, rec.Body.String())
			}
			agents, err := decode(rec.Body.Bytes())
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			got := map[string]bool{}
			for _, a := range agents {
				got[a.AgentID] = a.FactoryLab
			}
			if len(got) != 2 || !got["agent-lab"] || got["agent-plain"] {
				t.Fatalf("%s: factoryLab by agent = %v, want only agent-lab", name, got)
			}
		}
		check("unpaginated", "/api/agents", func(b []byte) ([]models.Agent, error) {
			var a []models.Agent
			return a, json.Unmarshal(b, &a)
		})
		check("paginated", "/api/agents?limit=10", func(b []byte) ([]models.Agent, error) {
			var env struct {
				Items []models.Agent `json:"items"`
			}
			if err := json.Unmarshal(b, &env); err != nil {
				return nil, err
			}
			return env.Items, nil
		})
	})
}
