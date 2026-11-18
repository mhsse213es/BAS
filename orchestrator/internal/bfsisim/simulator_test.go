package bfsisim

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestSimulator_StartServesAllFourEndpoints(t *testing.T) {
	s := NewSimulator("127.0.0.1:0")
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()

	base := "http://" + s.Addr()
	for _, path := range []string{
		"/api/banking/apps",
		"/api/payments/gateways",
		"/api/atm/switches",
		"/api/data/cardholder-locations",
	} {
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", path, resp.StatusCode)
		}
		var services []Service
		if err := json.NewDecoder(resp.Body).Decode(&services); err != nil {
			t.Fatalf("GET %s: decode: %v", path, err)
		}
		resp.Body.Close()
		if len(services) == 0 {
			t.Errorf("GET %s: empty service list", path)
		}
		for _, svc := range services {
			if svc.ID == "" {
				t.Errorf("GET %s: service with empty id", path)
			}
		}
	}
}

func TestSimulator_RegisteredServicesNonEmpty(t *testing.T) {
	s := NewSimulator("127.0.0.1:0")
	ids := s.RegisteredServices()
	if len(ids) == 0 {
		t.Fatal("RegisteredServices returned no ids")
	}
}

func TestSimulator_RejectsNonGetMethod(t *testing.T) {
	s := NewSimulator("127.0.0.1:0")
	if err := s.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()

	resp, err := http.Post("http://"+s.Addr()+"/api/banking/apps", "application/json", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/banking/apps: status %d, want 405", resp.StatusCode)
	}
}
