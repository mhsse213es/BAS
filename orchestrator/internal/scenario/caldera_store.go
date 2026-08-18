package scenario

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/models"
)

// CalderaStore holds Caldera abilities indexed by ATT&CK technique ID,
// pre-loaded once at server startup. Mirrors ARTStore's shape so
// resolveBaseCommand (internal/api/variant_handlers.go) can treat an ART
// atomic and a Caldera ability as interchangeable variant base-command
// sources.
type CalderaStore struct {
	mu    sync.RWMutex
	steps map[string][]ScenarioStep
}

// NewCalderaStoreFromSteps builds a CalderaStore directly from a pre-built
// technique-indexed step map, bypassing the live Caldera fetch NewCalderaStore
// requires. Used by tests that need a populated store without a running
// Caldera instance.
func NewCalderaStoreFromSteps(steps map[string][]ScenarioStep) *CalderaStore {
	return &CalderaStore{steps: steps}
}

// NewCalderaStore fetches every ability from a live Caldera instance and
// indexes it by technique ID. calderaURL == "" (Caldera not configured) or a
// failed fetch returns an empty, ready-to-use store rather than an error --
// mirrors how the rest of the Caldera integration treats "not configured" as
// a soft off-state (see builder.go's calderaURL == "" checks).
func NewCalderaStore(calderaURL, apiKey string) *CalderaStore {
	s := &CalderaStore{steps: make(map[string][]ScenarioStep)}
	if calderaURL == "" {
		return s
	}
	abilities, err := fetchAllCalderaAbilities(calderaURL, apiKey)
	if err != nil {
		log.Printf("[caldera] store: failed to load abilities: %v", err)
		return s
	}
	for _, ab := range abilities {
		cmd := pickExecutorCommand(ab.Executors, "psh")
		if cmd == "" || ab.TechniqueID == "" {
			continue // no Windows-compatible executor, or no technique mapping to index by
		}
		techniqueID := strings.ToUpper(ab.TechniqueID)
		s.steps[techniqueID] = append(s.steps[techniqueID], ScenarioStep{
			TaskID:       TaskID(techniqueID, ab.Name),
			TechniqueID:  techniqueID,
			Name:         ab.Name,
			Framework:    "caldera",
			Executor:     "powershell",
			Command:      cmd,
			TimeoutSec:   60,
			Fidelity:     calderaStepFidelity(ab),
			RequiresPriv: mapCalderaElevation(ab.Privilege).Effective(),
		})
	}
	return s
}

// GetAbilities returns every Caldera ability mapped to techniqueID, or nil
// if none exist (unmapped technique, or the store is empty because Caldera
// was unconfigured/unreachable at load time). Safe to call on a nil
// *CalderaStore (returns nil), so callers don't need a separate nil-check
// before every lookup.
func (s *CalderaStore) GetAbilities(techniqueID string) []ScenarioStep {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.steps[strings.ToUpper(techniqueID)]
}

// ListTechniqueMeta returns one catalog entry per technique with at least
// one loaded ability, sorted by technique ID -- same shape as
// ARTStore.ListTechniqueMeta, so the frontend can render both sources with
// shared code. Safe to call on a nil *CalderaStore (returns nil).
func (s *CalderaStore) ListTechniqueMeta() []TechniqueMeta {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TechniqueMeta, 0, len(s.steps))
	for id, steps := range s.steps {
		name := ""
		if len(steps) > 0 {
			name = steps[0].Name
		}
		out = append(out, TechniqueMeta{ID: id, Name: name, Tests: len(steps), Tactic: models.LookupTactic(id)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ListTechniqueIDs returns every technique ID this store has at least one
// ability mapped to, sorted for stable iteration. Safe to call on a nil
// *CalderaStore (returns nil).
func (s *CalderaStore) ListTechniqueIDs() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.steps))
	for id := range s.steps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Count returns the total number of loaded abilities across every mapped
// technique. Safe to call on a nil *CalderaStore (returns 0).
func (s *CalderaStore) Count() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, steps := range s.steps {
		n += len(steps)
	}
	return n
}

// fetchAllCalderaAbilities fetches and parses the full abilities list from a
// live Caldera instance. Shared by NewCalderaStore and
// buildCalderaAllWindowsSteps (which additionally converts to steps and
// requires at least one Windows-executor ability -- callers with different
// requirements do that conversion themselves).
func fetchAllCalderaAbilities(calderaURL, apiKey string) ([]calderaAbilityFull, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	base := strings.TrimRight(calderaURL, "/")

	req, _ := http.NewRequest("GET", base+"/api/v2/abilities", nil)
	if apiKey != "" {
		req.Header.Set("KEY", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch all abilities: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch all abilities: HTTP %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	var abilities []calderaAbilityFull
	if err := json.Unmarshal(body, &abilities); err != nil {
		return nil, fmt.Errorf("parse abilities: %w", err)
	}
	return abilities, nil
}
