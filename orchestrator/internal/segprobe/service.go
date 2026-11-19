package segprobe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/audspect/bas/internal/segprobe/runstore"
)

// ErrBusy is returned while another run holds the lab. Runs share the lab's
// firewall rules, so a second run is refused rather than queued.
var ErrBusy = errors.New("a segmentation run is already in progress")

// RunStore is the persistence the service needs. runstore.Store implements it.
type RunStore interface {
	Create(ctx context.Context, packID, requestedBy string) (runstore.Run, error)
	SetRunning(ctx context.Context, id string) error
	SaveRunResults(ctx context.Context, id string, runIndex int, rows []runstore.ProbeRow) error
	Finish(ctx context.Context, id, status string, runs int, stable *bool, failure string) error
}

// LabProvider is a Provider that can also load a pack's firewall rules.
type LabProvider interface {
	Provider
	ApplyRules(ctx context.Context, rulesFile string) error
}

// RunsPerPack is how many repeated passes each run makes. Three is the gate.
const RunsPerPack = 3

// runTimeout bounds one whole run: rules, three passes, and storage.
const runTimeout = 30 * time.Minute

// Service runs registered packs against the lab, one at a time.
type Service struct {
	store       RunStore
	scenarioDir string
	newProvider func() LabProvider

	mu     sync.Mutex
	active bool
	wg     sync.WaitGroup
}

func NewService(store RunStore, scenarioDir string, newProvider func() LabProvider) *Service {
	return &Service{store: store, scenarioDir: scenarioDir, newProvider: newProvider}
}

// Submit validates the pack, reserves the lab, records the run, and starts it
// in the background. It returns the queued run at once.
func (s *Service) Submit(ctx context.Context, packID, requestedBy string) (runstore.Run, error) {
	pack, err := LookupPack(packID)
	if err != nil {
		return runstore.Run{}, err
	}
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return runstore.Run{}, ErrBusy
	}
	s.active = true
	s.mu.Unlock()

	run, err := s.store.Create(ctx, pack.ID, requestedBy)
	if err != nil {
		s.release()
		return runstore.Run{}, err
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.release()
		s.execute(run, pack)
	}()
	return run, nil
}

// Wait blocks until every started run has finished. Used by tests and shutdown.
func (s *Service) Wait() { s.wg.Wait() }

func (s *Service) release() {
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
}

// execute runs one pack. Infrastructure faults (rules, scenario, storage) mark
// the run failed. A probe that graded ERROR is a verdict, not a fault: the run
// still completes and the verdict is stored as produced.
func (s *Service) execute(run runstore.Run, pack Pack) {
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	fail := func(reason string) {
		_ = s.store.Finish(context.Background(), run.ID, "failed", 0, nil, reason)
	}

	if err := s.store.SetRunning(ctx, run.ID); err != nil {
		fail(fmt.Sprintf("record start: %v", err))
		return
	}
	scenario, err := loadPackScenario(s.scenarioDir, pack)
	if err != nil {
		fail(err.Error())
		return
	}
	prov := s.newProvider()
	if err := prov.ApplyRules(ctx, pack.RulesFile); err != nil {
		fail(fmt.Sprintf("apply firewall rules: %v", err))
		return
	}
	passes, stable, err := RunRepeated(ctx, prov, scenario, RunsPerPack)
	if err != nil {
		fail(fmt.Sprintf("run scenario: %v", err))
		return
	}
	for _, pass := range passes {
		if err := s.store.SaveRunResults(ctx, run.ID, pass.RunIndex, toProbeRows(pass)); err != nil {
			fail(fmt.Sprintf("store results: %v", err))
			return
		}
	}
	stableCopy := stable
	if err := s.store.Finish(ctx, run.ID, "completed", len(passes), &stableCopy, ""); err != nil {
		fail(fmt.Sprintf("record completion: %v", err))
	}
}

func loadPackScenario(dir string, pack Pack) (Scenario, error) {
	data, err := os.ReadFile(filepath.Join(dir, pack.ScenarioFile))
	if err != nil {
		return Scenario{}, fmt.Errorf("read scenario %s: %w", pack.ScenarioFile, err)
	}
	s, err := LoadScenario(data)
	if err != nil {
		return Scenario{}, fmt.Errorf("load scenario %s: %w", pack.ScenarioFile, err)
	}
	return s, nil
}

// toProbeRows converts one pass into stored rows, keeping verdicts, reasons and
// the firewall rule IDs that decided them.
func toProbeRows(pass RunResult) []runstore.ProbeRow {
	rows := make([]runstore.ProbeRow, 0, len(pass.Outcomes))
	for seq, o := range pass.Outcomes {
		row := runstore.ProbeRow{
			RunIndex: pass.RunIndex,
			Seq:      seq,
			ProbeID:  o.Spec.ID,
			Src:      string(o.Spec.Src),
			Dst:      string(o.Spec.Dst),
			DstPort:  o.Spec.DstPort,
			Proto:    o.Spec.Proto,
			Expect:   string(o.Spec.Expect),
			Outcome:  string(o.Result.Outcome),
			Verdict:  string(o.Verdict),
			Reason:   o.Reason,
		}
		for _, e := range o.Events {
			row.RuleIDs = append(row.RuleIDs, e.RuleID)
		}
		if !o.Result.Start.IsZero() {
			start := o.Result.Start
			row.StartedAt = &start
		}
		if !o.Result.End.IsZero() {
			end := o.Result.End
			row.EndedAt = &end
		}
		rows = append(rows, row)
	}
	return rows
}
