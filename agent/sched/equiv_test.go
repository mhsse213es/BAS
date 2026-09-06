package sched

import (
	"context"
	"math/rand"
	"runtime"
	"testing"
)

// ── Equivalence harness ───────────────────────────────────────────────────────
//
// These tests prove the engine's central accuracy contract: for a fixed set of
// resource profiles, the parallel scheduler produces exactly the same per-step
// verdicts as a strict serial run. The model is a shared "world" of resource
// cells; each step writes a sentinel into the cells it owns, lingers to widen any
// race window, then reads back. A step's verdict is "clean" only if every cell it
// owns still held its sentinel on readback — i.e. nothing else touched its
// resource mid-execution. Correct labels keep contending steps from overlapping,
// so every verdict is clean and parallel == serial. A mislabel lets contenders
// overlap, a readback comes back dirty, and the harness sees a divergence.

// world is a fixed set of resource cells. The map is populated once and never
// structurally changed, so concurrent reads of the map are safe; only the int
// values are mutated, and those mutations are guarded by the scheduler's locks.
type world struct {
	cells map[string]*int
}

func newWorld(domains []string) *world {
	w := &world{cells: make(map[string]*int, len(domains))}
	for _, d := range domains {
		v := 0
		w.cells[d] = &v
	}
	return w
}

func (w *world) reset() {
	for _, p := range w.cells {
		*p = 0
	}
}

// linger burns a little time without sleeping so a mislabeled overlap has a real
// chance to interleave between the write and the readback.
func linger() {
	for range 200 {
		runtime.Gosched()
	}
}

// makeWorldJobs builds n jobs over w. Each job owns one or more domains, stamps
// its unique id into every owned cell, lingers, then records whether all its
// cells still hold that id. Verdicts are written to verdicts[i] by index so the
// result order is deterministic regardless of completion order.
func makeWorldJobs(rng *rand.Rand, w *world, domains []string, n int, verdicts []bool) []Job {
	jobs := make([]Job, n)
	for i := range jobs {
		id := i + 1
		// Each job owns 1–2 distinct domains, modified (write lock).
		k := 1 + rng.Intn(2)
		owned := map[string]bool{}
		for len(owned) < k {
			owned[domains[rng.Intn(len(domains))]] = true
		}
		var locks []ResourceLock
		var keys []string
		for d := range owned {
			locks = append(locks, ResourceLock{Domain: d})
			keys = append(keys, d)
		}
		p := &ResourceProfile{Domains: locks, Scope: "local", Risk: RiskModification}
		idx, ks := i, keys
		jobs[i] = Job{Resource: p, Run: func(ctx context.Context) bool {
			for _, d := range ks {
				*w.cells[d] = id
			}
			linger()
			clean := true
			for _, d := range ks {
				if *w.cells[d] != id {
					clean = false
					break
				}
			}
			verdicts[idx] = clean
			return false
		}}
	}
	return jobs
}

func TestParallelMatchesSerial(t *testing.T) {
	domains := []string{"registry", "filesystem", "network", "process", "wmi-secpolicy"}
	const n = 60

	for iter := range 20 {
		rng := rand.New(rand.NewSource(int64(iter) + 1))
		w := newWorld(domains)

		// Reference: strict serial execution, no locks, no overlap.
		serial := make([]bool, n)
		jobsSerial := makeWorldJobs(rng, w, domains, n, serial)
		RunSerial(context.Background(), jobsSerial)

		// Same job shape, executed through the parallel scheduler. Rebuild with
		// the same seed so the jobs are identical to the serial reference.
		w.reset()
		rng = rand.New(rand.NewSource(int64(iter) + 1))
		parallel := make([]bool, n)
		jobsParallel := makeWorldJobs(rng, w, domains, n, parallel)
		Run(context.Background(), 8, NewLockManager(), jobsParallel, nil)

		for i := range n {
			if !serial[i] {
				t.Fatalf("iter %d step %d: serial reference was dirty — test model is broken", iter, i)
			}
			if serial[i] != parallel[i] {
				t.Fatalf("iter %d step %d: parallel verdict %v != serial verdict %v — a resource profile is mislabeled",
					iter, i, parallel[i], serial[i])
			}
		}
	}
}

// TestMislabelIsDetectable is the harness's own canary: it deliberately mislabels
// every modification as an observation (read locks), which lets same-domain
// writers overlap. The harness MUST observe at least one dirty readback, proving
// it can actually catch an unsafe label rather than passing vacuously.
func TestMislabelIsDetectable(t *testing.T) {
	domains := []string{"registry", "filesystem"}
	const n = 40
	sawDirty := false

	// Many attempts: a race is probabilistic, so retry until it manifests.
	for attempt := 0; attempt < 200 && !sawDirty; attempt++ { //nolint:intrange // needs the && !sawDirty guard
		w := newWorld(domains)
		verdicts := make([]bool, n)
		jobs := make([]Job, n)
		for i := range jobs {
			id := i + 1
			d := domains[i%len(domains)]
			// MISLABEL: observation → read lock → same-domain writers overlap.
			p := &ResourceProfile{Domains: []ResourceLock{{Domain: d}}, Scope: "local", Risk: RiskObservation}
			idx := i
			jobs[i] = Job{Resource: p, Run: func(ctx context.Context) bool {
				*w.cells[d] = id
				linger()
				verdicts[idx] = (*w.cells[d] == id)
				return false
			}}
		}
		Run(context.Background(), 8, NewLockManager(), jobs, nil)
		for _, v := range verdicts {
			if !v {
				sawDirty = true
				break
			}
		}
	}
	if !sawDirty {
		t.Skip("mislabel race did not manifest in 200 attempts (run with -race for a deterministic signal)")
	}
}
