# Per-Atomic Parallelism Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let one destructive atomic stop forcing its harmless sibling atomics to run serially, by moving resource declaration from per-technique to per-atomic.

**Architecture:** The agent's `sched` package already runs steps concurrently under resource locks. This plan adds a per-atomic declaration (`reads[]`/`writes[]`), a fixed-granularity resource vocabulary with domain-specific canonicalisation enforced at the agent boundary, and a `basFootprint` quiescence barrier. Parallelism is derived from lock conflicts and never stored.

**Tech Stack:** Go 1.26.6, both modules (`agent/`, `orchestrator/`). No new dependencies.

**Spec:** `orchestrator/docs/superpowers/specs/2026-09-03-per-atomic-parallelism-design.md`

## Global Constraints

- **Core invariant:** a profile may cause unnecessary serialization, but an under-declared profile must never permit conflicting execution. Every task is judged against this.
- Parallelism is **derived** from lock conflicts. No `parallel_safe` field may be added anywhere.
- Granularity is **fixed per domain** — whole-domain or keyed, never both.
- Anything invalid (unparseable key, wrong granularity, unregistered domain) escalates to the **exclusive global barrier**, not a domain lock.
- `basFootprint` polarity: ordinary execution takes **shared**, footprint observers take **exclusive**. Never model as read/write.
- Canonicalisation and validation run **in the agent**, at the lock boundary — never trusted from the wire.
- Line endings: LF. On this Windows host `git stash` can rewrite files to CRLF; check with `python -c "print(open(F,'rb').read().count(b'\r\n'))"` before committing.
- POSIX-only tests run in Docker: `MSYS_NO_PATHCONV=1 docker run --rm -v "/c/Users/Administrator/Downloads/Audspect_Cloud/agent:/src" -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false golang:1.25-bookworm bash -c 'go test ./...'`
- Commit and push after each task.

---

### Task 1: Domain vocabulary with fixed granularity

**Files:**
- Create: `agent/sched/domains.go`
- Test: `agent/sched/domains_test.go`

**Interfaces:**
- Produces: `sched.DomainKind` (`KindWholeDomain`, `KindKeyed`), `sched.LookupDomain(name string) (DomainKind, bool)`, `sched.CanonicaliseKey(domain, key string) (string, bool)`

- [ ] **Step 1: Write the failing test**

```go
package sched

import "testing"

func TestLookupDomain_UnregisteredIsRejected(t *testing.T) {
	if _, ok := LookupDomain("not-a-real-domain"); ok {
		t.Error("unregistered domain must not resolve; it has to escalate to the global barrier")
	}
}

func TestLookupDomain_CurrentDomainsAreWholeDomain(t *testing.T) {
	// Every profile shipped today is observe(domain) with no Key. These must stay
	// whole-domain or existing parallelism regresses.
	// The exact set in orchestrator/internal/scenario/resource.go.
	for _, d := range []string{"registry", "filesystem", "process", "network", "wmi-secpolicy"} {
		kind, ok := LookupDomain(d)
		if !ok {
			t.Errorf("domain %q is not registered", d)
			continue
		}
		if kind != KindWholeDomain {
			t.Errorf("domain %q kind = %v, want KindWholeDomain (today's profiles address it whole)", d, kind)
		}
	}
}

func TestCanonicaliseKey_RejectsUnstableForms(t *testing.T) {
	for _, k := range []string{"", "relative/path", "/etc/../etc/foo", "%TEMP%/x", "$HOME/x"} {
		if got, ok := CanonicaliseKey("filesystem", k); ok {
			t.Errorf("CanonicaliseKey(filesystem, %q) = %q, ok — unstable forms must be rejected", k, got)
		}
	}
}

func TestCanonicaliseKey_NormalisesEquivalentSpellings(t *testing.T) {
	a, okA := CanonicaliseKey("filesystem", "/tmp/a")
	b, okB := CanonicaliseKey("filesystem", "/tmp/./a/")
	if !okA || !okB {
		t.Fatalf("expected both spellings to canonicalise, got ok=%v/%v", okA, okB)
	}
	if a != b {
		t.Errorf("equivalent paths produced different keys: %q vs %q", a, b)
	}
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd agent && go test ./sched/ -run "TestLookupDomain|TestCanonicaliseKey" -v`
Expected: FAIL — `undefined: LookupDomain`

- [ ] **Step 3: Implement the vocabulary**

```go
package sched

import (
	"path"
	"strings"
)

// DomainKind fixes how a domain may be addressed. A domain is addressed EITHER
// whole or by key, never both -- see the spec's "Granularity is fixed per
// domain". Mixing the two cannot be made safe on shared/exclusive locks alone.
type DomainKind int

const (
	KindWholeDomain DomainKind = iota
	KindKeyed
)

// domainRegistry is the closed vocabulary. Every domain addressed today is
// whole-domain, which is what preserves current parallelism: two whole-domain
// readers take shared locks and still overlap.
var domainRegistry = map[string]DomainKind{
	"registry":      KindWholeDomain,
	"filesystem":    KindWholeDomain,
	"process":       KindWholeDomain,
	"network":       KindWholeDomain,
	"wmi-secpolicy": KindWholeDomain,
}

func LookupDomain(name string) (DomainKind, bool) {
	k, ok := domainRegistry[name]
	return k, ok
}

// CanonicaliseKey returns the stable identity of key within domain, or ok=false
// if the key has no stable identity. A false result must escalate to the global
// barrier, never be accepted as written.
func CanonicaliseKey(domain, key string) (string, bool) {
	if key == "" {
		return "", false
	}
	if strings.ContainsAny(key, "%$") {
		return "", false // unexpanded %TEMP% / $HOME has no fixed identity
	}
	switch domain {
	case "filesystem":
		if !strings.HasPrefix(key, "/") {
			return "", false // relative paths have no stable identity
		}
		c := path.Clean(key)
		if strings.Contains(c, "..") {
			return "", false
		}
		return c, true
	default:
		// Flat identifiers: opaque, trimmed, must be non-empty.
		c := strings.TrimSpace(key)
		if c == "" {
			return "", false
		}
		return c, true
	}
}
```

- [ ] **Step 4: Run the tests**

Run: `cd agent && go test ./sched/ -run "TestLookupDomain|TestCanonicaliseKey" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/sched/domains.go agent/sched/domains_test.go
git commit -m "feat(sched): domain vocabulary with fixed per-domain granularity"
git push
```

---

### Task 2: basFootprint quiescence barrier

**Files:**
- Modify: `agent/sched/profile.go`, `agent/sched/locks.go`
- Test: `agent/sched/footprint_test.go`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `sched.footprintKey` constant; `ResourceProfile.ObservesFootprint bool`.

- [ ] **Step 1: Write the failing test**

```go
package sched

import "testing"

func hasLock(reqs []lockReq, key string, write bool) bool {
	for _, r := range reqs {
		if r.key == key && r.write == write {
			return true
		}
	}
	return false
}

// Ordinary atomics take a SHARED footprint hold so they remain compatible with
// each other. If this were exclusive, no two atomics could ever overlap and the
// whole parallelism feature would be silently disabled.
func TestFootprint_OrdinaryStepTakesSharedHold(t *testing.T) {
	reqs := resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "process"}}, Scope: "local", Risk: RiskObservation,
	})
	if !hasLock(reqs, footprintKey, false) {
		t.Errorf("ordinary step must hold %s SHARED, got %+v", footprintKey, reqs)
	}
	if hasLock(reqs, footprintKey, true) {
		t.Error("ordinary step must NOT hold the footprint exclusively — that serializes everything")
	}
}

// A footprint observer needs the surface quiet, so it takes the EXCLUSIVE hold.
func TestFootprint_ObserverTakesExclusiveHold(t *testing.T) {
	reqs := resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "process"}}, Scope: "local", Risk: RiskObservation,
		ObservesFootprint: true,
	})
	if !hasLock(reqs, footprintKey, true) {
		t.Errorf("footprint observer must hold %s EXCLUSIVE, got %+v", footprintKey, reqs)
	}
}

// The polarity check that fails loudly if anyone re-derives the barrier as
// ordinary read/write semantics.
func TestFootprint_TwoOrdinaryStepsDoNotConflictOnFootprint(t *testing.T) {
	a := resolve(&ResourceProfile{Domains: []ResourceLock{{Domain: "process"}}, Scope: "local", Risk: RiskObservation})
	b := resolve(&ResourceProfile{Domains: []ResourceLock{{Domain: "network"}}, Scope: "local", Risk: RiskObservation})
	if hasLock(a, footprintKey, true) || hasLock(b, footprintKey, true) {
		t.Fatal("two ordinary steps must be able to overlap on the footprint barrier")
	}
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd agent && go test ./sched/ -run TestFootprint -v`
Expected: FAIL — `undefined: footprintKey`

- [ ] **Step 3: Implement**

In `profile.go`, add the field and the key:

```go
// footprintKey is the quiescence barrier for BAS's own execution footprint --
// the process table, temp files, auth log and kernel ring buffer that every
// running atomic perturbs simply by existing.
//
// POLARITY IS INVERTED FROM ORDINARY READS AND MUST NOT BE "SIMPLIFIED":
//   ordinary step      -> SHARED    ("I perturb the surface")
//   footprint observer -> EXCLUSIVE ("I require the surface quiet")
//
// Modelling this as everyone-writes / observer-reads gives every atomic an
// exclusive hold, so every pair conflicts and parallelism is disabled entirely
// while still looking correct.
const footprintKey = "*footprint*"
```

and on `ResourceProfile`:

```go
	// ObservesFootprint marks an atomic whose EVIDENCE observes the surface BAS's
	// own execution perturbs (process table, auth log, dmesg, shared temp dirs).
	// See footprintKey for the inverted lock polarity.
	ObservesFootprint bool `json:"observesFootprint,omitempty"`
```

In `locks.go`, inside `resolve()`, after the existing global-barrier assignment:

```go
	// Footprint barrier: shared for ordinary execution, exclusive for observers.
	writes[footprintKey] = p != nil && p.ObservesFootprint
```

- [ ] **Step 4: Run the tests**

Run: `cd agent && go test ./sched/ -v`
Expected: PASS, including the existing equivalence and concurrency tests.

- [ ] **Step 5: Commit**

```bash
git add agent/sched/profile.go agent/sched/locks.go agent/sched/footprint_test.go
git commit -m "feat(sched): basFootprint quiescence barrier"
git push
```

---

### Task 3: Validate and canonicalise at the lock boundary

**Files:**
- Modify: `agent/sched/locks.go`
- Test: `agent/sched/locks_validation_test.go`

**Interfaces:**
- Consumes: `LookupDomain`, `CanonicaliseKey`, `KindWholeDomain`, `KindKeyed` from Task 1.
- Produces: `resolve()` escalating any invalid declaration to the exclusive global barrier.

- [ ] **Step 1: Write the failing test**

```go
package sched

import "testing"

func isFullySerial(reqs []lockReq) bool { return hasLock(reqs, globalKey, true) }

func TestResolve_EscalatesInvalidDeclarations(t *testing.T) {
	cases := []struct {
		name string
		p    *ResourceProfile
	}{
		{"unregistered domain", &ResourceProfile{
			Domains: []ResourceLock{{Domain: "nonsense"}}, Scope: "local", Risk: RiskObservation}},
		{"keyed access to a whole-domain domain", &ResourceProfile{
			Domains: []ResourceLock{{Domain: "process", Key: "1234"}}, Scope: "local", Risk: RiskObservation}},
		{"unparseable key", &ResourceProfile{
			Domains: []ResourceLock{{Domain: "filesystem", Key: "relative/path"}}, Scope: "local", Risk: RiskObservation}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !isFullySerial(resolve(c.p)) {
				t.Errorf("invalid declaration must escalate to the exclusive global barrier, got %+v", resolve(c.p))
			}
		})
	}
}

// Today's shipped shape must keep its shared lock, or existing parallelism regresses.
func TestResolve_WholeDomainReadStaysShared(t *testing.T) {
	reqs := resolve(&ResourceProfile{
		Domains: []ResourceLock{{Domain: "process"}}, Scope: "local", Risk: RiskObservation})
	if isFullySerial(reqs) {
		t.Fatal("a whole-domain observation must not serialize; that is today's behaviour")
	}
	if !hasLock(reqs, "process", false) {
		t.Errorf("want shared lock on \"process\", got %+v", reqs)
	}
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd agent && go test ./sched/ -run TestResolve_Escalates -v`
Expected: FAIL — invalid declarations currently resolve to per-domain locks, not the global barrier.

- [ ] **Step 3: Implement validation in `resolve()`**

Replace the domain loop's body so every declared resource is validated first; any failure escalates the whole profile:

```go
		for _, d := range p.Domains {
			kind, known := LookupDomain(d.Domain)
			if !known {
				return escalate() // unregistered domain
			}
			switch kind {
			case KindWholeDomain:
				if d.Key != "" {
					return escalate() // keyed access to a whole-domain domain
				}
				k := d.Domain
				writes[k] = writes[k] || exclusive
			case KindKeyed:
				ck, ok := CanonicaliseKey(d.Domain, d.Key)
				if !ok {
					return escalate() // unparseable or whole-domain access to a keyed domain
				}
				k := d.Domain + "/" + ck
				writes[k] = writes[k] || exclusive
			}
		}
```

with a helper that produces the fully-serial lock set, preserving the footprint hold:

```go
// escalate returns the lock set for a declaration that cannot be trusted: the
// exclusive global barrier, i.e. fully serial. Always correct, never optimistic.
func escalate() []lockReq {
	return []lockReq{
		{key: footprintKey, write: false},
		{key: globalKey, write: true},
	}
}
```

- [ ] **Step 4: Run the tests**

Run: `cd agent && go test ./sched/ -v`
Expected: PASS. The existing `TestParallelMatchesSerial` equivalence test must still pass.

- [ ] **Step 5: Commit**

```bash
git add agent/sched/locks.go agent/sched/locks_validation_test.go
git commit -m "feat(sched): validate and canonicalise resource declarations at the lock boundary"
git push
```

---

### Task 4: Per-atomic reads/writes

**Files:**
- Modify: `agent/sched/profile.go`, `agent/sched/locks.go`
- Test: `agent/sched/atomic_profile_test.go`

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `ResourceProfile.Reads []ResourceLock`, `ResourceProfile.Writes []ResourceLock`. When either is non-empty, `Domains`/`Risk` are ignored.

- [ ] **Step 1: Write the failing test**

```go
package sched

import "testing"

// The case a single Risk cannot express: reads one domain, writes another.
func TestResolve_SplitReadWriteSets(t *testing.T) {
	reqs := resolve(&ResourceProfile{
		Reads:  []ResourceLock{{Domain: "process"}},
		Writes: []ResourceLock{{Domain: "network"}},
		Scope:  "local",
	})
	if !hasLock(reqs, "process", false) {
		t.Errorf("declared read must take a SHARED lock, got %+v", reqs)
	}
	if !hasLock(reqs, "network", true) {
		t.Errorf("declared write must take an EXCLUSIVE lock, got %+v", reqs)
	}
}

// Writes dominate reads of the same resource: one exclusive hold, not both.
func TestResolve_WriteDominatesReadOfSameResource(t *testing.T) {
	reqs := resolve(&ResourceProfile{
		Reads:  []ResourceLock{{Domain: "network"}},
		Writes: []ResourceLock{{Domain: "network"}},
		Scope:  "local",
	})
	if hasLock(reqs, "network", false) {
		t.Error("must not hold the same resource shared AND exclusive")
	}
	if !hasLock(reqs, "network", true) {
		t.Errorf("write must dominate, got %+v", reqs)
	}
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd agent && go test ./sched/ -run TestResolve_Split -v`
Expected: FAIL — `unknown field Reads`

- [ ] **Step 3: Implement**

Add to `ResourceProfile`:

```go
	// Reads/Writes declare per-resource direction. A single Risk cannot express
	// "reads process, writes filesystem": observation under-locks the write,
	// modification over-serializes the read. When either is non-empty these take
	// precedence and Domains/Risk are ignored.
	Reads  []ResourceLock `json:"reads,omitempty"`
	Writes []ResourceLock `json:"writes,omitempty"`
```

In `resolve()`, before the legacy `Domains` path:

```go
	if len(p.Reads) > 0 || len(p.Writes) > 0 {
		for _, set := range []struct {
			res       []ResourceLock
			exclusive bool
		}{{p.Reads, false}, {p.Writes, true}} {
			for _, d := range set.res {
				k, ok := lockKeyFor(d)
				if !ok {
					return escalate()
				}
				writes[k] = writes[k] || set.exclusive
			}
		}
		// ... emit sorted lock set
	}
```

Factor the per-resource key derivation from Task 3 into `lockKeyFor(d ResourceLock) (string, bool)` so both paths share one validation.

- [ ] **Step 4: Run the tests**

Run: `cd agent && go test ./sched/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent/sched/profile.go agent/sched/locks.go agent/sched/atomic_profile_test.go
git commit -m "feat(sched): per-resource read/write direction on ResourceProfile"
git push
```

---

### Task 5: Reclassify T1057 and wire the server side

**Files:**
- Modify: `orchestrator/internal/scenario/resource.go`
- Test: `orchestrator/internal/scenario/resource_test.go`

**Interfaces:**
- Consumes: `ObservesFootprint` from Task 2 (mirrored in `scenario.ResourceProfile`).

- [ ] **Step 1: Write the failing test**

```go
func TestResourceProfileFor_FootprintObserversAreMarked(t *testing.T) {
	// ps aux under concurrency returns BAS's own atomics, so Process Discovery
	// observes the footprint and must take the quiesce barrier.
	p := ResourceProfileFor("T1057")
	if p == nil {
		t.Fatal("T1057 has no profile")
	}
	if !p.ObservesFootprint {
		t.Error("T1057 (Process Discovery) must be marked ObservesFootprint — its evidence includes BAS's own processes")
	}
}
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd orchestrator && go test ./internal/scenario/ -run TestResourceProfileFor_Footprint -v`
Expected: FAIL — `p.ObservesFootprint` is false.

- [ ] **Step 3: Implement**

Add `ObservesFootprint bool` to `scenario.ResourceProfile` (mirroring the agent type, same JSON tag), add an `observeFootprint(domain)` constructor, and switch `T1057` to it.

- [ ] **Step 4: Run the tests**

Run: `cd orchestrator && go test ./internal/scenario/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/scenario/resource.go orchestrator/internal/scenario/resource_test.go
git commit -m "fix(scenario): mark T1057 as a footprint observer"
git push
```

---

### Task 6: Full verification

- [ ] **Step 1: Cross-build both modules**

```bash
cd agent && for os in linux darwin windows; do GOOS=$os GOARCH=amd64 go build ./... || exit 1; done
cd ../orchestrator && go build ./... && go vet ./internal/scenario/
```

- [ ] **Step 2: Agent suite on both platforms**

```bash
cd agent && go test ./...
MSYS_NO_PATHCONV=1 docker run --rm -v "/c/Users/Administrator/Downloads/Audspect_Cloud/agent:/src" \
  -w /src -e GOWORK=off -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false \
  golang:1.25-bookworm bash -c 'go test -timeout 15m ./...'
```

- [ ] **Step 3: Orchestrator suites**

```bash
cd orchestrator && go test ./internal/scenario/ ./internal/api/ -timeout 25m
```
`internal/api` runs ~11 minutes; use an explicit `-timeout`.

- [ ] **Step 4: Confirm the equivalence property still holds**

Run: `cd agent && go test ./sched/ -run TestParallelMatchesSerial -count=5 -v`
Expected: PASS on all 5 runs. This is the test that proves concurrent execution matches serial.

- [ ] **Step 5: Verify no stored-parallelism regression**

```bash
grep -rn "parallel_safe\|ParallelSafe\|parallelSafe" agent/ orchestrator/internal/ --include=*.go
```
Expected: no matches. Parallelism must remain derived.

- [ ] **Step 6: Check line endings, then push**

```bash
python -c "
import glob
for f in glob.glob('agent/sched/*.go') + ['orchestrator/internal/scenario/resource.go']:
    b=open(f,'rb').read()
    print(f, 'CRLF=', b.count(b'\r\n'))"
```

---

## Out of scope

**Authoring profiles for the atomic corpus.** This plan delivers the mechanism; populating it is a separate, open-ended content effort with its own pacing question, and each profile needs the evidence standard applied against real resolved command text. Partial coverage is always safe — an unprofiled atomic inherits its technique's profile or falls back to fully serial — so the mechanism is useful before the corpus is complete.

Also out of scope, per the spec: `ISOLATABLE`, intention locks, symlink resolution.

## Expected effect on first deployment

Step 5 **removes** parallelism that exists today by correctly serializing `T1057`. Until atomic profiles are authored, the observable result of this work is a sweep that is slightly slower and measurably more correct. That is intended, and worth saying out loud before anyone reports it as a regression.
