# Phase 6: FIFO-Fair ConcurrencyLimiter Design

## Context

Phases 1-5 of the agent scheduler's adaptive control plane are shipped on
`main` (WS backoff/jitter, scheduler telemetry, `sched.ConcurrencyLimiter`
admission ceiling, host-pressure-driven ceiling, `sched.RiskGate`
risk-aware admission). Phase 3's `ConcurrencyLimiter`
(`agent/sched/limiter.go`) and Phase 5's `RiskGate`
(`agent/sched/riskgate.go`) both admit jobs through a `sync.Mutex` +
`sync.Cond` gate, and both carry the same doc-comment admission: this
"guarantees deadlock-freedom but explicitly not fairness."

A Phase 6 candidate ("priority + aging", to address potential
starvation) was proposed after Phase 5 shipped. Per this project's
"measure before adapting" discipline, a prior investigation (see project
memory `project_phase6_brainstorm_paused.md`) traced *where* the
unfairness actually lives before proposing a fix, rather than accepting
the original priority-tiers framing at face value. Three findings came
out of that investigation and are the starting point for this spec:

1. `sched.Run`'s dispatch loop (`agent/sched/scheduler.go`, `for i :=
   range jobs { ch <- jobs[i] }` into an unbuffered channel) only
   guarantees job *i* is *offered* to a worker before job *i+1* is
   offered — not that it finishes, or even starts, first. A
   priority-queue fix aimed at dispatch order would not address the
   actual risk.
2. The real starvation risk is inside `ConcurrencyLimiter.Acquire`'s
   `sync.Cond.Wait()`/`Broadcast()` pair: when a slot frees, `Broadcast`
   wakes every blocked waiter, and whichever goroutine wins the race to
   re-acquire the mutex and find `active < limit` true gets the slot —
   with no ordering guarantee among waiters. A goroutine that has been
   waiting the longest can, in principle, keep losing that race to
   newer arrivals indefinitely.
3. No priority concept exists anywhere in `agent/sched/` or
   `orchestrator/internal/scenario/` today (`ResourceProfile` has no
   priority-like field). A P0-P4 priority-tier design would need real
   per-technique priority data to assign meaningful values from
   honestly — the same wall Phase 4 (CPU/memory weights) and Phase 5
   (per-technique cost) already hit and declined to cross for the same
   reason.

Three approaches were presented to the user: (A) make the admission
gates' internal wait queues FIFO-fair, directly eliminating the
mechanism found above, with no new fields and no fabricated data; (B)
the full P0-P4 priority + aging system; (C) wait for the Phase 1-5
rollout to produce real `sched_lock_wait_max_ms`/`sched_queue_wait_max_ms`
evidence of actual starvation before building anything. **The user chose
Approach A.**

## Scope correction from the original brainstorm

The paused brainstorm's framing of Approach A targeted both
`ConcurrencyLimiter` and `RiskGate`. Re-reading `riskgate.go` in detail
during this session's design pass found that `RiskGate` does not
actually have the starvation bug described above.

`RiskGate.Allow`'s wait loop (`for !g.policy(risk) { ... cond.Wait() }`)
is a pure predicate check with no resource allocation — nothing is
incremented or consumed by `Allow` the way `ConcurrencyLimiter.active`
is consumed by `Acquire`. When `SetPolicy` broadcasts, every blocked
waiter independently re-checks its own `risk` value against the new
policy; whoever is eligible is admitted, with zero contention between
waiters, because eligibility isn't a scarce, countable thing being
handed out one unit at a time. Broadcast-wake-all is the *correct*
mechanism for `RiskGate`, not a bug — a FIFO/Signal-based grant would
in fact be wrong there, since it would only wake one waiter when
several different risk classes might have just become eligible at
once.

The genuine "longest-waiter can lose indefinitely" starvation risk
requires a scarce, countable resource being granted one unit at a time.
That's `ConcurrencyLimiter.active < limit` — not `RiskGate`.

**This spec covers `ConcurrencyLimiter` only.** `RiskGate` is
explicitly out of scope: it needs no code change, only a doc-comment
addition explaining why it's exempt, so a future reader who notices the
asymmetry between the two types finds the answer in the source rather
than having to re-derive it.

## Design

### Architecture: explicit FIFO ticket queue

Replace `ConcurrencyLimiter`'s `sync.Cond` with an explicit FIFO queue
of one-shot ticket channels, one per blocked `Acquire` call, in arrival
order:

```go
type ConcurrencyLimiter struct {
    mu     sync.Mutex
    limit  int
    active int
    queue  []chan struct{} // FIFO tickets, arrival order; grantLocked closes from the front
}
```

`Acquire` fast-paths only when a slot is free **and nobody is already
queued** — a slot being free at the instant of a new call is not enough
to admit it ahead of existing waiters, which is the actual fairness
guarantee this design provides. Otherwise the caller enqueues its own
ticket and blocks on it:

```go
func (l *ConcurrencyLimiter) Acquire(ctx context.Context) bool {
    l.mu.Lock()
    if l.active < l.limit && len(l.queue) == 0 {
        l.active++
        l.mu.Unlock()
        return true
    }
    ticket := make(chan struct{})
    l.queue = append(l.queue, ticket)
    l.mu.Unlock()

    select {
    case <-ticket:
        return true
    case <-ctx.Done():
        return l.cancelWaiting(ticket)
    }
}

func (l *ConcurrencyLimiter) grantLocked() {
    for len(l.queue) > 0 && l.active < l.limit {
        t := l.queue[0]
        l.queue = l.queue[1:]
        l.active++
        close(t)
    }
}

func (l *ConcurrencyLimiter) Release() {
    l.mu.Lock()
    l.active--
    l.grantLocked()
    l.mu.Unlock()
}

func (l *ConcurrencyLimiter) SetLimit(n int) {
    if n < 1 {
        n = 1
    }
    l.mu.Lock()
    l.limit = n
    l.grantLocked()
    l.mu.Unlock()
}
```

`grantLocked` pops from the front of the queue and closes exactly that
ticket. Closing a channel wakes only the one goroutine that owns it —
no broadcast, no post-wake re-check race among waiters. Whoever has
been waiting longest is provably the next one admitted, because the
queue itself, not goroutine-scheduling luck, decides admission order.

`Limit()` and `Active()` are unchanged (still simple mutex-guarded
reads). The full public API of `ConcurrencyLimiter`
(`Acquire`/`Release`/`SetLimit`/`Limit`/`Active`) is unchanged — this is
an internal-only rewrite of the admission mechanism.

### Cancellation while queued

`select` can legitimately choose either arm when a ticket is granted
(`grantLocked` closes it) and the caller's `ctx` is cancelled at close
to the same instant — this race is inherent to `select` over two
simultaneously-ready channels, not a bug to eliminate. `cancelWaiting`
resolves it without ever leaking a slot:

```go
func (l *ConcurrencyLimiter) cancelWaiting(ticket chan struct{}) bool {
    l.mu.Lock()
    for i, t := range l.queue {
        if t == ticket {
            // Still queued -- remove our own ticket, no slot was ever granted.
            l.queue = append(l.queue[:i], l.queue[i+1:]...)
            l.mu.Unlock()
            return false
        }
    }
    l.mu.Unlock()
    // Not in the queue: grantLocked already popped and closed it (we were
    // admitted) but select took the ctx.Done() arm anyway. The caller
    // treats `false` as "never acquired" and will never call Release, so
    // we must give the slot back ourselves or it leaks permanently.
    l.Release()
    return false
}
```

This is an intentional, documented behavior difference from the current
`sync.Cond`-based code: today, `ctx.Err()` is only ever checked *before*
calling `Wait`, so a grant that happens to race with cancellation always
wins in the current implementation (it can never report "granted but
returned false"). Under the new design, a caller can legitimately be
granted a slot and still observe `Acquire` returning `false`, in which
case the slot has already been released back to the pool by the time
`Acquire` returns. This does not change `Acquire`'s documented contract
— "returns false only on ctx cancellation... never trusted as a
verdict, always treated as an abort" — and no slot is ever leaked
either way.

### RiskGate: doc-comment only

Add a doc-comment note to `RiskGate`'s type comment in
`agent/sched/riskgate.go` explaining the Section-1 asymmetry: unlike
`ConcurrencyLimiter`, `RiskGate.Allow` does not allocate from a scarce
countable resource, so `sync.Cond`'s broadcast-wake-all remains correct
here and is deliberately not being replaced with a FIFO queue. No
functional code in `riskgate.go` changes.

## Testing

New/changed tests in `agent/sched/limiter_test.go`:

1. **`TestConcurrencyLimiter_FIFOOrderUnderContention`** — the
   regression this whole change exists to prevent. Construct a limiter
   with `limit=1`. Launch N goroutines that call `Acquire` in a
   strictly sequenced arrival order (each one's launch is gated on the
   previous one's `Acquire` call having already been issued, so arrival
   order into the queue is deterministic even though completion order
   is what's under test), recording admission order into a
   mutex-guarded slice as each `Acquire` returns. `Release` the held
   slot once at a time and assert the recorded admission order exactly
   matches arrival order. This test is expected to be flaky-in-the-old-
   direction against the current `sync.Cond` implementation (i.e., it
   can occasionally observe an out-of-order admission there) — that
   flakiness is the bug this spec fixes, not a property to preserve.
2. **`TestConcurrencyLimiter_CancelWhileQueuedRemovesTicket`** — with
   `limit=1` and one slot held, enqueue two more waiters. Cancel the
   *first* queued waiter's `ctx` and assert its `Acquire` returns
   `false`. Then `Release` the held slot and assert the *second*
   (still-waiting) waiter's `Acquire` returns `true` next — proving a
   cancelled ticket is fully removed from the queue and does not leave
   a phantom hole or block whoever's behind it.
3. **`TestConcurrencyLimiter_CancelRaceWithGrantDoesNotLeakSlot`** — a
   targeted test for the `cancelWaiting`-vs-`grantLocked` race described
   above: with `limit=1`, hold the slot, queue one waiter with a
   cancellable `ctx`, then trigger `Release` (which calls `grantLocked`
   and closes the waiter's ticket) and `cancel()` the waiter's `ctx` as
   close together as the test can arrange (e.g. from two goroutines
   racing against a shared start signal). Assert `Active()` never
   exceeds `limit` afterward, and that a subsequent `Acquire` still
   succeeds — proving the race in either direction never leaks a slot.
4. Existing tests (basic acquire/release ordering not under contention,
   `SetLimit` raising and lowering, `Limit()`/`Active()` accessors) are
   the regression suite and must all still pass unmodified — public
   behavior is not changing, only the internal admission mechanism.

No test changes needed in `agent/sched/riskgate_test.go` — no functional
code there is changing.

## Non-goals / out of scope

- `RiskGate` internals (see Scope correction above) — doc comment only.
- Priority tiers, aging, or any per-`ResourceProfile` priority field
  (Approach B) — explicitly declined; no real per-technique priority
  data exists to assign values from honestly, the same reasoning that
  blocked naive versions of Phase 4 and Phase 5.
- `sched.Run`'s dispatch loop (`agent/sched/scheduler.go`) — confirmed
  in the prior investigation to not be where the actual starvation risk
  lives; not touched by this spec.
- New telemetry/metrics — this is an internal correctness fix to an
  existing mechanism, not a new observable feature. Existing
  `sched_lock_wait_max_ms`/`sched_queue_wait_max_ms` metrics (Phase 2)
  remain the way to observe queue-wait behavior in practice; no new
  metric is being added to specifically measure FIFO ordering.
- Any change to `agent/pressure_loop.go`, `agent/agent.go`, or how
  `ConcurrencyLimiter`/`RiskGate` are wired into `sched.Run` via
  `RunOption`s — those call sites are unaffected, since the public API
  of `ConcurrencyLimiter` is unchanged.

## Success criteria

1. `TestConcurrencyLimiter_FIFOOrderUnderContention` passes
   deterministically (not merely "usually") against the new
   implementation.
2. All existing `agent/sched` tests continue to pass unmodified.
3. No change to any call site outside `agent/sched/limiter.go` —
   `ConcurrencyLimiter`'s public API is identical before and after.
4. `RiskGate`'s doc comment explains the asymmetry; no functional code
   in `riskgate.go` changes.
