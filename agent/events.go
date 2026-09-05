package main

import (
	"log"
	"sync"
	"time"

	"audspect/agent/protocol"
)

// RunEvent mirrors the server's models.RunEvent wire shape.
type RunEvent struct {
	RunID       string         `json:"runId"`
	Seq         int64          `json:"seq"`
	Type        string         `json:"type"`
	TaskID      string         `json:"taskId,omitempty"`
	TechniqueID string         `json:"techniqueId,omitempty"`
	StepName    string         `json:"stepName,omitempty"`
	Ts          time.Time      `json:"ts"`
	Payload     map[string]any `json:"payload,omitempty"`
}

// eventForResult derives the terminal event type and verdict from a step result.
// Timeout takes priority (an explicit "ran, did not return" verdict); a security
// block is a completed step with verdict "blocked"; ExitCode -1 with neither of
// those flags set is this codebase's own agent-side sentinel for "we didn't get
// a real result" (cmd.Start() failure, WaitDelay-abandoned, scenario-cancellation
// -- see executor.go) rather than a genuine command exit code, so it reports
// "error", never "fail" -- a step whose process never even launched is not
// evidence a control failed to block anything. Otherwise pass/fail by exit.
func eventForResult(r protocol.ExecResult) (typ, verdict string) {
	if r.TimedOut {
		return "timeout", ""
	}
	if r.Blocked {
		return "completed", "blocked"
	}
	if r.ExitCode == -1 {
		return "completed", "error"
	}
	if r.ExitCode == 0 {
		return "completed", "pass"
	}
	return "completed", "fail"
}

// eventEmitter buffers RunEvents on a bounded channel and flushes them to the
// server in batches. Emitting never blocks the run: if the queue is full (server
// unreachable), the oldest event is dropped and a throttled warning is logged.
type eventEmitter struct {
	send      func([]RunEvent) error
	queue     chan RunEvent
	maxBatch  int
	interval  time.Duration
	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	dropMu    sync.Mutex
	dropped   int
	lastDropL time.Time
}

func newEventEmitter(send func([]RunEvent) error, maxQueue int, interval time.Duration) *eventEmitter {
	if maxQueue < 1 {
		maxQueue = 1000
	}
	e := &eventEmitter{
		send:     send,
		queue:    make(chan RunEvent, maxQueue),
		maxBatch: 64,
		interval: interval,
		done:     make(chan struct{}),
	}
	e.wg.Add(1)
	go e.loop()
	return e
}

// emit enqueues an event without ever blocking. On a full queue it drops the
// OLDEST event (to keep the most recent state) and counts the drop. After close()
// it is a no-op. The caller is responsible for setting RunID and Seq; only Ts is
// auto-filled here.
func (e *eventEmitter) emit(ev RunEvent) {
	select {
	case <-e.done:
		return // emitter closed — best-effort, discard
	default:
	}
	if ev.Ts.IsZero() {
		ev.Ts = time.Now()
	}
	for {
		select {
		case e.queue <- ev:
			return
		default:
			select {
			case <-e.queue:
				e.noteDrop()
			default:
			}
		}
	}
}

// emitCritical sends ev directly, bypassing the bounded queue entirely --
// used only for events whose loss would be unrecoverable, currently just
// run_started. Everything else (queued/started/completed/etc.) goes
// through the normal batched emit(): losing one of those is a minor gap in
// an otherwise-fine progress feed, but losing run_started leaves
// scenario_runs.steps_total stuck at 0 forever, since nothing else ever
// sets it (see event_handlers.go's CASE WHEN ins.type='run_started').
// run_started is always the FIRST event of a run, which makes it the
// oldest -- and therefore the first candidate -- for emit()'s drop-oldest
// eviction once the queue fills, which a large sweep's immediate burst of
// "queued" events can trigger while the consumer is still blocked sending
// an earlier batch. Fires its own short-lived goroutine with a small
// retry budget since this is a single small message, once per run, not a
// high-frequency stream that needs batching.
func (e *eventEmitter) emitCritical(ev RunEvent) {
	if ev.Ts.IsZero() {
		ev.Ts = time.Now()
	}
	go func() {
		for attempt := 0; attempt < 3; attempt++ {
			if err := e.send([]RunEvent{ev}); err == nil {
				return
			}
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
		log.Printf("[events] critical event %q for run %s failed after retries", ev.Type, ev.RunID)
	}()
}

func (e *eventEmitter) noteDrop() {
	e.dropMu.Lock()
	e.dropped++
	if time.Since(e.lastDropL) > 5*time.Second {
		log.Printf("[events] queue full — dropped %d event(s) (server unreachable?)", e.dropped)
		e.dropped = 0
		e.lastDropL = time.Now()
	}
	e.dropMu.Unlock()
}

func (e *eventEmitter) loop() {
	defer e.wg.Done()
	t := time.NewTicker(e.interval)
	defer t.Stop()
	batch := make([]RunEvent, 0, e.maxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		_ = e.send(batch)
		batch = batch[:0]
	}
	for {
		select {
		case <-e.done:
			for {
				select {
				case ev := <-e.queue:
					batch = append(batch, ev)
					if len(batch) >= e.maxBatch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case ev := <-e.queue:
			batch = append(batch, ev)
			if len(batch) >= e.maxBatch {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// close flushes remaining events and stops the loop.
func (e *eventEmitter) close() {
	e.closeOnce.Do(func() { close(e.done) })
	e.wg.Wait()
}
