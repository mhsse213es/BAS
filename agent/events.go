package main

import (
	"log"
	"sync"
	"time"
)

// RunEvent mirrors the server's models.RunEvent wire shape.
type RunEvent struct {
	RunID       string         `json:"runId"`
	Seq         int64          `json:"seq"`
	Type        string         `json:"type"`
	TaskID      string         `json:"taskId,omitempty"`
	TechniqueID string         `json:"techniqueId,omitempty"`
	Ts          time.Time      `json:"ts"`
	Payload     map[string]any `json:"payload,omitempty"`
}

// eventForResult derives the terminal event type and verdict from a step result.
// Timeout takes priority (an explicit "ran, did not return" verdict); a security
// block is a completed step with verdict "blocked"; otherwise pass/fail by exit.
func eventForResult(r ExecResult) (typ, verdict string) {
	if r.TimedOut {
		return "timeout", ""
	}
	if r.Blocked {
		return "completed", "blocked"
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
// OLDEST event (to keep the most recent state) and counts the drop.
func (e *eventEmitter) emit(ev RunEvent) {
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
	close(e.done)
	e.wg.Wait()
}
