package api

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

// Refusals from the discovery gate. Each one is returned before any provider is
// contacted, and each maps to an HTTP status in discoveryStatusCode.
var (
	// errCloudAccountBusy: a discovery pass for this account is already running.
	errCloudAccountBusy = errors.New("a discovery pass for this account is already running; retry when it finishes")
	// errCloudServerSaturated: the server-wide limit is reached and the queue is
	// full, or the wait for a slot timed out.
	errCloudServerSaturated = errors.New("the server is at its cloud discovery limit; retry later")
)

// cloudDiscoveryGate bounds cloud discovery work. It allows one pass per account,
// at most maxConcurrent passes across the server, and at most maxQueued requests
// waiting for a server slot, each waiting at most queueWait. Anything beyond those
// limits is refused at once, so the queue cannot grow without bound.
type cloudDiscoveryGate struct {
	mu        sync.Mutex
	active    map[string]bool // provider|account currently holding a pass
	slots     chan struct{}   // server-wide concurrency, one token per running pass
	queued    int
	maxQueued int
	queueWait time.Duration
}

func newCloudDiscoveryGate(maxConcurrent, maxQueued int, queueWait time.Duration) *cloudDiscoveryGate {
	return &cloudDiscoveryGate{
		active:    map[string]bool{},
		slots:     make(chan struct{}, maxConcurrent),
		maxQueued: maxQueued,
		queueWait: queueWait,
	}
}

// Acquire reserves a discovery pass for account. It returns a release function
// that must be called when the pass ends. It returns errCloudAccountBusy or
// errCloudServerSaturated when the pass cannot start, and ctx.Err() if the caller
// gives up while queued. A nil gate refuses everything.
func (g *cloudDiscoveryGate) Acquire(ctx context.Context, account cloudgraph.AccountScope) (func(), error) {
	if g == nil {
		return nil, errCloudServerSaturated
	}
	key := account.Provider + "|" + account.AccountID

	g.mu.Lock()
	if g.active[key] {
		g.mu.Unlock()
		return nil, errCloudAccountBusy
	}
	g.active[key] = true
	g.mu.Unlock()

	releaseAccount := func() {
		g.mu.Lock()
		delete(g.active, key)
		g.mu.Unlock()
	}
	releaseSlot := func() {
		<-g.slots
		releaseAccount()
	}

	select {
	case g.slots <- struct{}{}:
		return releaseSlot, nil
	default:
	}

	g.mu.Lock()
	if g.queued >= g.maxQueued {
		g.mu.Unlock()
		releaseAccount()
		return nil, errCloudServerSaturated
	}
	g.queued++
	g.mu.Unlock()
	leave := func() {
		g.mu.Lock()
		g.queued--
		g.mu.Unlock()
	}

	timer := time.NewTimer(g.queueWait)
	defer timer.Stop()
	select {
	case g.slots <- struct{}{}:
		leave()
		return releaseSlot, nil
	case <-timer.C:
		leave()
		releaseAccount()
		return nil, errCloudServerSaturated
	case <-ctx.Done():
		leave()
		releaseAccount()
		return nil, ctx.Err()
	}
}
