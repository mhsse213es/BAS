// Package protocol holds the executable protocol adapters of API BAS. A protocol is supported
// only when an adapter is registered here. Scenarios that name any other protocol are reported
// UNSUPPORTED by the runner (blueprint section 2).
package protocol

import (
	"context"
	"sort"
	"sync"
)

// HTTP is the default transport and is always supported.
const HTTP = "http"

// Adapter validates one protocol operation before it is sent. Validation is where a protocol
// adapter refuses a request that is not well formed for its protocol, or that would reach a host
// outside the lab.
type Adapter interface {
	// Name is the protocol name a scenario declares in its protocol field.
	Name() string
	// Validate reports whether body is a well-formed operation for this protocol.
	Validate(body string) error
}

type scenarioKey struct{}

// WithProtocol records the protocol of the scenario being run, so the request path can apply its
// adapter.
func WithProtocol(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, scenarioKey{}, name)
}

// FromContext returns the protocol recorded by WithProtocol, or "" when none is recorded.
func FromContext(ctx context.Context) string {
	v, _ := ctx.Value(scenarioKey{}).(string)
	return v
}

var (
	mu       sync.RWMutex
	adapters = map[string]Adapter{}
)

// Register adds an adapter. It is called from init functions of the adapter files only.
func Register(a Adapter) {
	mu.Lock()
	defer mu.Unlock()
	adapters[a.Name()] = a
}

// Get returns the adapter for a protocol. HTTP has no adapter because the HTTP path needs no
// extra validation.
func Get(name string) (Adapter, bool) {
	mu.RLock()
	defer mu.RUnlock()
	a, ok := adapters[name]
	return a, ok
}

// Supported reports whether a protocol can be executed: HTTP, or a protocol with a registered
// adapter. The empty name means HTTP.
func Supported(name string) bool {
	if name == "" || name == HTTP {
		return true
	}
	_, ok := Get(name)
	return ok
}

// Names returns the registered adapter names in sorted order.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(adapters))
	for n := range adapters {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
