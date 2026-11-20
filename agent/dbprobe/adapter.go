package dbprobe

import (
	"context"
	"sort"
	"sync"
)

// Adapter is the engine-specific database access seam. Probes are named
// operations only; no method accepts free-form SQL.
type Adapter interface {
	Connect(ctx context.Context, cfg ConnectionConfig) error
	Identity(ctx context.Context) (string, error)
	EnumerateRoles(ctx context.Context) ([]Role, error)
	ReadGrants(ctx context.Context) ([]Grant, error)
	RunProbe(ctx context.Context, def ProbeDef, spec DBProbeSpec) (ProbeResult, error)
	CollectAudit(ctx context.Context, q AuditQuery) ([]AuditEvent, error)
	// Seed creates the synthetic fixture. Lab mode only; refused in client mode.
	Seed(ctx context.Context, f Fixture) error
	Cleanup(ctx context.Context, f Fixture) (CleanupResult, error)
	Capabilities() Capabilities
	Close() error
}

var (
	regMu    sync.RWMutex
	registry = map[string]func() Adapter{}
)

// Register makes an adapter factory available under engine.
func Register(engine string, f func() Adapter) {
	regMu.Lock()
	defer regMu.Unlock()
	registry[engine] = f
}

// New returns a fresh adapter for engine, or false if none is registered.
func New(engine string) (Adapter, bool) {
	regMu.RLock()
	f, ok := registry[engine]
	regMu.RUnlock()
	if !ok {
		return nil, false
	}
	return f(), true
}

// Engines lists registered engines, sorted.
func Engines() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registry))
	for e := range registry {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// ConnectionAuditor is the optional role+window audit collector (DB-04-03). An
// adapter without it reports the connection basis as unsupported.
type ConnectionAuditor interface {
	CollectConnections(ctx context.Context, q AuditQuery) ([]AuditEvent, error)
}

// PrivilegedConnector is optionally implemented by an adapter that can open a
// second, privileged lab session for fixture Seed and Cleanup while the probe
// runs on the restricted connection. Lab mode only.
type PrivilegedConnector interface {
	ConnectPrivileged(ctx context.Context, cfg ConnectionConfig) error
}
