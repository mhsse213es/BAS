package contentregistry

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/integrity"
)

// Refusal is one file intake refused since process start (inventory input).
type Refusal struct {
	Path      string    `json:"path"`
	ContentID string    `json:"contentId"`
	Source    string    `json:"source"` // builtin | custom | intel
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
}

// Registry implements scenario.ContentRegistry against Postgres.
type Registry struct {
	pool     *pgxpool.Pool
	verifier integrity.Verifier

	mu       sync.Mutex
	refusals []Refusal
}

func New(pool *pgxpool.Pool, v integrity.Verifier) *Registry {
	return &Registry{pool: pool, verifier: v}
}

func (r *Registry) devBuild() bool { return !r.verifier.SigningEnabled() }

// NoteRefusal records an intake refusal for the migration inventory. Keeps
// the most recent 500.
func (r *Registry) NoteRefusal(path, contentID, source, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refusals = append(r.refusals, Refusal{Path: path, ContentID: contentID, Source: source, Reason: reason, At: time.Now().UTC()})
	if len(r.refusals) > 500 {
		r.refusals = r.refusals[len(r.refusals)-500:]
	}
}

// BuiltinRefusals is the builtin-source subset of Refusals.
func (r *Registry) BuiltinRefusals() []Refusal {
	var out []Refusal
	for _, x := range r.Refusals() {
		if x.Source == string(SourceBuiltin) {
			out = append(out, x)
		}
	}
	return out
}

func (r *Registry) Refusals() []Refusal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Refusal(nil), r.refusals...)
}

// audit writes an audit_logs row synchronously (registry events are rare and
// security-relevant; losing one to a fire-and-forget goroutine is not OK).
func (r *Registry) audit(ctx context.Context, action, resource string, detail map[string]any, outcome string) {
	b, _ := json.Marshal(detail)
	if _, err := r.pool.Exec(ctx,
		`INSERT INTO audit_logs (actor_id, action, resource, detail, ip, outcome) VALUES ('', $1, $2, $3, '', $4)`,
		action, resource, b, outcome); err != nil {
		log.Printf("[contentregistry] audit %s %s: %v", action, resource, err)
	}
}
