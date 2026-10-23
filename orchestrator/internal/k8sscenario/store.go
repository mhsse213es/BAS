package k8sscenario

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Approval is one operator's approval for exactly one run. It is bound to the run, cluster, namespace, action
// and a hash of the parameters, so it cannot be reused for anything else.
type Approval struct {
	ID          string
	ApproverID  string
	RequesterID string
	RunID       string
	Cluster     string
	Namespace   string
	ActionID    string
	ParamsHash  string
	ExpiresAt   time.Time
	Used        bool
}

// ApprovalStore holds approvals. MarkUsed must be atomic: an approval can be consumed once.
type ApprovalStore interface {
	Get(id string) (Approval, bool, error)
	MarkUsed(id string) error
}

// HashParams returns a stable hash of the parameters, so an approval covers one exact set of values.
func HashParams(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(params[k])
		b.WriteString("\n")
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// memApprovals is an in-memory store for tests and single-process use.
type memApprovals struct {
	mu sync.Mutex
	m  map[string]Approval
}

func newMemApprovals() *memApprovals { return &memApprovals{m: map[string]Approval{}} }

// Put stores an approval as unused.
func (s *memApprovals) Put(a Approval) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a.Used = false
	s.m[a.ID] = a
	return nil
}

func (s *memApprovals) Get(id string) (Approval, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	return a, ok, nil
}

// MarkUsed consumes an approval. It fails if the approval is missing or already used.
func (s *memApprovals) MarkUsed(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.m[id]
	if !ok {
		return errors.New("approval not found")
	}
	if a.Used {
		return errors.New("approval already used")
	}
	a.Used = true
	s.m[id] = a
	return nil
}
