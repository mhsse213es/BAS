package scenario

import (
	"context"
	"errors"
)

// IntakeFile is one scenario YAML found on disk, handed to the content
// registry (TCF Phase 1 spec §5.1). Signature is the raw decoded RSA
// signature; SignatureVerified is true only after a real verification.
type IntakeFile struct {
	Path              string
	Source            string // builtin | custom | intel
	Artifact          []byte
	Signature         []byte
	SignatureVerified bool
}

type IntakeDecision struct {
	Accepted bool
	Reason   string
}

// ExecutableVersion is the runtime gate's answer: an immutable version that
// passed origin/trust/lifecycle checks, parsed from stored bytes.
type ExecutableVersion struct {
	VersionID string
	ContentID string
	Version   int
	Origin    string
	Trust     string
	Lifecycle string
	Scenario  *Scenario
}

// ContentRegistry is implemented by internal/contentregistry. Declared here
// so the engine can call it without an import cycle.
type ContentRegistry interface {
	Intake(ctx context.Context, f IntakeFile) (IntakeDecision, error)
	NoteRefusal(path, contentID, reason string)
	RegisterLocalApproved(ctx context.Context, contentID string, artifact []byte, actor string) error
	RetireExecutable(ctx context.Context, contentID, actor, reason string) error
	ResolveExecutable(ctx context.Context, contentID string) (ExecutableVersion, error)
}

// ErrNoRegistry is returned by Engine.ResolveExecutable when no registry is
// attached: fail closed, never fall back to the disk map.
var ErrNoRegistry = errors.New("content registry not attached")
