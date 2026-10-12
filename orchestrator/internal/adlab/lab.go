package adlab

import (
	"github.com/audspect/bas/internal/adenv"
	"github.com/audspect/bas/internal/adgate"
)

// Lab is one reproducible, controlled AD environment plus the attacker's
// starting foothold in it.
type Lab struct {
	Name        string
	Description string
	Env         adenv.Environment
	Attacker    string            // principal name present in Env.Identity — the starting foothold
	Attestation adgate.Provenance // provenance stamp; synthetic labs are stamped at origin
}

// Provider yields labs. The synthetic implementation returns deterministic
// built-in labs and a nil error; a future live-AD backend provisions real
// environments (via the SharpHound -> attackpath -> adenv.FromGraph
// pipeline) and returns them behind this same interface — hence the error
// return, which only the live backend will use.
type Provider interface {
	Labs() ([]Lab, error)
}
