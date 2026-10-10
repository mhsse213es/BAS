// Package adlabhyperv is the real, provider-neutral Hyper-V backing for the
// adlabrt controlled-lab substrate. This slice is lab-independent: the host
// interaction is a faked Commander seam (the real Hyper-V implementation is
// lab-gated). Topology detail lives here so the adlabrt.Substrate seam stays
// provider-neutral. See
// docs/superpowers/specs/2026-10-10-p5-ad-lab-substrate-hyperv-design.md.
package adlabhyperv

// Role is the function a lab VM performs.
type Role string

const (
	RoleDC     Role = "dc"
	RoleClient Role = "client"
	RoleADCS   Role = "adcs"
)

// VMSpec is one VM in a lab topology and its resource profile.
type VMSpec struct {
	Name           string
	Role           Role
	BaseCheckpoint string // clean, offline, prepared base to clone/revert to
	VCPU           int
	MemoryMB       int
	DiskGB         int
}

// AttackerIdentity is the controlled principal a validation case runs as, and
// the specific right it is granted. Documented, never a production principal.
type AttackerIdentity struct {
	Principal string
	Rights    string
}

// Topology is a declarative lab definition keyed by LabSpec.Name. It is the
// single place lab detail lives, so the adlabrt.Substrate seam stays
// provider-neutral.
type Topology struct {
	Name     string
	Switch   string // dedicated PRIVATE virtual switch; never External
	VMs      []VMSpec
	Attacker AttackerIdentity
}

// catalog holds the supported topologies. M1: a single self-contained DC.
var catalog = map[string]Topology{
	"dc-only": {
		Name:   "dc-only",
		Switch: "audspect-lab-private",
		VMs: []VMSpec{{
			Name:           "dc01",
			Role:           RoleDC,
			BaseCheckpoint: "dc01-base-clean",
			VCPU:           2,
			MemoryMB:       4096,
			DiskGB:         40,
		}},
		Attacker: AttackerIdentity{Principal: `LAB\attacker`, Rights: "AllExtendedRights@domain-root"},
	},
}

// LookupTopology returns the named topology; ok is false for an unknown name,
// so an unknown lab never silently resolves to an empty topology.
func LookupTopology(name string) (Topology, bool) {
	t, ok := catalog[name]
	return t, ok
}
