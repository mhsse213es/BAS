package otsafety

import (
	"fmt"

	"github.com/audspect/bas/internal/networktopology"
)

// ActiveTestAuthorization is the per-request authorization a caller
// must supply when any named target resolves into a declared
// SensitiveZone. Authorized alone is not sufficient -- SignOff must
// also be non-empty, mirroring every other "Limitations must be
// non-empty" discipline in this initiative.
type ActiveTestAuthorization struct {
	Authorized bool   `json:"authorized"`
	SignOff    string `json:"signOff,omitempty"`
}

// CheckActiveTestAuthorization resolves each target host to a zone
// via networktopology.ZoneForHost (reused, unmodified). If any
// resolved zone matches a SensitiveZone.ZoneName in safety, auth must
// have Authorized == true and a non-empty SignOff, or an error naming
// every matching sensitive zone is returned. matchedZones reports
// exactly which sensitive zones were found among the targets --
// empty with a nil error means nothing was gated at all (no target
// touched a declared-sensitive zone), which the caller (Task 6) uses
// to decide whether an authorization was actually exercised and worth
// an audit-log entry, as distinct from merely supplied. A target that
// does not resolve to any known zone at all, or resolves to a zone
// absent from safety.SensitiveZones, is never gated -- this only ever
// fails closed where there is positive evidence of OT-zone
// membership, never as a blanket new requirement on every caller.
func CheckActiveTestAuthorization(targetHosts []string, topo *networktopology.TopologyImport, safety *OTSafetyImport, auth *ActiveTestAuthorization) (matchedZones []string, err error) {
	sensitive := make(map[string]bool, len(safety.SensitiveZones))
	for _, sz := range safety.SensitiveZones {
		sensitive[sz.ZoneName] = true
	}

	seen := make(map[string]bool)
	for _, host := range targetHosts {
		zone, resolveErr := networktopology.ZoneForHost(host, topo.Zones)
		if resolveErr != nil {
			continue // unresolvable target -- fails open, never gated
		}
		if sensitive[zone] && !seen[zone] {
			seen[zone] = true
			matchedZones = append(matchedZones, zone)
		}
	}

	if len(matchedZones) == 0 {
		return nil, nil
	}
	if auth == nil || !auth.Authorized || auth.SignOff == "" {
		return nil, fmt.Errorf("explicit active-test authorization (with a non-empty sign-off) is required: target(s) resolve to declared sensitive zone(s) %v", matchedZones)
	}
	return matchedZones, nil
}
