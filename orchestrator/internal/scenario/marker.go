package scenario

import (
	"fmt"
	"regexp"
	"strings"
)

// markerPattern admits only characters that survive every executor's quoting, so the
// token reaches a process command line unchanged.
var markerPattern = regexp.MustCompile(`^[a-z0-9-]{8,40}$`)

// ValidateMarkers checks the marker on each step. Format must match markerPattern.
// The marker must appear literally in the step's command, so a step cannot claim
// evidence it never produces. No two steps in one scenario may share a marker.
func (s *Scenario) ValidateMarkers() error {
	seen := map[string]int{}
	for i, st := range s.Steps {
		if st.Marker == "" {
			continue
		}
		if !markerPattern.MatchString(st.Marker) {
			return fmt.Errorf("step %d marker %q must be 8-40 characters from a-z, 0-9 and hyphen", i+1, st.Marker)
		}
		if !strings.Contains(st.Command, st.Marker) {
			return fmt.Errorf("step %d marker %q does not appear in its command", i+1, st.Marker)
		}
		if first, dup := seen[st.Marker]; dup {
			return fmt.Errorf("marker %q is used by more than one step (steps %d and %d)", st.Marker, first, i+1)
		}
		seen[st.Marker] = i + 1
	}
	return nil
}

// MarkerRefusal names a scenario whose marker is already claimed by an earlier one.
type MarkerRefusal struct {
	ID     string
	Reason string
}

// CheckMarkerUniqueness returns every scenario that reuses a marker claimed by an
// earlier scenario in the slice. The first claim keeps the marker.
func CheckMarkerUniqueness(scenarios []*Scenario) []MarkerRefusal {
	owner := map[string]string{}
	var refused []MarkerRefusal
	for _, sc := range scenarios {
		for _, st := range sc.Steps {
			if st.Marker == "" {
				continue
			}
			if prev, ok := owner[st.Marker]; ok && prev != sc.ID {
				refused = append(refused, MarkerRefusal{ID: sc.ID,
					Reason: fmt.Sprintf("marker %q is already claimed by %s", st.Marker, prev)})
				break
			}
			owner[st.Marker] = sc.ID
		}
	}
	return refused
}
