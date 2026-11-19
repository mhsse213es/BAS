package riskinputs

import "github.com/audspect/bas/internal/riskquant"

// OpenFinding is a technique that is an open finding in the report being generated.
type OpenFinding struct {
	TechniqueID string
	Label       string
}

// ExposuresForReport returns one exposure per distinct open finding, in the order the findings were
// given. Each carries its stored input when there is one, and is unquantified otherwise. Stored inputs
// for techniques that are not open are not included, so an old input cannot move a report's figure.
func ExposuresForReport(open []OpenFinding, inputs []Input) []riskquant.Exposure {
	byTech := make(map[string]Input, len(inputs))
	for _, in := range inputs {
		byTech[in.TechniqueID] = in
	}
	seen := make(map[string]bool, len(open))
	var out []riskquant.Exposure
	for _, f := range open {
		if f.TechniqueID == "" || seen[f.TechniqueID] {
			continue
		}
		seen[f.TechniqueID] = true
		e := riskquant.Exposure{ID: f.TechniqueID, Label: f.Label}
		if in, ok := byTech[f.TechniqueID]; ok {
			freq, mag := in.Frequency, in.Magnitude
			e.Label = in.Label
			e.Frequency = &freq
			e.Magnitude = &mag
		}
		out = append(out, e)
	}
	return out
}

// AnyInput reports whether at least one exposure has inputs. A report with none shows no loss figure.
func AnyInput(exposures []riskquant.Exposure) bool {
	for _, e := range exposures {
		if e.Frequency != nil && e.Magnitude != nil {
			return true
		}
	}
	return false
}
