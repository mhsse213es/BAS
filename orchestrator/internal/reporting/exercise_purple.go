package reporting

import (
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/verification"
)

// PurpleDebrief is the blue-team half of a purple-team exercise: for the attacks the exercise ran, what the defenders
// detected, what they missed, and what nobody has judged yet. It is built only from attestations in the verification
// store; a technique with no attestation is reported as such, never as detected or missed.
type PurpleDebrief struct {
	Techniques []PurpleTechnique `json:"techniques"`
	Detected   int               `json:"detected"`
	Missed     int               `json:"missed"`
	Unresolved int               `json:"unresolved"` // expectations awaiting an approved verdict
	// DetectionRate is Detected over Detected+Missed, as a percentage. Nil when nothing has been resolved, so an
	// exercise nobody has judged yet shows no rate rather than 0% or 100%.
	DetectionRate *float64 `json:"detectionRate"`
	// NoExpectation lists techniques the template says the exercise exercises but for which no detection expectation
	// was recorded: a coverage hole in the exercise itself, not a SOC result.
	NoExpectation     []string `json:"noExpectation,omitempty"`
	Gaps              []string `json:"gaps,omitempty"` // missed detections, as lines a SOC can act on
	SuccessCriteria   string   `json:"successCriteria,omitempty"`
	DiscussionPrompts []string `json:"discussionPrompts,omitempty"`
}

// PurpleTechnique is one technique's detection outcome across the exercise's BAS runs.
type PurpleTechnique struct {
	TechniqueID string   `json:"techniqueId"`
	Detected    int      `json:"detected"`
	Missed      int      `json:"missed"`
	Unresolved  int      `json:"unresolved"`
	Providers   []string `json:"providers,omitempty"`
	Outcome     string   `json:"outcome"` // detected | missed | partial | unresolved
}

// BuildPurpleDebrief folds verification records (from every BAS run the exercise started) into the debrief.
// Only Approved records with a Detected or NotDetected result are resolved; NotApplicable is left out; the rest is
// unresolved.
func BuildPurpleDebrief(records []verification.Record, meta exercise.TemplateMetadata) *PurpleDebrief {
	d := &PurpleDebrief{SuccessCriteria: meta.SuccessCriteria, DiscussionPrompts: meta.DiscussionPrompts, Techniques: []PurpleTechnique{}}
	by := map[string]*PurpleTechnique{}
	provs := map[string]map[string]bool{}
	for _, r := range records {
		if r.Result == verification.ResultNotApplicable {
			continue
		}
		t := by[r.TechniqueID]
		if t == nil {
			t = &PurpleTechnique{TechniqueID: r.TechniqueID}
			by[r.TechniqueID] = t
			provs[r.TechniqueID] = map[string]bool{}
		}
		if r.Provider != "" {
			provs[r.TechniqueID][r.Provider] = true
		}
		switch {
		case r.WorkflowState != verification.StateApproved:
			t.Unresolved++
		case r.Result == verification.ResultDetected:
			t.Detected++
		case r.Result == verification.ResultNotDetected:
			t.Missed++
			d.Gaps = append(d.Gaps, r.TechniqueID+": "+gapWho(r)+" did not detect it")
		default:
			t.Unresolved++
		}
	}
	for id, t := range by {
		for p := range provs[id] {
			t.Providers = append(t.Providers, p)
		}
		sort.Strings(t.Providers)
		switch {
		case t.Detected > 0 && t.Missed == 0 && t.Unresolved == 0:
			t.Outcome = "detected"
		case t.Missed > 0 && t.Detected == 0 && t.Unresolved == 0:
			t.Outcome = "missed"
		case t.Detected == 0 && t.Missed == 0:
			t.Outcome = "unresolved"
		default:
			t.Outcome = "partial"
		}
		d.Detected += t.Detected
		d.Missed += t.Missed
		d.Unresolved += t.Unresolved
		d.Techniques = append(d.Techniques, *t)
	}
	sort.Slice(d.Techniques, func(i, j int) bool { return d.Techniques[i].TechniqueID < d.Techniques[j].TechniqueID })
	sort.Strings(d.Gaps)
	if n := d.Detected + d.Missed; n > 0 {
		v := float64(d.Detected) * 100 / float64(n)
		d.DetectionRate = &v
	}
	for _, id := range meta.ExpectedTechniques {
		if by[id] == nil {
			d.NoExpectation = append(d.NoExpectation, id)
		}
	}
	return d
}

func gapWho(r verification.Record) string {
	if r.Provider != "" {
		return r.Provider
	}
	return "the " + r.Domain + " control"
}

// RateLabel is the detection rate as text, or an explicit "not yet judged" when nothing is resolved.
func (d *PurpleDebrief) RateLabel() string {
	if d == nil || d.DetectionRate == nil {
		return "Not yet judged"
	}
	return fmt.Sprintf("%.0f%% (%d of %d)", *d.DetectionRate, d.Detected, d.Detected+d.Missed)
}
