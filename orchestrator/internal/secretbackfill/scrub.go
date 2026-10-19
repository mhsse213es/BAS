// Package secretbackfill applies the secret scrub to rows stored before the
// write-time fix. It is pure: callers supply the JSON and get back the JSON, so
// the database work stays in cmd/secretbackfill and the transform stays testable.
package secretbackfill

import (
	"encoding/json"

	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/models"
)

// ScrubResults scrubs the fields the read path scrubs: RawOutput, Details, and
// each DetectionAlert's CommandLine. It returns the original bytes and changed=false
// when nothing needs scrubbing, so clean rows are never rewritten.
func ScrubResults(raw []byte) ([]byte, bool, error) {
	var results []models.SimulationResult
	if err := json.Unmarshal(raw, &results); err != nil {
		return raw, false, err
	}
	changed := false
	for i := range results {
		r := &results[i]
		if v := models.WithholdSecrets(r.RawOutput); v != r.RawOutput {
			r.RawOutput, changed = v, true
		}
		if v := models.WithholdSecrets(r.Details); v != r.Details {
			r.Details, changed = v, true
		}
		if r.DetectionAlert != nil {
			if v := models.WithholdSecrets(r.DetectionAlert.CommandLine); v != r.DetectionAlert.CommandLine {
				r.DetectionAlert.CommandLine, changed = v, true
			}
		}
	}
	if !changed {
		return raw, false, nil
	}
	out, err := json.Marshal(results)
	if err != nil {
		return raw, false, err
	}
	return out, true, nil
}

// ScrubAlerts scrubs the command line of each stored detection alert
// (detections_raw). Same contract as ScrubResults.
func ScrubAlerts(raw []byte) ([]byte, bool, error) {
	var alerts []detect.AlertRecord
	if err := json.Unmarshal(raw, &alerts); err != nil {
		return raw, false, err
	}
	changed := false
	for i := range alerts {
		if v := models.WithholdSecrets(alerts[i].CommandLine); v != alerts[i].CommandLine {
			alerts[i].CommandLine, changed = v, true
		}
	}
	if !changed {
		return raw, false, nil
	}
	out, err := json.Marshal(alerts)
	if err != nil {
		return raw, false, err
	}
	return out, true, nil
}
