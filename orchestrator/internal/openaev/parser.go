package openaev

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// scenarioEntryComment is how OpenAEV's own export marks the ZIP entry that
// holds the scenario JSON — see openaev-api's ImportService.EXPORT_ENTRY_SCENARIO.
// The entry's FILENAME varies (it's "<scenarioName>.json"), so this comment is
// the only reliable way to find it.
const scenarioEntryComment = "Scenario"

// ParseBundle decodes a raw OpenAEV scenario export ZIP (as returned by
// GET /api/scenarios/{id}/export, or an air-gapped manual upload of the same
// format) into a ParsedBundle. It does not touch the database.
func ParseBundle(data []byte) (*ParsedBundle, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a valid bundle ZIP: %w", err)
	}

	var scenarioFile *zip.File
	for _, f := range zr.File {
		if f.Comment == scenarioEntryComment {
			scenarioFile = f
			break
		}
	}
	if scenarioFile == nil {
		return nil, fmt.Errorf("bundle has no entry commented %q — not a valid OpenAEV scenario export", scenarioEntryComment)
	}

	rc, err := scenarioFile.Open()
	if err != nil {
		return nil, fmt.Errorf("open scenario entry: %w", err)
	}
	defer rc.Close()

	var parsed ParsedBundle
	if err := json.NewDecoder(rc).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode scenario JSON: %w", err)
	}
	return &parsed, nil
}

// exerciseEntryComment is how OpenAEV's own export marks the ZIP entry that
// holds the exercise JSON — see openaev-api's ImportService.EXPORT_ENTRY_EXERCISE
// ("Exercise"). Mirrors scenarioEntryComment above for the Scenario case.
const exerciseEntryComment = "Exercise"

// parsedExerciseItem is Exercise's own top-level fields (openaev-main's
// Exercise.java, JSON-tagged exercise_id/exercise_name/...) -- the Exercise
// equivalent of ParsedScenario. Kept separate because the tag prefix
// ("exercise_" vs "scenario_") differs; the VALUES map 1:1 onto ParsedScenario.
type parsedExerciseItem struct {
	ID          string    `json:"exercise_id"`
	Name        string    `json:"exercise_name"`
	Description string    `json:"exercise_description"`
	Category    string    `json:"exercise_category"`
	Severity    string    `json:"exercise_severity"`
	UpdatedAt   time.Time `json:"exercise_updated_at"`
}

// parsedExerciseManifest is the decoded contents of one OpenAEV Exercise
// export ZIP entry. Objectives/Injects/Tags/Variables reuse ParsedBundle's
// nested types unchanged -- OpenAEV's Objective/Inject/Tag/Variable are the
// same Java model classes (and therefore the same JSON field names) in both
// a Scenario export and an Exercise export; only the wrapper key prefix and
// the top-level item's own fields differ.
type parsedExerciseManifest struct {
	ExportVersion int                `json:"export_version"`
	Exercise      parsedExerciseItem `json:"exercise_information"`
	Objectives    []ParsedObjective  `json:"exercise_objectives"`
	Injects       []ParsedInject     `json:"exercise_injects"`
	Tags          []ParsedTag        `json:"exercise_tags"`
	Variables     []ParsedVariable   `json:"exercise_variables"`
}

// ParseExerciseBundle decodes a raw OpenAEV EXERCISE export ZIP (as returned
// by GET /api/exercises/{id}/export) into the same ParsedBundle shape
// ParseBundle produces for Scenarios, so every downstream step (Normalize,
// Upsert, the Importer) needs no knowledge that this content originated
// from an Exercise rather than a Scenario. SourceType is stamped "exercise"
// so Normalize can carry it through to the stored row (see types.go).
func ParseExerciseBundle(data []byte) (*ParsedBundle, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a valid bundle ZIP: %w", err)
	}

	var entry *zip.File
	for _, f := range zr.File {
		if f.Comment == exerciseEntryComment {
			entry = f
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("bundle has no entry commented %q — not a valid OpenAEV exercise export", exerciseEntryComment)
	}

	rc, err := entry.Open()
	if err != nil {
		return nil, fmt.Errorf("open exercise entry: %w", err)
	}
	defer rc.Close()

	var m parsedExerciseManifest
	if err := json.NewDecoder(rc).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode exercise JSON: %w", err)
	}

	return &ParsedBundle{
		ExportVersion: m.ExportVersion,
		SourceType:    "exercise",
		Scenario: ParsedScenario{
			ID:          m.Exercise.ID,
			Name:        m.Exercise.Name,
			Description: m.Exercise.Description,
			Category:    m.Exercise.Category,
			Severity:    m.Exercise.Severity,
			UpdatedAt:   m.Exercise.UpdatedAt,
		},
		Objectives: m.Objectives,
		Injects:    m.Injects,
		Tags:       m.Tags,
		Variables:  m.Variables,
	}, nil
}

// marshalAsScenarioZip re-encodes an already-normalized ParsedBundle
// (regardless of its original source) as a synthetic in-memory ZIP with one
// entry commented "Scenario" — exactly the wire format ParseBundle already
// knows how to decode. This lets a non-Scenario source (the Exercise
// provider, see provider_rest_exercise.go) hand its content back through the
// existing Fetch -> ParseBundle -> Normalize -> Upsert pipeline unchanged.
func marshalAsScenarioZip(b *ParsedBundle) ([]byte, error) {
	jsonBytes, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("marshal synthetic scenario bundle: %w", err)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: b.Scenario.ID + ".json", Method: zip.Deflate}
	hdr.Comment = scenarioEntryComment
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(jsonBytes); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
