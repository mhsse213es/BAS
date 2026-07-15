package openaev

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
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
