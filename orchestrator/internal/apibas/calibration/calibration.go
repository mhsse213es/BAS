// Package calibration stores versioned timing calibration records.
//
// A record is written once. Recalibration creates the next version and names the
// version it supersedes, so the earlier record stays on disk. A scenario declares
// the version it runs under, and the runner refuses to grade timing unless the
// declared thresholds exactly match that record. Nothing here widens a threshold.
package calibration

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

//go:embed records
var recordFS embed.FS

// Thresholds is the full set of values a timing grade depends on. A scenario's
// declared policy must equal its record's thresholds field for field.
type Thresholds struct {
	DeclaredBaselineMs float64 `json:"declared_baseline_ms"`
	Tolerance          float64 `json:"tolerance"`
	CeilingMs          float64 `json:"ceiling_ms"`
	MinRatio           float64 `json:"min_ratio"`
	MaxCV              float64 `json:"max_cv"`
	AttackMaxMs        float64 `json:"attack_max_ms"`
	NoiseFloorMs       float64 `json:"noise_floor_ms"`
	Warmup             int     `json:"warmup"`
	Trials             int     `json:"trials"`
	Rounds             int     `json:"rounds"`
}

// Profile describes the machine and runtime a calibration was measured on.
type Profile struct {
	Machine   string `json:"machine"` // operator label, required
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	NumCPU    int    `json:"num_cpu"`
	GoVersion string `json:"go_version"`
}

// Record is one calibration version for one scenario.
type Record struct {
	ScenarioID  string     `json:"scenario_id"`
	Version     int        `json:"version"`
	Supersedes  int        `json:"supersedes"` // 0 for the first version
	Profile     Profile    `json:"profile"`
	Workload    string     `json:"workload"`
	SampleCount int        `json:"sample_count"` // baseline samples per round, summed over rounds
	Measured    Measured   `json:"measured"`
	Thresholds  Thresholds `json:"thresholds"`
}

// Measured holds the raw baseline statistics from the calibration run.
type Measured struct {
	BaselineMedianMs float64 `json:"baseline_median_ms"`
	BaselineP95Ms    float64 `json:"baseline_p95_ms"`
	BaselineCV       float64 `json:"baseline_cv"`
}

var fileName = regexp.MustCompile(`^([A-Z0-9-]+)\.v([0-9]+)\.json$`)

// Get returns one embedded record. It fails when the record is missing or does not
// match its own file name.
func Get(scenarioID string, version int) (Record, error) {
	name := fmt.Sprintf("records/%s.v%d.json", scenarioID, version)
	raw, err := recordFS.ReadFile(name)
	if err != nil {
		return Record{}, fmt.Errorf("calibration: no record %s", name)
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Record{}, fmt.Errorf("calibration: %s: %w", name, err)
	}
	if rec.ScenarioID != scenarioID || rec.Version != version {
		return Record{}, fmt.Errorf("calibration: %s does not describe %s v%d", name, scenarioID, version)
	}
	return rec, nil
}

// NextVersion returns the version a new record for scenarioID must carry: one more
// than the highest version already in dir, or 1 when none exists.
func NextVersion(dir, scenarioID string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	highest := 0
	for _, e := range entries {
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil || m[1] != scenarioID {
			continue
		}
		v, _ := strconv.Atoi(m[2])
		if v > highest {
			highest = v
		}
	}
	return highest + 1, nil
}

// Write stores a new record in dir. It refuses to overwrite: the file is created
// exclusively, and the record must carry the next version and supersede the one
// before it. The path of the written file is returned.
func Write(dir string, rec Record) (string, error) {
	if rec.Profile.Machine == "" {
		return "", errors.New("calibration: a machine label is required")
	}
	want, err := NextVersion(dir, rec.ScenarioID)
	if err != nil {
		return "", err
	}
	if rec.Version != want {
		return "", fmt.Errorf("calibration: %s must be version %d, got %d", rec.ScenarioID, want, rec.Version)
	}
	if rec.Supersedes != want-1 {
		return "", fmt.Errorf("calibration: version %d must supersede %d", want, want-1)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("%s.v%d.json", rec.ScenarioID, rec.Version))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", fmt.Errorf("calibration: %s already exists: %w", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rec); err != nil {
		return "", err
	}
	return path, nil
}
