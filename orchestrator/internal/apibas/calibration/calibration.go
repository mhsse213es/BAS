// Package calibration stores versioned, self-verifying timing calibration records.
//
// A record characterises one machine for one timing scenario. It holds the raw baseline
// and attack samples of the vulnerable and fixed builds, measured interleaved under the
// same workload, together with the qualification verdict computed from them. Records are
// write-once. Get recomputes the verdict from the stored samples, so an edited record
// fails its integrity check.
//
// Calibration characterises the environment against the declared policy. It never
// changes the policy. A record's thresholds must match the scenario's declared values
// exactly, or timing is refused.
package calibration

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/audspect/bas/internal/apibas/latency"
)

//go:embed records
var recordFS embed.FS

// ErrMissing means no record exists for the requested version.
var ErrMissing = errors.New("calibration record missing")

// ErrIntegrity means a record exists but its stored verdict does not follow from its
// stored samples and thresholds, or it does not describe the requested scenario.
var ErrIntegrity = errors.New("calibration record failed its integrity check")

// Thresholds is every declared value a qualification or timing grade depends on. A
// scenario's declared policy must equal its record's thresholds field for field.
type Thresholds struct {
	DeclaredBaselineMs float64 `json:"declared_baseline_ms"`
	Tolerance          float64 `json:"tolerance"`
	CeilingMs          float64 `json:"ceiling_ms"`
	MinRatio           float64 `json:"min_ratio"`
	MaxCV              float64 `json:"max_cv"`
	AttackMaxMs        float64 `json:"attack_max_ms"`
	NoiseFloorMs       float64 `json:"noise_floor_ms"`
	Alpha              float64 `json:"alpha"`
	MinSeparationRatio float64 `json:"min_separation_ratio"`
	Warmup             int     `json:"warmup"`
	Trials             int     `json:"trials"`
	Rounds             int     `json:"rounds"`
}

// Profile identifies the machine and runtime a record was measured on. A change to any
// field means the environment has changed and the record must be requalified.
type Profile struct {
	Machine   string `json:"machine"` // operator-asserted label, required
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	NumCPU    int    `json:"num_cpu"`
	GoVersion string `json:"go_version"`
}

// CurrentProfile returns the profile of the running process under a machine label.
func CurrentProfile(machine string) Profile {
	return Profile{Machine: machine, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU(), GoVersion: runtime.Version()}
}

// Matches reports whether two profiles describe the same environment.
func (p Profile) Matches(o Profile) bool {
	return p == o
}

// RoundSamples holds one round's raw samples in milliseconds.
type RoundSamples struct {
	BaselineMs []float64 `json:"baseline_ms"`
	AttackMs   []float64 `json:"attack_ms"`
}

// Build is the measurement of one build: its rounds and the resource use the lab
// reported for its attack responses.
type Build struct {
	Rounds       []RoundSamples `json:"rounds"`
	WorkUnitsMax int            `json:"work_units_max"`
}

// Separation is the vulnerable-versus-fixed comparison recorded with the verdict.
type Separation struct {
	P             float64 `json:"p_value"`
	Ratio         float64 `json:"ratio"`
	VulnMedianMs  float64 `json:"vulnerable_median_ms"`
	FixedMedianMs float64 `json:"fixed_median_ms"`
}

// Record is one calibration version for one scenario.
type Record struct {
	ScenarioID           string     `json:"scenario_id"`
	Version              int        `json:"version"`
	Supersedes           int        `json:"supersedes"` // 0 for the first version
	Profile              Profile    `json:"profile"`
	Workload             string     `json:"workload"`
	Thresholds           Thresholds `json:"thresholds"`
	Vulnerable           Build      `json:"vulnerable"`
	Fixed                Build      `json:"fixed"`
	Qualified            bool       `json:"qualified"`
	QualificationReasons []string   `json:"qualification_reasons"`
	Separation           Separation `json:"separation"`
}

var fileName = regexp.MustCompile(`^([A-Z0-9-]+)\.v([0-9]+)\.json$`)

// Evaluate qualifies the given samples against the thresholds. It is the single
// definition of the verdict, used both when a record is written and when it is read.
func Evaluate(th Thresholds, vuln, fixed []RoundSamples) latency.Qualification {
	return latency.Qualify(policyFor(th), toRounds(vuln), toRounds(fixed))
}

func policyFor(th Thresholds) latency.QualifyPolicy {
	return latency.QualifyPolicy{
		Policy: latency.Policy{
			CeilingMs:    th.CeilingMs,
			MinRatio:     th.MinRatio,
			MaxCV:        th.MaxCV,
			MinSamples:   th.Trials,
			BaselineMs:   th.DeclaredBaselineMs,
			Tolerance:    th.Tolerance,
			AttackMaxMs:  th.AttackMaxMs,
			NoiseFloorMs: th.NoiseFloorMs,
		},
		Alpha:              th.Alpha,
		MinSeparationRatio: th.MinSeparationRatio,
	}
}

func toRounds(rs []RoundSamples) []latency.Round {
	out := make([]latency.Round, 0, len(rs))
	for _, r := range rs {
		out = append(out, latency.Round{Baseline: toDurations(r.BaselineMs), Attack: toDurations(r.AttackMs)})
	}
	return out
}

func toDurations(ms []float64) []time.Duration {
	out := make([]time.Duration, len(ms))
	for i, v := range ms {
		out[i] = time.Duration(v * float64(time.Millisecond))
	}
	return out
}

// Verify recomputes the verdict from the stored samples and thresholds and compares it
// with the stored verdict. Any difference is an integrity failure.
func Verify(rec Record) error {
	// Records written before the two-build model carry no samples. They can only be
	// unqualified; a qualified verdict with no samples cannot be checked, so it is refused.
	if len(rec.Vulnerable.Rounds) == 0 && len(rec.Fixed.Rounds) == 0 {
		if rec.Qualified {
			return fmt.Errorf("%w: qualified verdict has no samples to check it against", ErrIntegrity)
		}
		return nil
	}
	q := Evaluate(rec.Thresholds, rec.Vulnerable.Rounds, rec.Fixed.Rounds)
	if q.Qualified != rec.Qualified || !slices.Equal(q.Reasons, rec.QualificationReasons) {
		return fmt.Errorf("%w: stored verdict %v does not follow from the samples", ErrIntegrity, rec.Qualified)
	}
	if math.Abs(q.P-rec.Separation.P) > 1e-9 {
		return fmt.Errorf("%w: stored p-value %g differs from recomputed %g", ErrIntegrity, rec.Separation.P, q.P)
	}
	if math.Abs(q.Ratio-rec.Separation.Ratio) > 1e-9*math.Max(1, math.Abs(q.Ratio)) {
		return fmt.Errorf("%w: stored ratio %g differs from recomputed %g", ErrIntegrity, rec.Separation.Ratio, q.Ratio)
	}
	return nil
}

// Get returns one embedded record after checking that it describes the requested
// scenario and version and that its verdict follows from its samples.
func Get(scenarioID string, version int) (Record, error) {
	name := fmt.Sprintf("records/%s.v%d.json", scenarioID, version)
	raw, err := recordFS.ReadFile(name)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %s", ErrMissing, name)
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Record{}, fmt.Errorf("%w: %s: %v", ErrIntegrity, name, err)
	}
	if rec.ScenarioID != scenarioID || rec.Version != version {
		return Record{}, fmt.Errorf("%w: %s does not describe %s v%d", ErrIntegrity, name, scenarioID, version)
	}
	if err := Verify(rec); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// NextVersion returns the version a new record must carry: one more than the highest
// version in dir, or 1 when none exists.
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

// Write stores a new record in dir. It refuses records that fail their own integrity
// check, that lack a machine label, or that do not carry the next version. Files are
// created exclusively, so an existing version is never overwritten.
func Write(dir string, rec Record) (string, error) {
	if rec.Profile.Machine == "" {
		return "", errors.New("calibration: a machine label is required")
	}
	if err := Verify(rec); err != nil {
		return "", err
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
	// Marshal before creating the file, so a record that cannot be encoded leaves nothing behind.
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", fmt.Errorf("calibration: cannot encode record: %w", err)
	}
	path := filepath.Join(dir, fmt.Sprintf("%s.v%d.json", rec.ScenarioID, rec.Version))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return "", fmt.Errorf("calibration: %s already exists: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(append(body, '\n')); err != nil {
		return "", err
	}
	return path, nil
}
