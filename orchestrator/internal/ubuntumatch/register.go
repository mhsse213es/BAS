package ubuntumatch

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Status value a mapping must carry before it can produce results.
const StatusApproved = "APPROVED"

var datePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// ReleaseFix is one release's data for a mapping.
type ReleaseFix struct {
	Corresponding []string
	Fixed         []PackageFix
}

// PackageFix is one fixed-version statement, for example
// "roundcube < 1.4.3+dfsg.1-1ubuntu0.1~esm1".
type PackageFix struct {
	Package string
	Version string
}

// Mapping is one reviewed mapping row from reviewed_mappings.yaml.
type Mapping struct {
	ID                  string
	CVE                 string
	Status              string
	Curator             string
	IndependentReviewer string
	ReviewDate          string
	Releases            map[string]ReleaseFix
}

// Register is the loaded set of mappings.
type Register struct {
	Mappings []Mapping
}

type rawRegister struct {
	Mappings []rawMapping `yaml:"mappings"`
}

type rawMapping struct {
	ID                  string    `yaml:"id"`
	CVE                 string    `yaml:"cve"`
	Status              string    `yaml:"status"`
	Curator             string    `yaml:"curator"`
	IndependentReviewer string    `yaml:"independent_reviewer"`
	ReviewDate          string    `yaml:"review_date"`
	FixedVersions       yaml.Node `yaml:"fixed_versions"`
}

// LoadRegister reads a reviewed_mappings.yaml file. Malformed fixed-version
// statements are an error. Rows whose fixed_versions is not a mapping (for
// example the open items, which carry "none") load with no releases.
func LoadRegister(path string) (*Register, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw rawRegister
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	reg := &Register{}
	for _, rm := range raw.Mappings {
		m := Mapping{
			ID: rm.ID, CVE: rm.CVE, Status: rm.Status, Curator: rm.Curator,
			IndependentReviewer: rm.IndependentReviewer, ReviewDate: rm.ReviewDate,
			Releases: map[string]ReleaseFix{},
		}
		if rm.FixedVersions.Kind == yaml.MappingNode {
			var perRelease map[string]struct {
				Corresponding []string `yaml:"corresponding"`
				Fixed         []string `yaml:"fixed"`
			}
			if err := rm.FixedVersions.Decode(&perRelease); err != nil {
				return nil, fmt.Errorf("%s: fixed_versions: %w", rm.ID, err)
			}
			for rel, d := range perRelease {
				rf := ReleaseFix{Corresponding: d.Corresponding}
				for _, s := range d.Fixed {
					pf, err := parseFix(s)
					if err != nil {
						return nil, fmt.Errorf("%s %s: %w", rm.ID, rel, err)
					}
					rf.Fixed = append(rf.Fixed, pf)
				}
				m.Releases[rel] = rf
			}
		}
		reg.Mappings = append(reg.Mappings, m)
	}
	return reg, nil
}

func parseFix(s string) (PackageFix, error) {
	parts := strings.SplitN(s, " < ", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
		return PackageFix{}, fmt.Errorf("malformed fixed statement %q", s)
	}
	return PackageFix{Package: strings.TrimSpace(parts[0]), Version: strings.TrimSpace(parts[1])}, nil
}

// Eligible reports whether a mapping may produce results. All of these must hold:
//   - status is APPROVED
//   - an independent reviewer is named, is not "none...", and is not the curator
//   - the review date is a YYYY-MM-DD date
//
// Mappings that fail any check produce no results, however complete their data.
func (m Mapping) Eligible() bool {
	if m.Status != StatusApproved {
		return false
	}
	r := strings.TrimSpace(m.IndependentReviewer)
	if r == "" || strings.HasPrefix(strings.ToLower(r), "none") || r == strings.TrimSpace(m.Curator) {
		return false
	}
	return datePattern.MatchString(m.ReviewDate)
}
