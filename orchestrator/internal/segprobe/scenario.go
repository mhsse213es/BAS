package segprobe

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type Zone string

const (
	ZoneCorp  Zone = "corp"
	ZoneSWIFT Zone = "swift"
	ZoneCDE   Zone = "cde"
	ZoneATM   Zone = "atm"
	ZoneApp   Zone = "app"
	ZoneDB    Zone = "db"
)

var knownZones = map[Zone]bool{
	ZoneCorp: true, ZoneSWIFT: true, ZoneCDE: true,
	ZoneATM: true, ZoneApp: true, ZoneDB: true,
}

type ProbeSpec struct {
	ID      string `yaml:"id"`
	Src     Zone   `yaml:"src"`
	Dst     Zone   `yaml:"dst"`
	DstPort int    `yaml:"port"`
	Proto   string `yaml:"proto"`
	Expect  Expect `yaml:"expect"`
	Note    string `yaml:"note"`
}

type Scenario struct {
	ID     string      `yaml:"id"`
	Name   string      `yaml:"name"`
	Probes []ProbeSpec `yaml:"probes"`
}

// LoadScenario parses and validates a scenario. Same-zone probes are allowed
// only when they expect allow: they are positive controls that never cross
// the firewall. A same-zone deny has no meaning and is rejected.
func LoadScenario(data []byte) (Scenario, error) {
	var s Scenario
	if err := yaml.Unmarshal(data, &s); err != nil {
		return Scenario{}, fmt.Errorf("parse scenario: %w", err)
	}
	if err := s.validate(); err != nil {
		return Scenario{}, err
	}
	return s, nil
}

func (s Scenario) validate() error {
	if s.ID == "" {
		return fmt.Errorf("scenario id is required")
	}
	if len(s.Probes) == 0 {
		return fmt.Errorf("scenario %s has no probes", s.ID)
	}
	seen := map[string]bool{}
	for _, p := range s.Probes {
		if p.ID == "" {
			return fmt.Errorf("scenario %s: probe id is required", s.ID)
		}
		if seen[p.ID] {
			return fmt.Errorf("scenario %s: duplicate probe id %q", s.ID, p.ID)
		}
		seen[p.ID] = true
		if !knownZones[p.Src] {
			return fmt.Errorf("probe %s: unknown source zone %q", p.ID, p.Src)
		}
		if !knownZones[p.Dst] {
			return fmt.Errorf("probe %s: unknown destination zone %q", p.ID, p.Dst)
		}
		if p.Src == p.Dst && p.Expect != ExpectAllow {
			return fmt.Errorf("probe %s: same-zone probe must expect allow", p.ID)
		}
		if p.Expect != ExpectAllow && p.Expect != ExpectDeny {
			return fmt.Errorf("probe %s: expect must be allow or deny, got %q", p.ID, p.Expect)
		}
		if p.Proto != "tcp" {
			return fmt.Errorf("probe %s: proto must be tcp, got %q", p.ID, p.Proto)
		}
		if p.DstPort < 1 || p.DstPort > 65535 {
			return fmt.Errorf("probe %s: port %d out of range", p.ID, p.DstPort)
		}
	}
	return nil
}
