package segprobe

import "testing"

const validScenario = `
id: swift-isolation
name: SWIFT isolation
probes:
  - id: corp-to-swift
    src: corp
    dst: swift
    port: 8443
    proto: tcp
    expect: deny
`

func TestLoadScenario_Valid(t *testing.T) {
	s, err := LoadScenario([]byte(validScenario))
	if err != nil {
		t.Fatalf("LoadScenario: %v", err)
	}
	if s.ID != "swift-isolation" || len(s.Probes) != 1 || s.Probes[0].Expect != ExpectDeny {
		t.Fatalf("unexpected scenario %+v", s)
	}
}

func TestLoadScenario_RejectsUnknownZone(t *testing.T) {
	bad := `
id: x
name: x
probes:
  - id: p
    src: corp
    dst: mars
    port: 80
    proto: tcp
    expect: deny
`
	if _, err := LoadScenario([]byte(bad)); err == nil {
		t.Fatal("want error for unknown zone")
	}
}

func TestLoadScenario_RejectsDuplicateProbeID(t *testing.T) {
	bad := `
id: x
name: x
probes:
  - {id: p, src: corp, dst: swift, port: 80, proto: tcp, expect: deny}
  - {id: p, src: corp, dst: cde, port: 80, proto: tcp, expect: deny}
`
	if _, err := LoadScenario([]byte(bad)); err == nil {
		t.Fatal("want error for duplicate probe id")
	}
}

func TestLoadScenario_SameZoneDenyRejected(t *testing.T) {
	bad := `
id: x
name: x
probes:
  - {id: p, src: swift, dst: swift, port: 8443, proto: tcp, expect: deny}
`
	if _, err := LoadScenario([]byte(bad)); err == nil {
		t.Fatal("want error for same-zone deny")
	}
}

func TestLoadScenario_SameZoneAllowAccepted(t *testing.T) {
	ok := `
id: x
name: x
probes:
  - {id: p, src: swift, dst: swift, port: 8443, proto: tcp, expect: allow}
`
	if _, err := LoadScenario([]byte(ok)); err != nil {
		t.Fatalf("same-zone allow should load: %v", err)
	}
}
