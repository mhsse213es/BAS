package contentimport

import (
	"testing"
)

func TestScenarioID_IsValidStableAndDistinct(t *testing.T) {
	a := ScenarioID("sigma", "Certutil Download (Windows) — with a very long title that goes on and on and on", Marker("sigma", "1"))
	if len(a) > 64 || !validID(a) {
		t.Errorf("id %q is not a valid scenario id", a)
	}
	if a != ScenarioID("sigma", "Certutil Download (Windows) — with a very long title that goes on and on and on", Marker("sigma", "1")) {
		t.Error("must be stable")
	}
	if a == ScenarioID("sigma", "Certutil Download (Windows) — with a very long title that goes on and on and on", Marker("sigma", "2")) {
		t.Error("different sources must differ")
	}
	if id := ScenarioID("yara", "***", Marker("yara", "x")); !validID(id) {
		t.Errorf("a title with no usable characters still needs a valid id: %q", id)
	}
}

func validID(s string) bool {
	if len(s) < 2 || len(s) > 64 {
		return false
	}
	for i, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0)
		if !ok {
			return false
		}
	}
	return true
}

func TestBuildScenario_IsValidAndCarriesTheStep(t *testing.T) {
	res := mustGen(t, certutilRule, "")
	sc := BuildScenario("sigma", res.Rule.Title, "d", res.OS, *res.Step)
	if err := sc.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := sc.ValidateMarkers(); err != nil {
		t.Fatal(err)
	}
	if len(sc.Steps) != 1 || sc.SupportedOS[0] != "windows" || !sc.Executable {
		t.Errorf("%+v", sc)
	}
}
