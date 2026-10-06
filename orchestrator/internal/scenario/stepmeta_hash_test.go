package scenario

import "testing"

func TestStepCommandSHA256_CoversExecutorCommandCleanupPayloads(t *testing.T) {
	base := ScenarioStep{TaskID: "t", Executor: "powershell", Command: "whoami", Cleanup: "x",
		Payloads: []Payload{{Name: "b.ps1", Content: "QQ=="}, {Name: "a.ps1", Content: "Qg=="}}}
	h := StepCommandSHA256(base)
	if len(h) != 64 {
		t.Fatalf("hash = %q", h)
	}
	reordered := base
	reordered.Payloads = []Payload{base.Payloads[1], base.Payloads[0]}
	if StepCommandSHA256(reordered) != h {
		t.Fatal("payload order must not change the hash")
	}
	for name, mut := range map[string]func(*ScenarioStep){
		"executor": func(s *ScenarioStep) { s.Executor = "cmd" },
		"command":  func(s *ScenarioStep) { s.Command = "hostname" },
		"cleanup":  func(s *ScenarioStep) { s.Cleanup = "" },
		"payload":  func(s *ScenarioStep) { s.Payloads = []Payload{{Name: "a.ps1", Content: "Zg=="}} },
	} {
		c := base
		mut(&c)
		if StepCommandSHA256(c) == h {
			t.Errorf("changing %s must change the hash", name)
		}
	}
}

func TestBuildStepMeta_RecordsComponentAndBothHashes(t *testing.T) {
	steps := []ScenarioStep{
		{TaskID: "a", TechniqueID: "T1082", Name: "n", Framework: "art", Platform: "windows", Executor: "powershell", Command: "systeminfo"},
		{TaskID: "c", TechniqueID: "T1059", Name: "c", Framework: "custom", Executor: "cmd", Command: "echo"},
	}
	resolved := ResolvedHashes(steps)
	steps[0].Command = "systeminfo #ARTIFACT-123" // per-run substitution after build
	meta := BuildStepMeta(steps, resolved, ComponentVersions{ART: "art-2026.09"})
	a := meta["a"]
	if a.Component != "art" || a.ComponentVersion != "art-2026.09" || a.Platform != "windows" {
		t.Fatalf("art meta: %+v", a)
	}
	if a.ResolvedSHA256 == "" || a.CommandSHA256 == "" || a.ResolvedSHA256 == a.CommandSHA256 {
		t.Fatalf("resolved and sent hashes must both exist and differ after substitution: %+v", a)
	}
	if c := meta["c"]; c.Component != "custom" || c.ComponentVersion != "" {
		t.Fatalf("custom meta: %+v", c)
	}
}
