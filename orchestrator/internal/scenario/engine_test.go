package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveAndDelete(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}

	sc := &Scenario{
		ID:          "my-custom-chain",
		Name:        "My Custom Chain",
		Description: "test",
		MITREPhases: []string{"execution"},
		Steps: []Step{
			{Name: "step one", TechniqueID: "T1059.001", Framework: "custom", Executor: "powershell", Command: "whoami"},
		},
	}

	if err := e.Save(sc); err != nil {
		t.Fatalf("save: %v", err)
	}
	if sc.Source != "custom" {
		t.Fatalf("expected source=custom, got %q", sc.Source)
	}

	// File should exist in custom/.
	want := filepath.Join(dir, "custom", "my-custom-chain.yaml")
	if _, ok := e.Get("my-custom-chain"); !ok {
		t.Fatalf("scenario not in memory after save")
	}

	// Reload from disk and confirm it parses with the right source.
	e2 := NewEngine(dir)
	if err := e2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := e2.Get("my-custom-chain")
	if !ok {
		t.Fatalf("scenario not found after reload (expected file at %s)", want)
	}
	if got.Source != "custom" {
		t.Fatalf("reloaded source = %q, want custom", got.Source)
	}
	if len(got.Steps) != 1 || got.Steps[0].TechniqueID != "T1059.001" {
		t.Fatalf("reloaded steps mismatch: %+v", got.Steps)
	}

	// Delete should remove it from memory and disk.
	if err := e2.Delete("my-custom-chain"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := e2.Get("my-custom-chain"); ok {
		t.Fatalf("scenario still present after delete")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name string
		sc   Scenario
		ok   bool
	}{
		{"bad id", Scenario{ID: "Bad ID!", Name: "x", LocalCheck: true}, false},
		{"no name", Scenario{ID: "ok-id", LocalCheck: true}, false},
		{"no mode", Scenario{ID: "ok-id", Name: "x"}, false},
		{"step no technique", Scenario{ID: "ok-id", Name: "x", Steps: []Step{{Name: "s"}}}, false},
		{"valid local", Scenario{ID: "ok-id", Name: "x", LocalCheck: true}, true},
		{"valid steps", Scenario{ID: "ok-id", Name: "x", Steps: []Step{{Name: "s", TechniqueID: "T1059"}}}, true},
	}
	for _, c := range cases {
		err := c.sc.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: expected valid, got %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

func TestValidate_IDPathTraversal(t *testing.T) {
	cases := []struct {
		name string
		id   string
		ok   bool
	}{
		{"path traversal", "../evil", false},
		{"embedded slash", "a/b", false},
		{"uppercase", "Bad-ID", false},
		{"empty", "", false},
		{"too long", strings.Repeat("a", 65), false},
		{"valid slug", "ok-id-2", true},
	}
	for _, c := range cases {
		sc := Scenario{ID: c.id, Name: "x", LocalCheck: true}
		err := sc.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: expected valid, got %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

func TestSave_RoundTripFidelity(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}

	sc := &Scenario{
		ID:          "roundtrip-sc",
		Name:        "Round Trip",
		Description: "fidelity check",
		Tags:        []string{"tag-a", "tag-b"},
		MITREPhases: []string{"execution", "persistence"},
		Steps: []Step{
			{Name: "scalar priv", TechniqueID: "T1059.001", RequiresPriv: PrivSpec{Minimum: "admin"}},
			{Name: "minimum only", TechniqueID: "T1059.002", RequiresPriv: PrivSpec{Minimum: "user"}},
			{Name: "minimum and preferred", TechniqueID: "T1059.003", RequiresPriv: PrivSpec{Minimum: "user", Preferred: "admin"}},
		},
		LivePolicy: &LivePolicy{
			BlockOnDomainController: true,
			RequireDCReachable:      true,
			MaxSprayAttempts:        3,
			SprayAccountAllowlist:   []string{"svc-test"},
			ExecutionWindow:         "22:00-06:00",
		},
		Executable:  true,
		SupportedOS: []string{"windows", "linux"},
	}

	if err := e.Save(sc); err != nil {
		t.Fatalf("save: %v", err)
	}

	e2 := NewEngine(dir)
	if err := e2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := e2.Get("roundtrip-sc")
	if !ok {
		t.Fatalf("scenario not found after reload")
	}

	if len(got.Tags) != 2 || got.Tags[0] != "tag-a" || got.Tags[1] != "tag-b" {
		t.Fatalf("tags mismatch: %+v", got.Tags)
	}
	if len(got.MITREPhases) != 2 || got.MITREPhases[0] != "execution" || got.MITREPhases[1] != "persistence" {
		t.Fatalf("mitre phases mismatch: %+v", got.MITREPhases)
	}
	if !got.Executable {
		t.Fatalf("executable not preserved")
	}
	if len(got.SupportedOS) != 2 || got.SupportedOS[0] != "windows" || got.SupportedOS[1] != "linux" {
		t.Fatalf("supported_os mismatch: %+v", got.SupportedOS)
	}
	if got.LivePolicy == nil {
		t.Fatalf("live_policy not preserved (nil)")
	}
	if !got.LivePolicy.BlockOnDomainController || !got.LivePolicy.RequireDCReachable ||
		got.LivePolicy.MaxSprayAttempts != 3 || got.LivePolicy.ExecutionWindow != "22:00-06:00" ||
		len(got.LivePolicy.SprayAccountAllowlist) != 1 || got.LivePolicy.SprayAccountAllowlist[0] != "svc-test" {
		t.Fatalf("live_policy fields mismatch: %+v", got.LivePolicy)
	}
	if len(got.Steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(got.Steps))
	}
	// PrivSpec has no custom YAML marshaler, so a scalar "admin" on the way in
	// comes back out as the equivalent {minimum: admin} mapping on disk — the
	// parsed VALUE is what must round-trip, not the on-disk byte format.
	if got.Steps[0].RequiresPriv.Effective() != "admin" {
		t.Fatalf("step 0 requires_priv.Effective() = %q, want admin", got.Steps[0].RequiresPriv.Effective())
	}
	if got.Steps[1].RequiresPriv.Effective() != "user" {
		t.Fatalf("step 1 requires_priv.Effective() = %q, want user", got.Steps[1].RequiresPriv.Effective())
	}
	if got.Steps[2].RequiresPriv.Minimum != "user" || got.Steps[2].RequiresPriv.Preferred != "admin" {
		t.Fatalf("step 2 requires_priv = %+v, want {user admin}", got.Steps[2].RequiresPriv)
	}
}

func TestLoad_SourceClassification(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}

	// custom/ — via the normal Save path.
	if err := e.Save(&Scenario{ID: "custom-src-sc", Name: "Custom", LocalCheck: true}); err != nil {
		t.Fatalf("save custom: %v", err)
	}

	// intel/ — written directly, since only connectors populate this folder.
	intelDir := filepath.Join(dir, "intel")
	if err := os.MkdirAll(intelDir, 0o755); err != nil {
		t.Fatalf("mkdir intel: %v", err)
	}
	intelYAML := []byte("id: intel-src-sc\nname: Intel\nlocal_check: true\n")
	if err := os.WriteFile(filepath.Join(intelDir, "intel-src-sc.yaml"), intelYAML, 0o644); err != nil {
		t.Fatalf("write intel file: %v", err)
	}

	if err := e.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	custom, ok := e.Get("custom-src-sc")
	if !ok || custom.Source != "custom" {
		t.Fatalf("custom scenario source = %+v, want custom", custom)
	}
	intel, ok := e.Get("intel-src-sc")
	if !ok || intel.Source != "intel" {
		t.Fatalf("intel scenario source = %+v, want intel", intel)
	}
}

func TestLoad_UnsignedBuiltinRefused(t *testing.T) {
	dir := t.TempDir()
	// A file placed directly under the engine root (not custom/ or intel/) is
	// classified "builtin" by sourceForPath and therefore requires a valid
	// .sig file. This one has none, so Load must skip it rather than trust it.
	unsigned := []byte("id: unsigned-builtin-sc\nname: Unsigned\nlocal_check: true\n")
	if err := os.WriteFile(filepath.Join(dir, "unsigned-builtin-sc.yaml"), unsigned, 0o644); err != nil {
		t.Fatalf("write unsigned builtin file: %v", err)
	}

	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	if _, ok := e.Get("unsigned-builtin-sc"); ok {
		t.Fatalf("unsigned builtin scenario should have been refused, but was loaded")
	}
	if e.Count() != 0 {
		t.Fatalf("expected 0 loaded scenarios, got %d", e.Count())
	}
}

func TestDelete_IntelRescan(t *testing.T) {
	dir := t.TempDir()
	intelDir := filepath.Join(dir, "intel")
	if err := os.MkdirAll(intelDir, 0o755); err != nil {
		t.Fatalf("mkdir intel: %v", err)
	}
	filePath := filepath.Join(intelDir, "intel-delete-sc.yaml")
	intelYAML := []byte("id: intel-delete-sc\nname: Intel Delete\nlocal_check: true\n")
	if err := os.WriteFile(filePath, intelYAML, 0o644); err != nil {
		t.Fatalf("write intel file: %v", err)
	}

	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := e.Get("intel-delete-sc"); !ok {
		t.Fatalf("fixture not loaded")
	}

	// Engine-level Delete permits removing an intel-sourced scenario — only
	// the API layer restricts intel deletion (see DeleteScenario's source
	// guard, tested in internal/api/scenario_source_guard_test.go).
	if err := e.Delete("intel-delete-sc"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, ok := e.Get("intel-delete-sc"); ok {
		t.Fatalf("scenario still present in memory after delete")
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("file still present on disk after delete: err = %v", err)
	}
}

// TestLoad_SkipsMalformedFileWithoutBlockingOthers locks down Load()'s
// documented guarantee ("Individual file errors are logged and skipped — a
// bad file never blocks the rest", engine.go:44): a syntactically invalid
// file and a file missing the required id field must both be skipped without
// causing Load() to error or preventing a valid scenario elsewhere from
// loading.
func TestLoad_SkipsMalformedFileWithoutBlockingOthers(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}
	if err := e.Save(&Scenario{ID: "valid-alongside-sc", Name: "Valid", LocalCheck: true}); err != nil {
		t.Fatalf("save valid fixture: %v", err)
	}

	// Syntactically invalid YAML (tab indentation) — never unmarshals.
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("id: broken\n\tname: bad\n"), 0o644); err != nil {
		t.Fatalf("write broken file: %v", err)
	}
	// Parses fine but has no id — explicitly skipped by Load().
	if err := os.WriteFile(filepath.Join(dir, "no-id.yaml"), []byte("name: No ID\nlocal_check: true\n"), 0o644); err != nil {
		t.Fatalf("write no-id file: %v", err)
	}

	if err := e.Load(); err != nil {
		t.Fatalf("load should not fail even with bad files present: %v", err)
	}
	if _, ok := e.Get("valid-alongside-sc"); !ok {
		t.Fatalf("valid scenario should still load even though other files in the dir are malformed")
	}
	if e.Count() != 1 {
		t.Fatalf("expected exactly 1 loaded scenario (broken.yaml and no-id.yaml should both be skipped), got %d", e.Count())
	}
}

// TestSave_RefusesToOverwriteNonCustomDirectly exercises Save()'s own source
// guard (engine.go:181-183) directly at the engine level, independent of any
// API-layer pre-check. Since this test lives in package scenario, it can
// inject a non-custom scenario straight into the private scenarios map —
// sidestepping the need for a genuinely-signed builtin fixture (see the
// spec's note on the unavailable release-signing private key).
func TestSave_RefusesToOverwriteNonCustomDirectly(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}
	e.scenarios["fake-intel-sc"] = &Scenario{ID: "fake-intel-sc", Name: "Fake Intel", LocalCheck: true, Source: "intel"}

	err := e.Save(&Scenario{ID: "fake-intel-sc", Name: "Overwrite Attempt", LocalCheck: true})
	if err == nil {
		t.Fatalf("expected error overwriting a non-custom scenario directly via Save")
	}
	got, ok := e.Get("fake-intel-sc")
	if !ok || got.Name != "Fake Intel" {
		t.Fatalf("scenario mutated despite Save's own source guard: %+v", got)
	}
}

// TestDelete_NotFoundAndBuiltinGuarded exercises Delete()'s own not-found and
// builtin-source guards (engine.go:211-216) directly, independent of any
// API-layer pre-check. Same white-box injection technique as
// TestSave_RefusesToOverwriteNonCustomDirectly.
func TestDelete_NotFoundAndBuiltinGuarded(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(dir)
	if err := e.Load(); err != nil {
		t.Fatalf("load empty: %v", err)
	}

	if err := e.Delete("does-not-exist"); err == nil {
		t.Fatalf("expected error deleting an unknown id")
	}

	e.scenarios["fake-builtin-sc"] = &Scenario{ID: "fake-builtin-sc", Name: "Fake Builtin", Source: "builtin"}
	if err := e.Delete("fake-builtin-sc"); err == nil {
		t.Fatalf("expected error deleting a builtin-sourced scenario")
	}
	if _, ok := e.Get("fake-builtin-sc"); !ok {
		t.Fatalf("builtin scenario should not have been removed from memory")
	}
}

func TestParseYAML_UbuntuHardeningValidation(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", "ubuntu-hardening-validation.yaml"))
	if err != nil {
		t.Fatalf("read scenario file: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sc.ID != "ubuntu-hardening-validation" {
		t.Fatalf("id = %q, want ubuntu-hardening-validation", sc.ID)
	}
	if !sc.Executable {
		t.Fatalf("expected executable: true")
	}
	if sc.LocalCheck {
		t.Fatalf("expected local_check to be unset — this scenario runs real attack techniques, not posture checks")
	}
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "linux" {
		t.Fatalf("supported_os = %v, want [linux]", sc.SupportedOS)
	}
	wantTechniques := []string{
		"T1547.006", "T1055", "T1003", "T1562.001", "T1554", "T1078",
		"T1046", "T1200", "T1222", "T1059", "T1548.001", "T1548.003",
	}
	if len(sc.ARTTechniques) != len(wantTechniques) {
		t.Fatalf("art_techniques count = %d, want %d (%v)", len(sc.ARTTechniques), len(wantTechniques), sc.ARTTechniques)
	}
	for i, want := range wantTechniques {
		if sc.ARTTechniques[i] != want {
			t.Fatalf("art_techniques[%d] = %q, want %q", i, sc.ARTTechniques[i], want)
		}
	}
}

func TestParseYAML_DLPExfiltrationValidation(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", "dlp-exfiltration-validation.yaml"))
	if err != nil {
		t.Fatalf("read scenario file: %v", err)
	}
	sc, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sc.ID != "dlp-exfiltration-validation" {
		t.Fatalf("id = %q, want dlp-exfiltration-validation", sc.ID)
	}
	if !sc.Executable {
		t.Fatalf("expected executable: true")
	}
	if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "windows" {
		t.Fatalf("supported_os = %v, want [windows]", sc.SupportedOS)
	}
	if len(sc.Steps) != 5 {
		t.Fatalf("steps = %d, want 5", len(sc.Steps))
	}
	wantTechniques := []string{"T1052.001", "T1115", "T1052", "T1560.001", "T1074.001"}
	for i, want := range wantTechniques {
		if sc.Steps[i].TechniqueID != want {
			t.Errorf("step %d technique_id = %q, want %q", i, sc.Steps[i].TechniqueID, want)
		}
		if len(sc.Steps[i].DetectionProfiles) != 1 || sc.Steps[i].DetectionProfiles[0] != "windows_dlp_exfiltration" {
			t.Errorf("step %d detection_profiles = %v, want [windows_dlp_exfiltration]", i, sc.Steps[i].DetectionProfiles)
		}
	}
}

func TestParseYAML_RansomwareScenariosDetectionProfilesWired(t *testing.T) {
	cases := []struct {
		file        string
		stepName    string
		wantProfile string
	}{
		{"../../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 1 — Security Software Discovery (T1518.001)", "windows_security_software_discovery"},
		{"../../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 2 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 3 — SMB Admin Share Lateral Movement Probe (T1021.002)", "windows_smb_lateral_probe"},
		{"../../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 4 — Ransomware Payload Simulation (T1486)", "windows_ransomware_encryption"},
		{"../../../scenarios/lockbit-kill-chain.yaml", "LockBit Stage 5 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../../scenarios/ransomware-drill.yaml", "File Enumeration (BFSI high-value filename markers)", "windows_file_discovery"},
		{"../../../scenarios/ransomware-drill.yaml", "Defender Exclusion Invocation (cmdline probe  -  no state change)", "windows_defender_tampering"},
		{"../../../scenarios/ransomware-drill.yaml", "Event Log Clear Probe (nonexistent log  -  process telemetry only)", "windows_log_manipulation"},
		{"../../../scenarios/ransomware-drill.yaml", "VSS + Backup Catalog Enumeration", "windows_vss_inhibition"},
		{"../../../scenarios/ransomware-drill.yaml", "Benign File Rename Probe (.bas_locked extension)", "windows_ransomware_encryption"},
		{"../../../scenarios/ransomware-drill.yaml", "XOR Encryption Simulation (lab  -  isolated temp dir, forced cleanup)", "windows_ransomware_encryption"},
		{"../../../scenarios/ransomware-drill.yaml", "VSS Shadow Copy Deletion (lab  -  requires BAS_CONFIRM_VSS_DELETE=true)", "windows_vss_inhibition"},
		{"../../../scenarios/ransomware-drill.yaml", "Defender RTP Disable (lab  -  mandatory restoration + health check)", "windows_defender_tampering"},
		{"../../../scenarios/ransomware-drill.yaml", "Malicious Service Probe (lab  -  creation + lineage logging)", "windows_malicious_service"},

		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 1A — BFSI File Target Reconnaissance", "windows_file_discovery"},
		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 1B — Network Share Discovery", "windows_network_share_discovery"},
		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 2A — Defender Exclusion Invocation Probe", "windows_defender_tampering"},
		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 2B — Event Log Clear Probe", "windows_log_manipulation"},
		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 3A — Canary File Mass Encryption Loop", "windows_ransomware_encryption"},
		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 3B — Ransom Note Drop (Canary Directory)", "windows_ransomware_encryption"},
		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 4A — VSS Shadow Copy Deletion Signature", "windows_vss_inhibition"},
		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 4B — wbadmin Backup Catalog Delete Probe", "windows_vss_inhibition"},
		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 4C — BCDEdit Bootloader Recovery Disable Probe", "windows_vss_inhibition"},
		{"../../../scenarios/endpoint-mastery/em-07-ransomware-readiness.yaml", "Stage 5A — Backup Service Stop Attempt", "windows_backup_service_stop"},
	}

	parsed := map[string]*Scenario{}
	for _, tc := range cases {
		if _, ok := parsed[tc.file]; ok {
			continue
		}
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		sc, err := ParseYAML(data)
		if err != nil {
			t.Fatalf("ParseYAML %s: %v", tc.file, err)
		}
		parsed[tc.file] = sc
	}

	for _, tc := range cases {
		sc := parsed[tc.file]
		var step *Step
		for i := range sc.Steps {
			if sc.Steps[i].Name == tc.stepName {
				step = &sc.Steps[i]
				break
			}
		}
		if step == nil {
			t.Errorf("%s: step %q not found", tc.file, tc.stepName)
			continue
		}
		if len(step.DetectionProfiles) != 1 || step.DetectionProfiles[0] != tc.wantProfile {
			t.Errorf("%s / %q: DetectionProfiles = %v, want [%s]", tc.file, tc.stepName, step.DetectionProfiles, tc.wantProfile)
		}
	}
}

func TestParseYAML_NewRansomwareFamiliesDetectionProfilesWired(t *testing.T) {
	cases := []struct {
		file        string
		stepName    string
		wantProfile string
	}{
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 1 — AD Domain & Privileged Account Discovery (T1087.002)", "windows_ad_discovery"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 2 — Security Software Discovery (T1518.001)", "windows_security_software_discovery"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 3 — SAM & SYSTEM Hive Theft via reg save (T1003.002)", "windows_sam_theft"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 4 — Defender RTP Disable (lab  -  mandatory restoration + health check) (T1562.001)", "windows_defender_tampering"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 5 — Malicious Service Probe (lab  -  PsExec-style self-propagation) (T1543.003)", "windows_malicious_service"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 6 — Ransomware Payload Simulation (T1486)", "windows_ransomware_encryption"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 7 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/blackcat-kill-chain.yaml", "BlackCat Stage 8 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 1 — RDP / NLA Exposure Posture Check (T1021.001)", "windows_rdp_nla_posture"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 2 — Network Share Discovery (T1135)", "windows_network_share_discovery"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 3 — SAM & SYSTEM Hive Theft via reg save (T1003.002)", "windows_sam_theft"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 4 — Defender Exclusion Invocation (cmdline probe  -  no state change) (T1562.001)", "windows_defender_tampering"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 5 — SMB Admin Share Lateral Movement Probe (T1021.002)", "windows_smb_lateral_probe"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 6 — Ransomware Payload Simulation (T1486)", "windows_ransomware_encryption"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 7 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 8 — VSS Shadow Copy Deletion via WMI (lab  -  requires BAS_CONFIRM_VSS_DELETE=true) (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/akira-kill-chain.yaml", "Akira Stage 9 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 1 — AdFind-Style AD Enumeration (T1087.002)", "windows_ad_discovery"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 2 — Grixba-Style Network & Share Discovery (T1135)", "windows_network_share_discovery"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 3 — GPO-Style Defender RTP Disable (lab  -  mandatory restoration + health check) (T1562.001)", "windows_defender_tampering"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 4 — EDR-Killer / Vulnerable-Driver Staging Probe (T1562.001)", "windows_vulnerable_driver_load"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 5 — SMB Admin Share Lateral Movement Probe (T1021.002)", "windows_smb_lateral_probe"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 6 — Ransomware Payload Simulation (T1486)", "windows_ransomware_encryption"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 7 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/play-kill-chain.yaml", "Play Stage 8 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 1 — Security Software Discovery (T1518.001)", "windows_security_software_discovery"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 2 — Network Share Discovery (T1135)", "windows_network_share_discovery"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 3 — SAM & SYSTEM Hive Theft via reg save (T1003.002)", "windows_sam_theft"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 4 — Defender Exclusion Invocation (cmdline probe  -  no state change) (T1562.001)", "windows_defender_tampering"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 5 — EDRKillShifter-Style Vulnerable-Driver Staging Probe (T1562.001)", "windows_vulnerable_driver_load"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 6 — Ransomware Payload Simulation, Double-Extortion Note (T1486)", "windows_ransomware_encryption"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 7 — VSS Snapshot Enumeration (T1490)", "windows_vss_inhibition"},
		{"../../../scenarios/ransomhub-kill-chain.yaml", "RansomHub Stage 8 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},

		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 1 — BFSI File Target Reconnaissance (T1083)", "windows_file_discovery"},
		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 2 — Security Process Termination Probe (T1562.001)", "windows_security_process_termination"},
		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 3 — Archive Staging via Compress-Archive (T1560.001)", "windows_archive_staging"},
		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 4 — Cloud Storage Egress Reachability (T1567.002)", "windows_cloud_egress"},
		{"../../../scenarios/clop-kill-chain.yaml", "Cl0p Stage 5 — Event Log Clearing Attempt (T1070.001)", "windows_log_manipulation"},
	}

	parsed := map[string]*Scenario{}
	for _, tc := range cases {
		if _, ok := parsed[tc.file]; ok {
			continue
		}
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		sc, err := ParseYAML(data)
		if err != nil {
			t.Fatalf("ParseYAML %s: %v", tc.file, err)
		}
		parsed[tc.file] = sc
	}

	for _, tc := range cases {
		sc := parsed[tc.file]
		var step *Step
		for i := range sc.Steps {
			if sc.Steps[i].Name == tc.stepName {
				step = &sc.Steps[i]
				break
			}
		}
		if step == nil {
			t.Errorf("%s: step %q not found", tc.file, tc.stepName)
			continue
		}
		if len(step.DetectionProfiles) != 1 || step.DetectionProfiles[0] != tc.wantProfile {
			t.Errorf("%s / %q: DetectionProfiles = %v, want [%s]", tc.file, tc.stepName, step.DetectionProfiles, tc.wantProfile)
		}
	}
}

func TestParseYAML_InsiderThreatDetectionProfilesWired(t *testing.T) {
	cases := []struct {
		file        string
		stepName    string
		wantProfile string
	}{
		{"../../../scenarios/insider-threat-kill-chain.yaml", "Insider Stage 1 — Sensitive-File Search Outside Normal Job Scope (T1083 / T1005)", "windows_file_discovery"},
		{"../../../scenarios/insider-threat-kill-chain.yaml", "Insider Stage 2 — Personal Webmail Exfiltration Reachability (T1567)", "windows_webmail_egress"},
		{"../../../scenarios/insider-threat-kill-chain.yaml", "Insider Stage 3 — Mass File Rename/Delete Sabotage (T1485)", "windows_data_destruction"},
	}

	parsed := map[string]*Scenario{}
	for _, tc := range cases {
		if _, ok := parsed[tc.file]; ok {
			continue
		}
		data, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		sc, err := ParseYAML(data)
		if err != nil {
			t.Fatalf("ParseYAML %s: %v", tc.file, err)
		}
		parsed[tc.file] = sc
	}

	for _, tc := range cases {
		sc := parsed[tc.file]
		var step *Step
		for i := range sc.Steps {
			if sc.Steps[i].Name == tc.stepName {
				step = &sc.Steps[i]
				break
			}
		}
		if step == nil {
			t.Errorf("%s: step %q not found", tc.file, tc.stepName)
			continue
		}
		if len(step.DetectionProfiles) != 1 || step.DetectionProfiles[0] != tc.wantProfile {
			t.Errorf("%s / %q: DetectionProfiles = %v, want [%s]", tc.file, tc.stepName, step.DetectionProfiles, tc.wantProfile)
		}
	}
}
