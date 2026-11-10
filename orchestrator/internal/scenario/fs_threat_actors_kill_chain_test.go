package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFSThreatActorKillChains_ParseWindowsOnlyWithExpectedTechniques is the
// REQ-019 acceptance gate: the five bank-targeting threat-actor kill chains
// added to complete the FS threat-actor library (Carbanak, Cobalt Group,
// Silence, TA505, FIN8) must each parse, be Windows-only, carry exactly the
// intended ATT&CK technique sequence, and be safe to run (each step is either
// production_safe + reversible, or explicitly lab-only).
//
// Carbanak, Cobalt Group, Silence and TA505 are the enterprise-grade rebuilds
// (black-basta standard): a full initial-access -> ... -> objective arc with
// the impact/destructive stages lab-gated, per-step grounding
// (threat_intel_sources + family_attribution_confidence), and real detectable
// actions scored PASS/FAIL on the control outcome. FIN8 still follows the
// earlier fin7-style pattern (narrative citations in the description, no
// per-step provenance fields); its enterprise rebuild is tracked separately.
func TestFSThreatActorKillChains_ParseWindowsOnlyWithExpectedTechniques(t *testing.T) {
	cases := []struct {
		file       string
		techniques []string
	}{
		{
			// Enterprise-grade rebuild (black-basta standard): initial-access
			// -> service persistence -> firewall evasion -> LSASS cred access
			// -> payment-app discovery -> operator screen capture -> HTTPS C2
			// -> fraudulent-transfer objective (lab-gated).
			file:       "carbanak-kill-chain.yaml",
			techniques: []string{"T1566.001", "T1543.003", "T1686", "T1003.001", "T1057", "T1113", "T1071.001", "T1078"},
		},
		{
			// Enterprise-grade rebuild: initial-access -> encoded loader ->
			// security-software discovery -> regsvr32 Squiblydoo -> service
			// persistence -> scheduled-task persistence -> DNS C2 ->
			// ATM/card-processing manipulation objective (lab-gated).
			file:       "cobalt-group-kill-chain.yaml",
			techniques: []string{"T1566.001", "T1059.001", "T1518.001", "T1218.010", "T1543.003", "T1053.005", "T1071.004", "T1565.002"},
		},
		{
			// Enterprise-grade rebuild: initial-access -> encoded loader ->
			// operator screen capture -> LSASS cred access -> network
			// topology mapping -> Run-key persistence -> ingress reachability
			// -> Atmosphere ATM cash-dispense objective (lab-gated).
			file:       "silence-kill-chain.yaml",
			techniques: []string{"T1566.001", "T1059.001", "T1113", "T1003.001", "T1018", "T1547.001", "T1105", "T1565.001"},
		},
		{
			// Enterprise-grade reference chain (black-basta standard): full
			// initial-access -> loader -> persistence -> discovery -> collection
			// -> exfil -> impact -> recovery-inhibition arc, with the impact and
			// VSS-deletion stages lab-gated.
			file:       "ta505-kill-chain.yaml",
			techniques: []string{"T1566.001", "T1059.001", "T1547.001", "T1053.005", "T1518.001", "T1560.001", "T1567.002", "T1486", "T1490", "T1490"},
		},
		{
			file:       "fin8-kill-chain.yaml",
			techniques: []string{"T1047", "T1518.001", "T1140", "T1543.003", "T1071.001"},
		},
	}

	dir, err := filepath.Abs("../../../scenarios")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, tc.file))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			sc, err := ParseYAML(b)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			if len(sc.SupportedOS) != 1 || sc.SupportedOS[0] != "windows" {
				t.Fatalf("SupportedOS = %v, want [windows]", sc.SupportedOS)
			}
			if !sc.Executable {
				t.Errorf("executable = false, want true")
			}
			if sc.ProductLine != "killchain" {
				t.Errorf("product_line = %q, want killchain", sc.ProductLine)
			}

			if len(sc.Steps) != len(tc.techniques) {
				t.Fatalf("got %d steps, want %d", len(sc.Steps), len(tc.techniques))
			}
			for i, want := range tc.techniques {
				if got := sc.Steps[i].TechniqueID; got != want {
					t.Errorf("step %d: technique_id = %q, want %q", i, got, want)
				}
			}

			for i, st := range sc.Steps {
				if strings.TrimSpace(st.Name) == "" {
					t.Errorf("step %d (%s): name is empty", i, st.TechniqueID)
				}
				if strings.TrimSpace(st.Command) == "" {
					t.Errorf("step %d (%s): command is empty", i, st.TechniqueID)
				}
				// A step is either production-safe + reversible, or it is an
				// explicitly lab-only step (fidelity: lab-only) -- the pattern
				// that lets the impact/destructive stages do the real thing
				// safely. A non-production-safe step that is NOT lab-only would
				// be an unguarded destructive action.
				if st.ProductionSafe {
					if !st.Reversible {
						t.Errorf("step %d (%s): production_safe but reversible = false", i, st.TechniqueID)
					}
				} else if st.Fidelity != "lab-only" {
					t.Errorf("step %d (%s): production_safe = false but fidelity = %q, want lab-only", i, st.TechniqueID, st.Fidelity)
				}
				// A [BAS-SIM-...] marker must be present so operators can
				// distinguish simulation output from a real intrusion.
				if !strings.Contains(st.Command, "BAS-SIM-") {
					t.Errorf("step %d (%s): command has no [BAS-SIM-...] marker", i, st.TechniqueID)
				}
			}
		})
	}
}
