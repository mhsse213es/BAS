package admatrix

import "github.com/audspect/bas/internal/adprimitive"

var gpoReuse = map[string]string{
	"gpo-abuse-linked-scope": "adenv.HasGPOWriteAccess + adenv.GPOAffectsScope + adlab EnvResolver(controls_writable_linked_gpo)",
}

var gpoEvidence = map[string][]string{
	"gpo-abuse-linked-scope": {"a modification to a GPO's policy (e.g. an added immediate scheduled task or Restricted Groups entry)", "code execution / privileged group membership on an object under the GPO's linked scope"},
}

var gpoCleanup = map[string][]string{
	"gpo-abuse-linked-scope": {"revert the GPO to its prior policy and version", "remove any scheduled task or group membership it pushed", "restore the GPO object's ACL"},
}

var gpoTelemetry = map[string][]string{
	"gpo-abuse-linked-scope": {"Directory Service Changes on the GPO / gPLink (event 5136)", "SYSVOL GPO file/version changes (gPCFileSysPath, GPT.INI versionNumber)", "scheduled-task creation (event 4698) on objects in the linked scope"},
}

// GPOEntries returns the coverage-matrix row(s) for Group Policy abuse, iterating
// adprimitive.GPOAbuseCatalog so IDs and postconditions cannot drift.
func GPOEntries() []Entry {
	out := make([]Entry, 0, len(adprimitive.GPOAbuseCatalog))
	for _, p := range adprimitive.GPOAbuseCatalog {
		if p.ID == "gpo-abuse-exposure-check" {
			continue // read-only discovery primitive, tracked via realScenarioEvidenceByID
		}
		out = append(out, Entry{
			PrimitiveID:            p.ID,
			TechniqueID:            p.TechniqueID,
			RequiredEnvToExecute:   EnvDomainController, // GPO push needs a real domain + SYSVOL
			ExecutionMethod:        "synthetic-predicate",
			ReuseSource:            gpoReuse[p.ID],
			ExpectedPostconditions: p.Postconditions,
			EvidenceRequirements:   gpoEvidence[p.ID],
			TelemetrySources:       gpoTelemetry[p.ID],
			Cleanup:                gpoCleanup[p.ID],
			CurrentValidation:      LevelModelSimulated,
		})
	}
	return out
}
