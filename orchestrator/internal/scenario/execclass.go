package scenario

import "strings"

// ExecutionClass is the destructiveness tier B5 (the agent-side
// destructive-action guardrail) enforces per step. See
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md.
//
// This is a SEPARATE concern from ResourceProfile's Risk field
// (resource.go) -- that classifies concurrency-locking risk
// (observation/modification/persistence); this classifies whether
// executing the step can cause irreversible real-world damage. The two
// catalogs are deliberately never merged.
type ExecutionClass string

const (
	ClassNonDestructive         ExecutionClass = "non_destructive"
	ClassPotentiallyDestructive ExecutionClass = "potentially_destructive"
	ClassDestructive            ExecutionClass = "destructive"
)

// ExecutionClassification is the catalog's resolved answer for one
// (technique_id, action_key) pair.
type ExecutionClassification struct {
	Class ExecutionClass
	// DestructiveAction is a stable, audit/report-facing identifier for
	// what this action does (often just the action_key itself).
	DestructiveAction string
	// BlastRadius is a human-readable description for audit/reporting --
	// never itself consulted for enforcement.
	BlastRadius string
}

// unclassified is the fail-closed answer for any (technique_id,
// action_key) pair this catalog has no entry for -- see the spec's
// "Resolution rules": no fallback from an unknown pair to a
// technique-wide generic classification, ever.
var unclassified = ExecutionClassification{
	Class:             ClassDestructive,
	DestructiveAction: "unclassified",
	BlastRadius:       "No catalog entry exists for this technique/action -- treated as destructive per the fail-closed default.",
}

// executionClassifications is the Audspect-controlled catalog, keyed
// technique_id -> action_key -> classification. Populated exhaustively by
// Task 10's full-library audit; this task seeds it only with the entries
// already verified against real scenario command text during this
// plan's own design investigation.
var executionClassifications = map[string]map[string]*ExecutionClassification{
	"T1490": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only enumeration of VSS shadow copies / backup catalog (vssadmin list shadows, wbadmin get versions). No state changed.",
		},
		"vss_delete": {
			Class:             ClassDestructive,
			DestructiveAction: "vss_delete",
			BlastRadius:       "Deletes VSS shadow copies (vssadmin/wbadmin/WMI Win32_ShadowCopy.Delete()) -- irreversible, removes the ransomware-recovery path.",
		},
		"wbadmin_delete_catalog": {
			Class:             ClassDestructive,
			DestructiveAction: "wbadmin_delete_catalog",
			BlastRadius:       "Deletes the Windows Server Backup catalog (wbadmin delete catalog) -- irreversible.",
		},
		"bootloader_recovery_disable": {
			Class:             ClassDestructive,
			DestructiveAction: "bootloader_recovery_disable",
			BlastRadius:       "Disables Windows Recovery Environment via bcdedit (recoveryenabled no / bootstatuspolicy ignoreallfailures) -- removes the final recovery path.",
		},
	},
	// T1082 seeded here as the resolver test's "default" example --
	// mirrors resource.go's own discoveryProfiles entry for the same
	// technique (already proven read-only there). Real coverage of every
	// discoveryProfiles technique is Task 10's job, not duplicated by hand
	// here for each one.
	"T1082": {
		"default": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only system information query.",
		},
	},
}

// ResolveExecutionClass returns the catalog's classification for a step's
// (technique_id, action_key) pair. An empty action_key resolves against
// the technique's own "default" entry. Any miss -- unknown technique,
// unknown action_key under a known technique, or no "default" entry for
// an empty action_key -- fails closed to ClassDestructive. No fallback to
// a technique-wide generic classification exists at any point in this
// resolution.
func ResolveExecutionClass(techniqueID, actionKey string) ExecutionClassification {
	tid := strings.ToUpper(strings.TrimSpace(techniqueID))
	key := strings.ToLower(strings.TrimSpace(actionKey))
	if key == "" {
		key = "default"
	}
	actions, ok := executionClassifications[tid]
	if !ok {
		return unclassified
	}
	c, ok := actions[key]
	if !ok {
		return unclassified
	}
	return *c
}
